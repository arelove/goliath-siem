//! Checking a search against the OCSF schema and the deployment's limits.

use goliath_ocsf::schema::{self, Base, Class, Resolution};
use serde_json::Value;

use crate::{Checked, Condition, Kind, Limits, Op, Scalar, Search, SearchError};

impl Search {
    /// Checks every part of the search: the time range and its span, the
    /// page size, the classes, and each filter's path, operator, and value.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] describing the first problem found.
    pub fn check(&self, limits: &Limits) -> Result<Checked, SearchError> {
        let from = time("from", &self.from)?;
        let to = time("to", &self.to)?;
        if to <= from {
            return Err(SearchError::EmptyRange);
        }
        if to - from > limits.max_span_ms {
            return Err(SearchError::SpanTooLong {
                max_days: limits.max_span_ms / (24 * 60 * 60 * 1000),
            });
        }
        let limit = self.limit.unwrap_or(limits.default_limit);
        if limit == 0 || limit > limits.max_limit {
            return Err(SearchError::Limit {
                max: limits.max_limit,
            });
        }

        let mut classes = self.classes.clone();
        classes.sort_unstable();
        classes.dedup();
        let named = classes
            .iter()
            .map(|&class_uid| {
                schema::class(class_uid).ok_or(SearchError::UnknownClass {
                    class_uid,
                    version: goliath_ocsf::SCHEMA_VERSION,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if self.filters.len() > limits.max_filters {
            return Err(SearchError::TooManyFilters {
                max: limits.max_filters,
            });
        }
        let conditions = self
            .filters
            .iter()
            .map(|filter| condition(&filter.path, filter.op, &filter.value, &named, limits))
            .collect::<Result<_, _>>()?;

        Ok(Checked {
            from,
            to,
            classes,
            conditions,
            limit,
            after: self.after,
        })
    }
}

fn time(bound: &'static str, text: &str) -> Result<i64, SearchError> {
    text.parse::<jiff::Timestamp>()
        .map(jiff::Timestamp::as_millisecond)
        .map_err(|error| SearchError::Time {
            bound,
            reason: error.to_string(),
        })
}

/// What a path names, and what it holds.
#[derive(Clone, Copy)]
struct Target {
    kind: Kind,
    /// For an integer: whether it is a time, which may be written as text.
    time: bool,
    /// For an integer: the values an enumeration defines, if it is one.
    values: &'static [i64],
}

fn condition(
    path: &str,
    op: Op,
    value: &Value,
    named: &[&'static Class],
    limits: &Limits,
) -> Result<Condition, SearchError> {
    let segments: Vec<String> = path.split('.').map(str::to_owned).collect();
    if segments.iter().any(|segment| {
        segment.is_empty()
            || segment
                .chars()
                .any(|c| c == '`' || c == '\\' || c.is_control())
    }) {
        return Err(SearchError::Segment {
            path: path.to_owned(),
        });
    }
    let target = target(path, named)?;
    let values = values(path, op, value, target, limits)?;
    Ok(Condition {
        path: segments,
        kind: target.kind,
        op,
        values,
    })
}

/// Resolves `path` in each class named, or in every class if none is, and
/// requires them to agree.
fn target(path: &str, named: &[&'static Class]) -> Result<Target, SearchError> {
    let mut found: Vec<Target> = Vec::new();
    if named.is_empty() {
        for class in schema::classes() {
            if let Ok(resolution) = class.resolve(path) {
                found.push(of(path, resolution)?);
            }
        }
        if found.is_empty() {
            return Err(SearchError::NoClass {
                path: path.to_owned(),
            });
        }
    } else {
        for class in named {
            let resolution = class
                .resolve(path)
                .map_err(|error| SearchError::Path(error.to_string()))?;
            found.push(of(path, resolution)?);
        }
    }
    let first = found[0];
    if found
        .iter()
        .any(|target| target.kind != first.kind || target.time != first.time)
    {
        return Err(SearchError::Ambiguous {
            path: path.to_owned(),
        });
    }
    // Enumerations of one attribute can differ between classes, as
    // `activity_id` does: a value is accepted if some class defines it.
    let values = if found.iter().any(|target| target.values.is_empty()) {
        &[][..]
    } else {
        first.values
    };
    Ok(Target { values, ..first })
}

fn of(path: &str, resolution: Resolution) -> Result<Target, SearchError> {
    let attribute = resolution.attribute;
    if resolution.within_array || (attribute.is_array() && !resolution.free_form) {
        return Err(SearchError::Array {
            path: path.to_owned(),
        });
    }
    let kind = if resolution.free_form {
        Kind::Any
    } else {
        match attribute.base() {
            Base::String => Kind::Text,
            Base::Integer | Base::Long => Kind::Integer,
            Base::Float => Kind::Float,
            Base::Boolean => Kind::Boolean,
            Base::Object => Kind::Object,
            _ => Kind::Any,
        }
    };
    Ok(Target {
        kind,
        time: attribute.type_name() == "timestamp_t",
        values: if resolution.free_form {
            &[]
        } else {
            attribute.enum_values()
        },
    })
}

fn values(
    path: &str,
    op: Op,
    value: &Value,
    target: Target,
    limits: &Limits,
) -> Result<Vec<Scalar>, SearchError> {
    let wrong = |reason: String| SearchError::Value {
        path: path.to_owned(),
        reason,
    };
    match op {
        Op::Exists | Op::Missing => {
            return if value.is_null() {
                Ok(Vec::new())
            } else {
                Err(wrong(format!("`{}` takes no value", op.as_str())))
            };
        }
        _ if target.kind == Kind::Object => {
            return Err(operator(path, op, target.kind));
        }
        _ => {}
    }
    let written: Vec<&Value> = if op == Op::In {
        let Value::Array(list) = value else {
            return Err(wrong("`in` takes a list of values".to_owned()));
        };
        if list.is_empty() || list.len() > limits.max_values {
            return Err(wrong(format!(
                "`in` takes between 1 and {} values",
                limits.max_values
            )));
        }
        list.iter().collect()
    } else {
        vec![value]
    };
    let scalars = written
        .into_iter()
        .map(|value| scalar(path, value, target, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let first = std::mem::discriminant(&scalars[0]);
    if scalars
        .iter()
        .any(|scalar| std::mem::discriminant(scalar) != first)
    {
        return Err(wrong(
            "the values of `in` must all be of one type".to_owned(),
        ));
    }
    let compares_as = match (&scalars[0], target.kind) {
        (_, kind) if kind != Kind::Any => kind,
        (Scalar::Text(_), _) => Kind::Text,
        (Scalar::Integer(_), _) => Kind::Integer,
        (Scalar::Float(_), _) => Kind::Float,
        (Scalar::Boolean(_), _) => Kind::Boolean,
    };
    let fits = match compares_as {
        Kind::Text => matches!(
            op,
            Op::Equals | Op::NotEquals | Op::Contains | Op::StartsWith | Op::EndsWith | Op::In
        ),
        Kind::Integer | Kind::Float => matches!(
            op,
            Op::Equals | Op::NotEquals | Op::In | Op::Gt | Op::Gte | Op::Lt | Op::Lte
        ),
        Kind::Boolean => matches!(op, Op::Equals | Op::NotEquals),
        Kind::Object | Kind::Any => false,
    };
    if !fits {
        return Err(operator(path, op, compares_as));
    }
    Ok(scalars)
}

fn operator(path: &str, op: Op, holds: Kind) -> SearchError {
    SearchError::Operator {
        path: path.to_owned(),
        op: op.as_str(),
        holds: holds.describe(),
    }
}

/// Converts one written value to what the attribute holds.
fn scalar(
    path: &str,
    value: &Value,
    target: Target,
    limits: &Limits,
) -> Result<Scalar, SearchError> {
    let wrong = |reason: String| SearchError::Value {
        path: path.to_owned(),
        reason,
    };
    let text = |text: &str| {
        if text.len() > limits.max_text {
            Err(wrong(format!(
                "a value may hold at most {} bytes",
                limits.max_text
            )))
        } else {
            Ok(Scalar::Text(text.to_owned()))
        }
    };
    match (target.kind, value) {
        (Kind::Text | Kind::Any, Value::String(written)) => text(written),
        (Kind::Integer, Value::String(written)) if target.time => time("value", written)
            .map(Scalar::Integer)
            .map_err(|error| wrong(error.to_string())),
        (Kind::Integer | Kind::Any, Value::Number(number)) if number.is_i64() => {
            let integer = number.as_i64().unwrap_or_default();
            if !target.values.is_empty() && !target.values.contains(&integer) {
                return Err(wrong(format!("{integer} is not a defined value")));
            }
            Ok(Scalar::Integer(integer))
        }
        (Kind::Float | Kind::Any, Value::Number(number)) => number
            .as_f64()
            .map(Scalar::Float)
            .ok_or_else(|| wrong(format!("{number} is not a number searches can compare"))),
        (Kind::Boolean | Kind::Any, Value::Bool(boolean)) => Ok(Scalar::Boolean(*boolean)),
        (kind, other) => Err(wrong(format!(
            "it holds {}, but the value is {}",
            kind.describe(),
            describe(other)
        ))),
    }
}

fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "missing",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "text",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}
