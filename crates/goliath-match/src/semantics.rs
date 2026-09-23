//! Value semantics shared by every evaluator.
//!
//! The reference evaluator defines what a match means, and the engine must
//! agree with it exactly. Wherever the engine does not have a faster way to
//! answer a question, it asks it through the same functions as the reference
//! evaluator, so the two cannot drift apart there. The semantics themselves
//! are documented on [`crate::reference`].

use std::net::IpAddr;

use goliath_rule::{ClassValue, Comparison, FieldPath, Network, Number, StringTest, Test, fold};
use goliath_sigma::RegexFlags;
use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::error::CompileError;

/// Upper bound on the compiled size of one regular expression, in bytes.
///
/// The `regex` crate runs in time linear in the input whatever the pattern,
/// so a rule cannot make matching slow; this bounds the memory a pattern can
/// make compilation take instead.
///
/// Classes such as `\w` are Unicode aware, which makes them large: `SigmaHQ`'s
/// `-k\s\w{1,64}` compiles to more than a megabyte. Ten megabytes, the `regex`
/// crate's own default, loads every rule in the repository.
///
/// Unicode classes are also a deliberate difference from PCRE, where `\w`,
/// `\d`, and `\s` are ASCII only. Positive classes match more here, so a
/// value spelled with non-ASCII letters or digits cannot slip past a rule by
/// that alone; negated classes such as `\W` match correspondingly less.
pub(crate) const REGEX_SIZE_LIMIT: usize = 10 << 20;

pub(crate) fn regex(pattern: &str, flags: RegexFlags) -> Result<Regex, CompileError> {
    RegexBuilder::new(pattern)
        .case_insensitive(flags.case_insensitive)
        .multi_line(flags.multiline)
        .dot_matches_new_line(flags.dot_all)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|source| CompileError::Regex {
            pattern: pattern.to_owned(),
            reason: source.to_string(),
        })
}

pub(crate) fn has_class_value(event: &Value, path: &FieldPath, expected: &ClassValue) -> bool {
    let mut found = false;
    path.visit(event, &mut |value| {
        found |= match expected {
            ClassValue::Integer(expected) => value.as_i64() == Some(*expected),
            ClassValue::String(expected) => value.as_str() == Some(expected.as_str()),
        };
    });
    found
}

/// Every non-null value any of `paths` reaches.
pub(crate) fn pool<'a>(event: &'a Value, paths: &[FieldPath]) -> Vec<&'a Value> {
    let mut values = Vec::new();
    pool_into(event, paths, &mut values);
    values
}

/// Appends every non-null value any of `paths` reaches to `values`, in the
/// order [`pool`] returns them.
pub(crate) fn pool_into<'a>(event: &'a Value, paths: &[FieldPath], values: &mut Vec<&'a Value>) {
    for path in paths {
        path.visit(event, &mut |value| {
            if !value.is_null() {
                values.push(value);
            }
        });
    }
}

/// Reports whether `regex` matches some value's text, without copying
/// strings: the same answer as testing [`text`] of each value.
pub(crate) fn regex_matches_any(regex: &Regex, values: &[&Value]) -> bool {
    values.iter().any(|value| match value {
        Value::String(text) => regex.is_match(text),
        Value::Number(number) => regex.is_match(&number.to_string()),
        _ => false,
    })
}

pub(crate) fn test_values(test: &Test, values: &[&Value], event: &Value) -> bool {
    match test {
        Test::String(test) => values
            .iter()
            .filter_map(|value| text(value))
            .any(|text| string_matches(test, &text)),
        Test::Cidr(network) => values
            .iter()
            .filter_map(|value| value.as_str())
            .filter_map(|text| text.trim().parse::<IpAddr>().ok())
            .any(|address| Network::contains(network, address)),
        Test::Exists(expected) => values.is_empty() != *expected,
        Test::Null => values.is_empty(),
        Test::Equals(expected) => values.iter().any(|value| {
            number(value)
                .is_some_and(|actual| compare(actual, *expected) == Some(std::cmp::Ordering::Equal))
        }),
        Test::Boolean(expected) => values.iter().any(|value| match value {
            Value::Bool(actual) => actual == expected,
            Value::String(written) => {
                written.eq_ignore_ascii_case(if *expected { "true" } else { "false" })
            }
            _ => false,
        }),
        Test::Compare { op, value: bound } => values.iter().any(|value| {
            number(value)
                .and_then(|actual| compare(actual, *bound))
                .is_some_and(|ordering| match op {
                    Comparison::Less => ordering.is_lt(),
                    Comparison::LessOrEqual => ordering.is_le(),
                    Comparison::Greater => ordering.is_gt(),
                    Comparison::GreaterOrEqual => ordering.is_ge(),
                })
        }),
        Test::FieldRef { paths, cased } => {
            let others = pool(event, paths);
            values
                .iter()
                .any(|value| others.iter().any(|other| same_value(value, other, *cased)))
        }
        // Compiled into `Check::Regex`; never reaches here.
        Test::Regex { .. } => false,
    }
}

pub(crate) fn string_matches(test: &StringTest, candidate: &str) -> bool {
    if test.cased {
        test.pattern.matches(candidate)
    } else {
        test.pattern.matches(&fold(candidate))
    }
}

/// A value as text: strings as they are, numbers in decimal.
pub(crate) fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// A value as a number: numbers as they are, strings that parse as numbers.
pub(crate) fn number(value: &Value) -> Option<Number> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .map(Number::Integer)
            .or_else(|| number.as_f64().map(Number::Float)),
        Value::String(text) => {
            let text = text.trim();
            text.parse::<i64>()
                .map(Number::Integer)
                .ok()
                .or_else(|| text.parse::<f64>().ok().map(Number::Float))
        }
        _ => None,
    }
}

/// Compares two numbers exactly when both are integers.
#[allow(clippy::cast_precision_loss)] // Only reached when one side is a float already.
pub(crate) fn compare(left: Number, right: Number) -> Option<std::cmp::Ordering> {
    match (left, right) {
        (Number::Integer(left), Number::Integer(right)) => Some(left.cmp(&right)),
        (Number::Integer(left), Number::Float(right)) => (left as f64).partial_cmp(&right),
        (Number::Float(left), Number::Integer(right)) => left.partial_cmp(&(right as f64)),
        (Number::Float(left), Number::Float(right)) => left.partial_cmp(&right),
    }
}

pub(crate) fn same_value(left: &Value, right: &Value, cased: bool) -> bool {
    match (text(left), text(right)) {
        (Some(left), Some(right)) if cased => left == right,
        (Some(left), Some(right)) => fold(&left) == fold(&right),
        _ => left == right,
    }
}

/// Calls `visit` on every string anywhere in `value` until it returns true.
pub(crate) fn any_string(value: &Value, visit: &mut impl FnMut(&str) -> bool) -> bool {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => items.iter().any(|item| any_string(item, visit)),
        Value::Object(map) => map.values().any(|item| any_string(item, visit)),
        _ => false,
    }
}
