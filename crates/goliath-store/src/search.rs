//! Searches, compiled to parameterized ClickHouse queries.
//!
//! See `docs/adr/0016-event-search.md`. A value never enters the SQL text:
//! each is a query parameter, `{p0:String}`, typed by the attribute. Paths do
//! enter it, after `goliath-search` checked them against the schema and
//! refused any segment holding a backtick, a backslash, or a control
//! character; each segment is quoted with backticks.

use std::fmt::Write as _;

use clickhouse::Row;
use goliath_search::{Checked, Condition, Cursor, Kind, Op, Scalar};
use serde::{Deserialize, Serialize};

use crate::error::StoreError;
use crate::store::Store;

/// What one search may cost the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchLimits {
    /// Seconds a query may run.
    pub max_seconds: u32,
    /// Rows a query may read.
    pub max_rows_read: u64,
}

impl Default for SearchLimits {
    /// Ten seconds and one billion rows.
    fn default() -> Self {
        Self {
            max_seconds: 10,
            max_rows_read: 1_000_000_000,
        }
    }
}

/// An event a search found.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    /// Where it is, to fetch it again or to page after it.
    pub at: Cursor,
    /// Its class.
    pub class_uid: u32,
    /// The source that produced it.
    pub source: String,
    /// The kind of record it was in that source.
    pub kind: String,
    /// The OCSF event.
    pub event: serde_json::Value,
}

/// One page of results, newest first.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    /// The events.
    pub events: Vec<Found>,
    /// Where to continue, if the page is full and more may follow.
    pub next: Option<Cursor>,
}

/// An event with what normalization reported about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    /// The event.
    pub found: Found,
    /// The source's definition version that produced it.
    pub source_version: u32,
    /// Values that did not convert, as `(target, source, reason)`.
    pub issues: Vec<(String, String, String)>,
}

/// A value bound to a query parameter.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
enum Param {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Texts(Vec<String>),
    Integers(Vec<i64>),
    Floats(Vec<f64>),
}

/// A query and its parameters.
#[derive(Debug, Clone, PartialEq)]
struct Compiled {
    sql: String,
    params: Vec<(String, Param)>,
}

impl Compiled {
    /// Adds a parameter and returns its placeholder, such as `{p3:String}`.
    fn bind(&mut self, param: Param) -> String {
        let name = format!("p{}", self.params.len());
        let placeholder = format!("{{{name}:{}}}", param.clickhouse_type());
        self.params.push((name, param));
        placeholder
    }
}

impl Param {
    fn clickhouse_type(&self) -> &'static str {
        match self {
            Self::Text(_) => "String",
            Self::Integer(_) => "Int64",
            Self::Float(_) => "Float64",
            Self::Boolean(_) => "Bool",
            Self::Texts(_) => "Array(String)",
            Self::Integers(_) => "Array(Int64)",
            Self::Floats(_) => "Array(Float64)",
        }
    }
}

// Aliases differ from the columns' names: ClickHouse would otherwise read
// the alias wherever the query names the column, in WHERE and ORDER BY too.
const COLUMNS: &str = "toUnixTimestamp64Milli(time) AS time_ms, id, class_uid, source, kind, \
                       toJSONString(event) AS event_json";

#[derive(Debug, Row, Deserialize)]
struct FoundRow {
    time_ms: i64,
    id: [u8; 16],
    class_uid: u32,
    source: String,
    kind: String,
    event_json: String,
}

#[derive(Debug, Row, Deserialize)]
struct StoredRow {
    time_ms: i64,
    id: [u8; 16],
    class_uid: u32,
    source: String,
    kind: String,
    event_json: String,
    source_version: u32,
    #[serde(rename = "issues.target")]
    targets: Vec<String>,
    #[serde(rename = "issues.source")]
    sources: Vec<String>,
    #[serde(rename = "issues.reason")]
    reasons: Vec<String>,
}

impl FoundRow {
    fn into_found(self) -> Result<Found, StoreError> {
        Ok(Found {
            at: Cursor {
                time: self.time_ms,
                id: self.id,
            },
            class_uid: self.class_uid,
            source: self.source,
            kind: self.kind,
            event: serde_json::from_str(&self.event_json)
                .map_err(|error| StoreError::Stored(error.to_string()))?,
        })
    }
}

impl Store {
    /// Runs a checked search: one page of matching events, newest first.
    ///
    /// Runs read-only, within `limits`, and with `FINAL`, so that an event
    /// stored twice is found once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails or exceeds its
    /// limits, and [`StoreError::Stored`] if a stored event is not JSON.
    pub async fn search(&self, search: &Checked, limits: SearchLimits) -> Result<Page, StoreError> {
        let compiled = compile(search);
        let mut query = self.client().query(&compiled.sql);
        for (name, param) in &compiled.params {
            query = query.param(name, param);
        }
        let rows = with_limits(query, limits).fetch_all::<FoundRow>().await?;
        let events = rows
            .into_iter()
            .map(FoundRow::into_found)
            .collect::<Result<Vec<_>, _>>()?;
        let full = u32::try_from(events.len()).is_ok_and(|count| count == search.limit);
        let next = full.then(|| events.last().map(|found| found.at)).flatten();
        Ok(Page { events, next })
    }

    /// The event at `at`, with its normalization issues, if it is stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails, and
    /// [`StoreError::Stored`] if the stored event is not JSON.
    pub async fn event(
        &self,
        at: Cursor,
        limits: SearchLimits,
    ) -> Result<Option<Stored>, StoreError> {
        let sql = format!(
            "SELECT {COLUMNS}, source_version, issues.target, issues.source, issues.reason \
             FROM events FINAL \
             WHERE time = fromUnixTimestamp64Milli({{time:Int64}}, 'UTC') \
             AND id = toFixedString(unhex({{id:String}}), 16) \
             LIMIT 1"
        );
        let id = hex(&at.id);
        let query = self
            .client()
            .query(&sql)
            .param("time", at.time)
            .param("id", id);
        let row = with_limits(query, limits)
            .fetch_optional::<StoredRow>()
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let issues = row
            .targets
            .into_iter()
            .zip(row.sources)
            .zip(row.reasons)
            .map(|((target, source), reason)| (target, source, reason))
            .collect();
        let found = FoundRow {
            time_ms: row.time_ms,
            id: row.id,
            class_uid: row.class_uid,
            source: row.source,
            kind: row.kind,
            event_json: row.event_json,
        }
        .into_found()?;
        Ok(Some(Stored {
            found,
            source_version: row.source_version,
            issues,
        }))
    }
}

fn with_limits(query: clickhouse::query::Query, limits: SearchLimits) -> clickhouse::query::Query {
    query
        // Read-only whatever the user may do; 2 still lets this request
        // set the limits below.
        .with_setting("readonly", "2")
        .with_setting("max_execution_time", limits.max_seconds.to_string())
        .with_setting("max_rows_to_read", limits.max_rows_read.to_string())
        .with_setting("output_format_json_quote_64bit_integers", "0")
}

fn compile(search: &Checked) -> Compiled {
    let mut compiled = Compiled {
        sql: String::new(),
        params: Vec::new(),
    };
    let from = compiled.bind(Param::Integer(search.from));
    let to = compiled.bind(Param::Integer(search.to));
    let mut conditions = vec![
        format!("time >= fromUnixTimestamp64Milli({from}, 'UTC')"),
        format!("time < fromUnixTimestamp64Milli({to}, 'UTC')"),
    ];
    if !search.classes.is_empty() {
        let classes: Vec<String> = search
            .classes
            .iter()
            .map(|&class_uid| compiled.bind(Param::Integer(i64::from(class_uid))))
            .collect();
        conditions.push(format!("class_uid IN ({})", classes.join(", ")));
    }
    if let Some(after) = search.after {
        let time = compiled.bind(Param::Integer(after.time));
        let id = compiled.bind(Param::Text(hex(&after.id)));
        conditions.push(format!(
            "(time, id) < (fromUnixTimestamp64Milli({time}, 'UTC'), toFixedString(unhex({id}), 16))"
        ));
    }
    for condition in &search.conditions {
        let sql = filter(&mut compiled, condition);
        conditions.push(sql);
    }
    let limit = compiled.bind(Param::Integer(i64::from(search.limit)));
    compiled.sql = format!(
        "SELECT {COLUMNS} FROM events FINAL WHERE {} ORDER BY time DESC, id DESC LIMIT {limit}",
        conditions.join(" AND ")
    );
    compiled
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// The attribute as a dynamic subcolumn of `event`, each segment quoted.
fn column(path: &[String]) -> String {
    path.iter().fold("event".to_owned(), |mut column, segment| {
        let _ = write!(column, ".`{segment}`");
        column
    })
}

/// The object at the path, for attributes that hold one.
fn object(path: &[String]) -> String {
    let rest: Vec<String> = path.iter().map(|segment| format!("`{segment}`")).collect();
    format!("event.^{}", rest.join("."))
}

fn filter(compiled: &mut Compiled, condition: &Condition) -> String {
    let dynamic = column(&condition.path);
    match condition.op {
        Op::Exists | Op::Missing => {
            let present = match condition.kind {
                Kind::Object => format!("notEmpty(JSONAllPaths({}))", object(&condition.path)),
                Kind::Any => format!(
                    "(isNotNull({dynamic}) OR notEmpty(JSONAllPaths({})))",
                    object(&condition.path)
                ),
                _ => format!("isNotNull({dynamic})"),
            };
            if condition.op == Op::Exists {
                present
            } else {
                format!("NOT {present}")
            }
        }
        op => match &condition.values[..] {
            [Scalar::Text(_), ..] => text(compiled, &dynamic, op, &condition.values),
            _ => typed(compiled, &dynamic, op, &condition.values),
        },
    }
}

/// Text compared without regard to case.
fn text(compiled: &mut Compiled, dynamic: &str, op: Op, values: &[Scalar]) -> String {
    let texts: Vec<String> = values
        .iter()
        .filter_map(|value| match value {
            Scalar::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    let value = format!("{dynamic}.:String");
    if op == Op::In {
        let list = compiled.bind(Param::Texts(texts));
        return format!("has(arrayMap(v -> lowerUTF8(v), {list}), lowerUTF8({value}))");
    }
    let one = compiled.bind(Param::Text(texts.into_iter().next().unwrap_or_default()));
    match op {
        Op::NotEquals => format!("NOT coalesce(lowerUTF8({value}) = lowerUTF8({one}), false)"),
        Op::Contains => format!("positionCaseInsensitiveUTF8({value}, {one}) > 0"),
        Op::StartsWith => format!("startsWith(lowerUTF8({value}), lowerUTF8({one}))"),
        Op::EndsWith => format!("endsWith(lowerUTF8({value}), lowerUTF8({one}))"),
        _ => format!("lowerUTF8({value}) = lowerUTF8({one})"),
    }
}

/// Numbers and booleans, compared as their type.
fn typed(compiled: &mut Compiled, dynamic: &str, op: Op, values: &[Scalar]) -> String {
    let (value, list, one) = match values {
        [Scalar::Integer(_), ..] => (
            format!("{dynamic}.:Int64"),
            Param::Integers(
                values
                    .iter()
                    .filter_map(|value| match value {
                        Scalar::Integer(integer) => Some(*integer),
                        _ => None,
                    })
                    .collect(),
            ),
            values.first().cloned(),
        ),
        [Scalar::Float(_), ..] => (
            // A whole number in a float attribute is stored as an integer.
            format!("coalesce({dynamic}.:Float64, toFloat64({dynamic}.:Int64))"),
            Param::Floats(
                values
                    .iter()
                    .filter_map(|value| match value {
                        Scalar::Float(float) => Some(*float),
                        _ => None,
                    })
                    .collect(),
            ),
            values.first().cloned(),
        ),
        _ => (
            format!("{dynamic}.:Bool"),
            Param::Texts(Vec::new()),
            values.first().cloned(),
        ),
    };
    if op == Op::In {
        let list = compiled.bind(list);
        return format!("has({list}, {value})");
    }
    let one = compiled.bind(match one {
        Some(Scalar::Integer(integer)) => Param::Integer(integer),
        Some(Scalar::Float(float)) => Param::Float(float),
        Some(Scalar::Boolean(boolean)) => Param::Boolean(boolean),
        Some(Scalar::Text(text)) => Param::Text(text),
        _ => Param::Text(String::new()),
    });
    let comparison = match op {
        Op::Gt => ">",
        Op::Gte => ">=",
        Op::Lt => "<",
        Op::Lte => "<=",
        _ => "=",
    };
    if op == Op::NotEquals {
        format!("NOT coalesce({value} = {one}, false)")
    } else {
        format!("{value} {comparison} {one}")
    }
}

#[cfg(test)]
mod tests {
    use goliath_search::{Limits, Search};
    use serde_json::json;

    use super::*;

    fn compiled(filters: &serde_json::Value) -> Compiled {
        let search: Search = serde_json::from_value(json!({
            "from": "2026-09-25T00:00:00Z",
            "to": "2026-09-26T00:00:00Z",
            "classes": [1007],
            "filters": filters.clone(),
        }))
        .unwrap();
        compile(&search.check(&Limits::default()).unwrap())
    }

    #[test]
    fn values_are_parameters_and_never_sql() {
        let hostile = "'); DROP TABLE events; --";
        let compiled = compiled(&json!([
            { "path": "process.cmd_line", "op": "contains", "value": hostile },
            { "path": "unmapped.x", "op": "in", "value": [hostile] },
        ]));
        assert!(!compiled.sql.contains("DROP"), "{}", compiled.sql);
        assert!(
            compiled
                .params
                .iter()
                .any(|(_, param)| *param == Param::Text(hostile.to_owned()))
        );
        assert!(compiled.sql.contains(
            "positionCaseInsensitiveUTF8(event.`process`.`cmd_line`.:String, {p3:String}) > 0"
        ));
    }

    #[test]
    fn a_search_reads_newest_first_within_its_range_and_classes() {
        let compiled = compiled(&json!([]));
        assert_eq!(
            compiled.sql,
            "SELECT toUnixTimestamp64Milli(time) AS time_ms, id, class_uid, source, kind, \
             toJSONString(event) AS event_json FROM events FINAL \
             WHERE time >= fromUnixTimestamp64Milli({p0:Int64}, 'UTC') \
             AND time < fromUnixTimestamp64Milli({p1:Int64}, 'UTC') \
             AND class_uid IN ({p2:Int64}) \
             ORDER BY time DESC, id DESC LIMIT {p3:Int64}"
        );
    }

    #[test]
    fn each_operator_has_its_sql() {
        let cases = [
            (
                json!({ "path": "process.pid", "op": "gte", "value": 10 }),
                "event.`process`.`pid`.:Int64 >= {p3:Int64}",
            ),
            (
                json!({ "path": "process.pid", "op": "in", "value": [1, 2] }),
                "has({p3:Array(Int64)}, event.`process`.`pid`.:Int64)",
            ),
            (
                json!({ "path": "process.pid", "op": "not_equals", "value": 1 }),
                "NOT coalesce(event.`process`.`pid`.:Int64 = {p3:Int64}, false)",
            ),
            (
                json!({ "path": "process.name", "op": "equals", "value": "sh" }),
                "lowerUTF8(event.`process`.`name`.:String) = lowerUTF8({p3:String})",
            ),
            (
                json!({ "path": "process.name", "op": "ends_with", "value": ".exe" }),
                "endsWith(lowerUTF8(event.`process`.`name`.:String), lowerUTF8({p3:String}))",
            ),
            (
                json!({ "path": "process.file", "op": "missing" }),
                "NOT notEmpty(JSONAllPaths(event.^`process`.`file`))",
            ),
            (
                json!({ "path": "process.name", "op": "exists" }),
                "isNotNull(event.`process`.`name`)",
            ),
        ];
        for (filter, expected) in cases {
            let compiled = compiled(&json!([filter]));
            assert!(
                compiled.sql.contains(expected),
                "{filter}: {}",
                compiled.sql
            );
        }
    }
}
