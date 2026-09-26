//! Event searches for the Goliath security platform.
//!
//! A search is a typed structure, not text: a time range, optional classes,
//! and conditions on OCSF attributes, each checked against the schema before
//! any query runs. See `docs/adr/0016-event-search.md`.
//!
//! ```
//! use goliath_search::{Limits, Search};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let search: Search = serde_json::from_str(r#"{
//!     "from": "2026-09-25T00:00:00Z",
//!     "to": "2026-09-26T00:00:00Z",
//!     "classes": [1007],
//!     "filters": [{ "path": "process.cmd_line", "op": "contains", "value": "curl" }]
//! }"#)?;
//! let checked = search.check(&Limits::default())?;
//! assert_eq!(checked.conditions[0].path, ["process", "cmd_line"]);
//!
//! // A misspelled attribute is an error, not an empty result.
//! let search: Search = serde_json::from_str(r#"{
//!     "from": "2026-09-25T00:00:00Z",
//!     "to": "2026-09-26T00:00:00Z",
//!     "classes": [1007],
//!     "filters": [{ "path": "process.cmdline", "op": "contains", "value": "curl" }]
//! }"#)?;
//! assert!(search.check(&Limits::default()).is_err());
//! # Ok(())
//! # }
//! ```

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod check;
mod cursor;
mod error;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use cursor::{Cursor, CursorError};
pub use error::SearchError;

/// A search as a client writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Search {
    /// The start of the time range, inclusive, in RFC 3339.
    pub from: String,
    /// The end of the time range, exclusive, in RFC 3339.
    pub to: String,
    /// The classes to search, by `class_uid`; every class if empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<u32>,
    /// Conditions every event must meet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<Filter>,
    /// Events a page holds at most.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Where the previous page ended, to read the page after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
}

/// One condition on an attribute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// The OCSF path, such as `process.cmd_line`.
    pub path: String,
    /// The comparison.
    pub op: Op,
    /// What to compare with: a value, a list for [`Op::In`], or nothing for
    /// [`Op::Exists`] and [`Op::Missing`].
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub value: Value,
}

/// A comparison. Text comparisons ignore case.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Equal to the value.
    Equals,
    /// Not equal to the value, or absent.
    NotEquals,
    /// Text holding the value.
    Contains,
    /// Text starting with the value.
    StartsWith,
    /// Text ending with the value.
    EndsWith,
    /// Equal to one of the values.
    In,
    /// Greater than the value.
    Gt,
    /// Greater than or equal to the value.
    Gte,
    /// Less than the value.
    Lt,
    /// Less than or equal to the value.
    Lte,
    /// Present, whatever its value.
    Exists,
    /// Absent.
    Missing,
}

impl Op {
    /// The name as a search writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::NotEquals => "not_equals",
            Self::Contains => "contains",
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::In => "in",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Exists => "exists",
            Self::Missing => "missing",
        }
    }
}

/// What a deployment allows a search to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The longest time range, in milliseconds.
    pub max_span_ms: i64,
    /// Events a page may hold at most.
    pub max_limit: u32,
    /// Events a page holds when the search does not say.
    pub default_limit: u32,
    /// Filters a search may have.
    pub max_filters: usize,
    /// Values an [`Op::In`] may list.
    pub max_values: usize,
    /// Bytes a text value may hold.
    pub max_text: usize,
}

impl Default for Limits {
    /// 31 days, pages of 100 up to 1,000 events, 32 filters, 1,000 listed
    /// values, and 4 KiB of text.
    fn default() -> Self {
        Self {
            max_span_ms: 31 * 24 * 60 * 60 * 1000,
            max_limit: 1000,
            default_limit: 100,
            max_filters: 32,
            max_values: 1000,
            max_text: 4096,
        }
    }
}

/// A search that passed every check, ready to become a query.
#[derive(Debug, Clone, PartialEq)]
pub struct Checked {
    /// The start of the range, inclusive, in milliseconds since the epoch.
    pub from: i64,
    /// The end of the range, exclusive, in milliseconds since the epoch.
    pub to: i64,
    /// The classes, sorted and without repeats; every class if empty.
    pub classes: Vec<u32>,
    /// The conditions, in the order written.
    pub conditions: Vec<Condition>,
    /// Events the page holds at most.
    pub limit: u32,
    /// Where the previous page ended.
    pub after: Option<Cursor>,
}

/// A condition whose path and value fit the schema.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    /// The path's segments, such as `["process", "cmd_line"]`. Every segment
    /// is free of backticks, backslashes, and control characters.
    pub path: Vec<String>,
    /// What the attribute holds.
    pub kind: Kind,
    /// The comparison.
    pub op: Op,
    /// The values: none for [`Op::Exists`] and [`Op::Missing`], several for
    /// [`Op::In`], one otherwise. All of one type.
    pub values: Vec<Scalar>,
}

/// What an attribute holds, as far as a search compares it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Text.
    Text,
    /// A whole number, including times as milliseconds.
    Integer,
    /// A floating point number.
    Float,
    /// A boolean.
    Boolean,
    /// An object, which can only be present or absent.
    Object,
    /// Anything, as under `unmapped`: the values say what to compare as.
    Any,
}

impl Kind {
    fn describe(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Integer => "an integer",
            Self::Float => "a number",
            Self::Boolean => "a boolean",
            Self::Object => "an object",
            Self::Any => "any value",
        }
    }
}

/// A value to compare with.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Scalar {
    /// Text.
    Text(String),
    /// A whole number.
    Integer(i64),
    /// A floating point number.
    Float(f64),
    /// A boolean.
    Boolean(bool),
}
