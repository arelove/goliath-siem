//! Why a search is refused.

use thiserror::Error;

/// Why a search is refused. Every message is written for the person who
/// wrote the search.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SearchError {
    /// A bound of the time range is not a time.
    #[error("`{bound}` is not an RFC 3339 time, such as 2026-09-25T08:00:00Z: {reason}")]
    Time {
        /// `from` or `to`.
        bound: &'static str,
        /// Why it does not parse.
        reason: String,
    },
    /// The range ends before it starts.
    #[error("the time range is empty: `to` must be after `from`")]
    EmptyRange,
    /// The range is longer than the deployment allows.
    #[error("the time range is longer than {max_days} days")]
    SpanTooLong {
        /// The longest range allowed, in whole days.
        max_days: i64,
    },
    /// The page size is out of bounds.
    #[error("`limit` must be between 1 and {max}")]
    Limit {
        /// The largest page allowed.
        max: u32,
    },
    /// A class the schema does not define.
    #[error("OCSF {version} has no class {class_uid}")]
    UnknownClass {
        /// The class as written.
        class_uid: u32,
        /// The schema version.
        version: &'static str,
    },
    /// More filters than allowed.
    #[error("a search may have at most {max} filters")]
    TooManyFilters {
        /// The most allowed.
        max: usize,
    },
    /// A path names no attribute of a class searched.
    #[error("{0}")]
    Path(String),
    /// A path names an attribute of no class at all.
    #[error("`{path}` is not an attribute of any class")]
    NoClass {
        /// The path.
        path: String,
    },
    /// A path leads into an array.
    #[error("`{path}` is inside a list, which searches cannot look into yet")]
    Array {
        /// The path.
        path: String,
    },
    /// Classes disagree on what a path holds.
    #[error("`{path}` holds different types in different classes; name the class to search")]
    Ambiguous {
        /// The path.
        path: String,
    },
    /// A path segment holds a character searches do not accept.
    #[error(
        "`{path}`: path segments may not be empty or hold backticks, backslashes, or control characters"
    )]
    Segment {
        /// The path.
        path: String,
    },
    /// An operator that does not apply to what the attribute holds.
    #[error("`{op}` does not apply to `{path}`, which holds {holds}")]
    Operator {
        /// The path.
        path: String,
        /// The operator.
        op: &'static str,
        /// What the attribute holds.
        holds: &'static str,
    },
    /// A value that does not fit the attribute or the operator.
    #[error("`{path}`: {reason}")]
    Value {
        /// The path.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
}
