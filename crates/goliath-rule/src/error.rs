//! Error types.

use thiserror::Error;

/// A field path that cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    /// The path is empty.
    #[error("field path is empty")]
    Empty,

    /// A segment between dots is empty.
    #[error("field path `{path}` has an empty segment at position {position}")]
    EmptySegment {
        /// The path as written.
        path: String,
        /// The zero-based index of the empty segment.
        position: usize,
    },
}
