//! Error types.

use thiserror::Error;

/// A resolved rule the engine cannot run.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CompileError {
    /// A regular expression that does not compile.
    #[error("regular expression `{pattern}` cannot be used: {reason}")]
    Regex {
        /// The expression as written.
        pattern: String,
        /// Why it was refused.
        reason: String,
    },
}
