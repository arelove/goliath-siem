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

    /// The literal automaton could not be built, for instance because the
    /// rules hold more literal text than it can index.
    #[error("literal index cannot be built: {reason}")]
    Automaton {
        /// Why it was refused.
        reason: String,
    },
}
