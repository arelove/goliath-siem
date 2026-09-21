//! Errors raised while parsing Sigma conditions.

use thiserror::Error;

use crate::span::Span;

/// A failure to parse a Sigma condition expression.
///
/// Every variant carries a [`Span`] into the source condition. A rule author,
/// or a tool acting on their behalf, needs to know which characters are wrong,
/// not merely that the rule did not parse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConditionError {
    /// The condition was empty or contained only whitespace.
    #[error("the condition is empty")]
    Empty,

    /// A character appeared that cannot begin any token.
    #[error("unexpected character `{character}`")]
    UnexpectedCharacter {
        /// The offending character.
        character: char,
        /// Where it appeared.
        span: Span,
    },

    /// A token appeared where the grammar did not allow it.
    #[error("expected {expected}, found {found}")]
    UnexpectedToken {
        /// What the grammar allowed at this position.
        expected: &'static str,
        /// What was found instead.
        found: &'static str,
        /// Where it appeared.
        span: Span,
    },

    /// The condition ended while more input was required.
    #[error("expected {expected}, but the condition ended")]
    UnexpectedEnd {
        /// What the grammar required.
        expected: &'static str,
        /// The end of the condition.
        span: Span,
    },

    /// A `(` was never closed.
    #[error("unclosed `(`")]
    UnclosedGroup {
        /// The opening parenthesis.
        span: Span,
    },

    /// A quantifier used a count other than `1`.
    ///
    /// The Sigma specification defines `1 of` and `all of`. Any other count has
    /// no defined meaning, and guessing one would silently change what a rule
    /// detects.
    #[error("`{value} of` is not defined by Sigma; use `1 of` or `all of`")]
    UnsupportedQuantifier {
        /// The count that was written.
        value: u64,
        /// Where it appeared.
        span: Span,
    },

    /// The condition used a legacy aggregation expression.
    ///
    /// Rejected rather than ignored: dropping an aggregation would turn a
    /// threshold rule into one that fires on every single event.
    #[error("aggregation expressions are not supported; express this as a correlation rule")]
    AggregationUnsupported {
        /// The `|` that introduced the aggregation, through the end of input.
        span: Span,
    },
}

impl ConditionError {
    /// Returns the source range this error refers to.
    pub fn span(&self) -> Span {
        match self {
            Self::Empty => Span::empty_at(0),
            Self::UnexpectedCharacter { span, .. }
            | Self::UnexpectedToken { span, .. }
            | Self::UnexpectedEnd { span, .. }
            | Self::UnclosedGroup { span }
            | Self::UnsupportedQuantifier { span, .. }
            | Self::AggregationUnsupported { span } => *span,
        }
    }
}
