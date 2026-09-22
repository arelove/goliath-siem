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

/// A failure to parse a detection map key into a field and its modifiers.
///
/// Modifier mistakes are silent at runtime: a misspelled modifier, or one
/// applied in the wrong order, produces a rule that loads and never fires.
/// Refusing the rule is the only way the author finds out.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ModifierError {
    /// The key had no field name before the first `|`.
    #[error("`{key}` has no field name")]
    EmptyFieldName {
        /// The key as written.
        key: String,
    },

    /// A modifier name was not recognized.
    #[error("unknown modifier `{modifier}` in `{key}`")]
    Unknown {
        /// The unrecognized name.
        modifier: String,
        /// Its index among the modifiers, counting from zero.
        position: usize,
        /// The key as written.
        key: String,
    },

    /// A regex flag appeared without a `re` before it.
    #[error("`{flag}` in `{key}` is a regex flag and must follow `re`")]
    RegexFlagWithoutRe {
        /// The flag as written.
        flag: String,
        /// The key as written.
        key: String,
    },

    /// Two modifiers of the same exclusive role were combined.
    #[error("`{first}` and `{second}` in `{key}` cannot be combined")]
    Conflicting {
        /// The modifier already present.
        first: String,
        /// The modifier that conflicts with it.
        second: String,
        /// The key as written.
        key: String,
    },
}

/// A rule file that is not acceptable YAML.
///
/// Raised both for syntax errors and for input refused on safety grounds:
/// duplicate keys, unsupported tags, or alias expansion beyond the budget.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct YamlError {
    /// The parser's description of the problem.
    pub message: String,
    /// One-based line of the problem, when known.
    pub line: Option<u64>,
    /// One-based column of the problem, when known.
    pub column: Option<u64>,
}

/// A failure to parse a Sigma rule.
///
/// Errors below the YAML layer name the search identifier and field involved.
/// YAML line numbers are not available there, because interpretation happens
/// after deserialization; the identifier and field locate the problem within
/// one rule precisely enough to fix it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RuleError {
    /// The file is not acceptable YAML, or does not have the shape of a rule.
    #[error(transparent)]
    Yaml(#[from] YamlError),

    /// The detection block has no `condition`.
    #[error("the detection block has no condition")]
    MissingCondition,

    /// `condition` is neither a string nor a non-empty list of strings.
    #[error("condition must be a string or a list of strings, found {found}")]
    InvalidConditionType {
        /// The kind of value found instead.
        found: &'static str,
    },

    /// A condition failed to parse.
    #[error("invalid condition `{text}`: {source}")]
    InvalidCondition {
        /// The condition as written, which the error's span points into.
        text: String,
        /// The parse failure.
        source: ConditionError,
    },

    /// `timeframe` is not a string.
    #[error("timeframe must be a string, found {found}")]
    InvalidTimeframe {
        /// The kind of value found instead.
        found: &'static str,
    },

    /// A search is empty or null, so it can never match.
    #[error("search `{identifier}` is empty and can never match")]
    EmptySearch {
        /// The search identifier.
        identifier: String,
    },

    /// A search list mixes mappings with plain values.
    #[error("search `{identifier}` mixes mappings with plain values")]
    MixedSearchList {
        /// The search identifier.
        identifier: String,
    },

    /// A field key failed to parse.
    #[error("in search `{identifier}`: {source}")]
    InvalidFieldKey {
        /// The search identifier.
        identifier: String,
        /// The parse failure.
        source: ModifierError,
    },

    /// A field's value is a list or mapping where a scalar was required.
    #[error("in search `{identifier}`, field `{field}` has {found} as a value")]
    InvalidFieldValue {
        /// The search identifier.
        identifier: String,
        /// The field key as written.
        field: String,
        /// The kind of value found.
        found: &'static str,
    },

    /// A field's value list is empty, so the field can never match.
    #[error("in search `{identifier}`, field `{field}` has an empty value list")]
    EmptyValueList {
        /// The search identifier.
        identifier: String,
        /// The field key as written.
        field: String,
    },
}
