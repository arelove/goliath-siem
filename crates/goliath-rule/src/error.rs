//! Error types.

use goliath_sigma::YamlError;
use thiserror::Error;

use crate::mapping::LogSourceSelector;

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

/// A mapping set that cannot be loaded, or cannot resolve a rule's log source.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MappingError {
    /// The file is not acceptable YAML, or does not have the shape of a
    /// mapping set.
    #[error(transparent)]
    Yaml(#[from] YamlError),

    /// An entry's selector names no key, so it would apply to every rule.
    #[error("mapping {index} selects every log source; name at least one key")]
    EmptySelector {
        /// The zero-based index of the entry.
        index: usize,
    },

    /// A field is mapped to an empty list of paths.
    #[error("mapping {index} maps field `{field}` to no path")]
    NoPaths {
        /// The zero-based index of the entry.
        index: usize,
        /// The field name.
        field: String,
    },

    /// Two entries have the same selector, so neither can be chosen.
    #[error("mappings {earlier} and {index} have the same log source selector")]
    DuplicateSelector {
        /// The zero-based index of the first entry.
        earlier: usize,
        /// The zero-based index of the repeated entry.
        index: usize,
    },

    /// No entry applies to a rule's log source.
    #[error("no mapping for log source ({logsource})")]
    NoMapping {
        /// The log source the rule declared.
        logsource: LogSourceSelector,
    },

    /// Two equally specific entries apply to a rule's log source.
    #[error("more than one mapping applies equally to log source ({logsource})")]
    Ambiguous {
        /// The log source the rule declared.
        logsource: LogSourceSelector,
    },
}
