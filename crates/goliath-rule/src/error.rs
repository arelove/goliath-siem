//! Error types.

use goliath_ocsf::schema::PathError as SchemaPathError;
use goliath_sigma::YamlError;
use thiserror::Error;

use crate::mapping::LogSourceSelector;

/// A field path that cannot be parsed.
#[non_exhaustive]
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

/// Text that is not an IP address or network.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("`{0}` is not an IP address or network")]
pub struct NetworkError(pub String);

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

    /// An entry's `class_uid` is not a class of the OCSF schema.
    #[error("mapping {index}: OCSF {version} has no class {class_uid}")]
    UnknownClass {
        /// The zero-based index of the entry.
        index: usize,
        /// The `class_uid` as written.
        class_uid: i64,
        /// The schema version checked against.
        version: &'static str,
    },

    /// A path is not an attribute of the entry's class.
    #[error("mapping {index}: {source}")]
    Attribute {
        /// The zero-based index of the entry.
        index: usize,
        /// Where the path left the schema.
        source: SchemaPathError,
    },

    /// A path names an attribute no value of a rule can be compared with.
    #[error("mapping {index}: `{path}` holds {holds}, which cannot equal {value}")]
    Type {
        /// The zero-based index of the entry.
        index: usize,
        /// The path as written.
        path: String,
        /// What the attribute holds, such as `` an object `file` ``.
        holds: String,
        /// What it would be compared with, such as `a rule's value`.
        value: String,
    },

    /// A class condition requires a value its enumerated attribute does
    /// not define, so no event could satisfy it.
    #[error("mapping {index}: {value} is not a defined value of `{path}`")]
    UnknownValue {
        /// The zero-based index of the entry.
        index: usize,
        /// The path as written.
        path: String,
        /// The value.
        value: i64,
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

/// A rule that cannot be resolved exactly.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ResolveError {
    /// No mapping applies to the rule's log source.
    #[error(transparent)]
    Mapping(#[from] MappingError),

    /// The mapping for the rule's log source does not map a field it uses.
    ///
    /// Refused rather than treated as absent: the rule would load and never
    /// fire, and the gap would be invisible.
    #[error("field `{field}` has no mapping for log source ({logsource})")]
    UnmappedField {
        /// The field name as the rule wrote it.
        field: String,
        /// The rule's log source.
        logsource: LogSourceSelector,
    },

    /// A modifier whose meaning depends on configuration this resolution
    /// does not have.
    #[error("field `{field}` uses `{modifier}`, which is not supported")]
    UnsupportedModifier {
        /// The field name.
        field: String,
        /// The modifier.
        modifier: &'static str,
    },

    /// A value that cannot mean anything under its modifiers.
    #[error("field `{field}`: {reason}")]
    InvalidValue {
        /// The field name.
        field: String,
        /// Why.
        reason: &'static str,
    },

    /// A value expands into more variants than a rule may carry.
    #[error("field `{field}` expands into {count} variants")]
    TooManyVariants {
        /// The field name.
        field: String,
        /// How many variants it would produce.
        count: usize,
    },

    /// A keyword that is not text.
    #[error("a keyword must be text, found {found}")]
    UnsupportedKeyword {
        /// What was found.
        found: &'static str,
    },
}
