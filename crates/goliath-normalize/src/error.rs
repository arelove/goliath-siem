//! Error types.

use goliath_rule::PathError;
use goliath_sigma::YamlError;
use thiserror::Error;

/// A source definition that cannot be loaded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DefinitionError {
    /// The file is not acceptable YAML, or does not have the shape of a
    /// source definition.
    #[error(transparent)]
    Yaml(#[from] YamlError),

    /// A path into the OCSF event cannot be parsed.
    #[error("kind `{kind}`: target `{target}`: {source}")]
    Target {
        /// The kind the field belongs to, or `common`.
        kind: String,
        /// The target as written.
        target: String,
        /// Why it cannot be parsed.
        source: PathError,
    },

    /// A path into the decoded record cannot be parsed.
    #[error("kind `{kind}`: source path `{path}` has an empty segment")]
    SourcePath {
        /// The kind the path belongs to, or `common`.
        kind: String,
        /// The path as written.
        path: String,
    },

    /// Two fields write the same attribute, or one writes inside another,
    /// so one of them would be lost.
    #[error("kind `{kind}`: targets `{first}` and `{second}` overlap")]
    Overlap {
        /// The kind the fields belong to, with the common fields included.
        kind: String,
        /// One target.
        first: String,
        /// The other.
        second: String,
    },

    /// A field writes an attribute the definition may not set directly.
    #[error("kind `{kind}`: `{target}` is set by {reason}, not by a field")]
    Reserved {
        /// The kind the field belongs to, or `common`.
        kind: String,
        /// The target as written.
        target: String,
        /// What sets it instead.
        reason: &'static str,
    },

    /// A kind has no condition, so it would accept every record and hide the
    /// kinds after it.
    #[error("kind `{kind}` has no `when` condition")]
    Unconditional {
        /// The kind.
        kind: String,
    },

    /// The definition has no kinds, so every record would be rejected.
    #[error("the definition has no kinds")]
    NoKinds,
}
