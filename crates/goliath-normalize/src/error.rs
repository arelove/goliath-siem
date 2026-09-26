//! Error types.

use goliath_ocsf::schema::PathError as SchemaPathError;
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

    /// The framing and the decoding cannot be used together.
    #[error("framing `{framing}` cannot be used with decoding `{decoding}`")]
    Decoding {
        /// The framing as written.
        framing: &'static str,
        /// The decoding as written.
        decoding: &'static str,
    },

    /// The definition has no kinds, so every record would be rejected.
    #[error("the definition has no kinds")]
    NoKinds,

    /// A kind names a class the OCSF schema does not define.
    #[error("kind `{kind}`: OCSF {version} has no class {class_uid}")]
    UnknownClass {
        /// The kind.
        kind: String,
        /// The `class_uid` as written.
        class_uid: u32,
        /// The schema version checked against.
        version: &'static str,
    },

    /// A kind names an activity its class does not define.
    #[error("kind `{kind}`: class `{class}` has no activity {activity_id}")]
    UnknownActivity {
        /// The kind.
        kind: String,
        /// The class name.
        class: &'static str,
        /// The `activity_id` as written.
        activity_id: u32,
    },

    /// A target is not an attribute of the kind's class.
    #[error("kind `{kind}`: {source}")]
    Attribute {
        /// The kind; a common field is reported for the first kind it fails
        /// in.
        kind: String,
        /// Where the path left the schema.
        source: SchemaPathError,
    },

    /// A field writes a value the attribute cannot hold.
    #[error("kind `{kind}`: `{target}` holds {holds}, but the field writes {writes}")]
    Type {
        /// The kind; a common field is reported for the first kind it fails
        /// in.
        kind: String,
        /// The target as written.
        target: String,
        /// What the attribute holds, such as `` `integer_t` ``.
        holds: String,
        /// What the field writes, such as `text`.
        writes: &'static str,
    },

    /// A constant is not one of the values an enumerated attribute defines.
    #[error("kind `{kind}`: {value} is not a defined value of `{target}`")]
    UnknownValue {
        /// The kind; a common field is reported for the first kind it fails
        /// in.
        kind: String,
        /// The target as written.
        target: String,
        /// The constant.
        value: i64,
    },

    /// A translation table is empty, or its values are not all of one type.
    #[error("kind `{kind}`: the translation for `{target}` {reason}")]
    Translation {
        /// The kind the field belongs to, or `common`.
        kind: String,
        /// The target as written.
        target: String,
        /// What is wrong with the table.
        reason: &'static str,
    },

    /// A target lies inside an array, so there is no one place to write it.
    #[error("kind `{kind}`: `{target}` is inside an array, which a field cannot write into")]
    WithinArray {
        /// The kind; a common field is reported for the first kind it fails
        /// in.
        kind: String,
        /// The target as written.
        target: String,
    },
}
