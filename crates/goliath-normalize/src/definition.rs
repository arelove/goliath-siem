//! The source definition file format.
//!
//! A definition is written by people who know a log source, not Rust, and is
//! loaded as untrusted input: see `docs/adr/0007-source-and-parser-model.md`
//! for the model and `sources/sysmon.yaml` for a complete example.

use std::collections::BTreeMap;

use serde::Deserialize;

/// A source definition as written.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDefinition {
    /// The source's name, such as `sysmon`.
    pub name: String,
    /// Increased whenever the output for some input changes, so a stored
    /// event can be traced to the definition that produced it.
    pub version: u32,
    /// How a byte stream splits into records.
    pub framing: Framing,
    /// How a record becomes a field map.
    pub decoding: Decoding,
    /// Values a source writes for a field it has no value for, such as
    /// Windows' `-`. A field whose source holds one is not written, as if
    /// the source had left it out; the value is still kept under
    /// `unmapped` where the kind keeps the object it is in.
    #[serde(default)]
    pub nil: Vec<String>,
    /// A member that holds a batch of records, such as `Records` in the log
    /// files AWS delivers. A decoded object whose only member this is,
    /// holding an array, is taken as the records in the array, each with
    /// its own raw bytes; any other record is taken as it is. `.` names the
    /// record itself: a record that is an array, as many APIs answer with,
    /// is taken as its elements.
    pub unwrap: Option<String>,
    /// Fields every kind writes, such as the time and the device.
    #[serde(default)]
    pub common: BTreeMap<String, FieldSpec>,
    /// The kinds of record the source produces, tried in order.
    pub kinds: Vec<KindDefinition>,
}

/// How a byte stream splits into records.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framing {
    /// One record per line. Blank lines are skipped.
    Lines,
    /// JSON values one after another, separated by any whitespace, as
    /// `evtx_dump` writes them.
    JsonValues,
    /// Linux audit lines, grouped into one record per event by their
    /// `msg=audit(time:serial)`, whether or not they are adjacent. Needs
    /// `auditd` decoding.
    AuditEvents,
    /// Syslog messages framed as RFC 6587 describes, each either preceded by
    /// its length in bytes and a space or ending at its line's end, as
    /// senders over TCP write them. Needs a `syslog` decoding.
    Syslog,
}

/// How a record becomes a field map.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decoding {
    /// A JSON object.
    Json,
    /// Linux audit records, `key=value` fields per line, as one object with
    /// each record under its type, such as `SYSCALL.exe` or `PATH.0.name`.
    Auditd,
    /// A syslog message, RFC 5424 or RFC 3164, as one object with its
    /// header's fields, such as `hostname` and `app_name`, and the text
    /// after the header as `message`.
    Syslog,
    /// A syslog message whose text after the header is JSON, decoded under
    /// `message`, for applications that log JSON over syslog.
    SyslogJson,
}

/// One kind of record, and how it maps to an OCSF class.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindDefinition {
    /// A name for the kind, used in errors and reports.
    pub name: String,
    /// Source paths and the values they must hold for a record to be of this
    /// kind. Values compare exactly: `1` does not equal `"1"`.
    pub when: BTreeMap<String, Scalar>,
    /// The OCSF class and activity of the resulting event.
    pub class: ClassSpec,
    /// OCSF attributes and where their values come from.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldSpec>,
    /// Source objects whose other members are all kept under `unmapped`,
    /// by their own names, so that nothing the source wrote is dropped. `.`
    /// names the record itself, for sources that write every field at its
    /// top level.
    #[serde(default)]
    pub unmapped: Vec<String>,
}

/// The OCSF class of a kind. The category and type follow from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassSpec {
    /// `class_uid`.
    pub class_uid: u32,
    /// `activity_id`.
    pub activity_id: u32,
}

/// Where an attribute's value comes from.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum FieldSpec {
    /// A source path, copied as it is.
    Path(String),
    /// A source path, converted.
    Converted {
        /// The source path.
        from: String,
        /// The conversion.
        #[serde(rename = "as")]
        coercion: Coercion,
    },
    /// A source path, translated through a table, as a source's own words
    /// become the values of an OCSF enumeration.
    Translated {
        /// The source path.
        from: String,
        /// Source values, as text, and what each becomes. A number in the
        /// source is looked up by its decimal text.
        map: BTreeMap<String, Scalar>,
        /// What a value the table does not list becomes, such as `99`, the
        /// OCSF `Other`. Without it, such a value is kept under `unmapped`
        /// and reported as an issue.
        #[serde(default)]
        otherwise: Option<Scalar>,
    },
    /// A constant.
    Value {
        /// The value.
        value: Scalar,
    },
}

/// A conversion of a source value to an OCSF type.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coercion {
    /// Text; a number becomes its decimal text.
    String,
    /// A whole number, from a number, its decimal text, or its hexadecimal
    /// text after `0x`, as Windows writes process and logon identifiers.
    Integer,
    /// An RFC 3339 time, such as `2025-12-25T14:30:27.369114Z`, as the
    /// milliseconds since the Unix epoch OCSF stores.
    Timestamp,
    /// An RFC 3339 time written without an offset, such as Microsoft 365's
    /// `2026-09-28T12:00:01`, taken as UTC, as milliseconds. A time with an
    /// offset is read with it.
    UtcTimestamp,
    /// Seconds since the Unix epoch, with a fraction if any, such as
    /// auditd's `1727251200.123`, as milliseconds.
    UnixSeconds,
    /// An IP address, v4 or v6, kept as written. Text that is not one, such
    /// as the service name AWS writes where a service made a call, is
    /// reported and kept under `unmapped`, never written as an address.
    Ip,
}

/// A constant or a value to compare with, as YAML writes it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    /// `true` or `false`.
    Boolean(bool),
    /// A whole number.
    Integer(i64),
    /// Text.
    String(String),
}

impl From<&Scalar> for serde_json::Value {
    fn from(scalar: &Scalar) -> Self {
        match scalar {
            Scalar::Boolean(value) => Self::Bool(*value),
            Scalar::Integer(value) => Self::from(*value),
            Scalar::String(value) => Self::String(value.clone()),
        }
    }
}
