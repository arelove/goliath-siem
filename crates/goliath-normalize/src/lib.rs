//! Declarative source definitions that turn raw log records into OCSF events.
//!
//! A source definition says, in YAML, how a log source's bytes split into
//! records, how a record decodes, which kind of record it is, and where each
//! of its fields goes in OCSF. People who know a log source can write one
//! without writing Rust. The model is `docs/adr/0007-source-and-parser-model.md`.
//!
//! Nothing a source sends is dropped. A record that cannot become an event is
//! a [`DeadLetter`] with its raw bytes intact. A field whose value does not
//! convert is kept as written under `unmapped` and reported as an [`Issue`],
//! and the event still goes on to detection.
//!
//! Definitions shipped with this crate live in `sources/`, each with fixtures
//! of raw records and the events they must produce.
//!
//! # Example
//!
//! ```
//! use goliath_normalize::{Normalizer, Outcome, SYSMON};
//!
//! let sysmon = Normalizer::from_yaml(SYSMON)?;
//! let raw = br##"{"Event": {
//!     "System": {
//!         "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
//!         "EventID": 1,
//!         "TimeCreated": { "#attributes": { "SystemTime": "2026-09-24T10:15:30.1234567Z" } },
//!         "Computer": "WS-07"
//!     },
//!     "EventData": { "Image": "C:\\Windows\\notepad.exe", "ProcessId": "42", "RuleName": "-" }
//! }}"##;
//!
//! sysmon.normalize(raw, |outcome| match outcome {
//!     Outcome::Event(normalized) => {
//!         assert_eq!(normalized.event["class_uid"], 1007);
//!         assert_eq!(normalized.event["process"]["pid"], 42);
//!         assert_eq!(normalized.event["time"], 1_790_244_930_123_i64);
//!         // Nothing is dropped: fields the definition does not map are kept.
//!         assert_eq!(normalized.event["unmapped"]["RuleName"], "-");
//!     }
//!     other => panic!("{other:?}"),
//! });
//! # Ok::<(), goliath_normalize::DefinitionError>(())
//! ```

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod auditd;
pub mod definition;
pub mod error;
pub mod normalizer;
pub mod wire;

pub use definition::SourceDefinition;
pub use error::DefinitionError;
pub use normalizer::{DeadLetter, EventId, Issue, Normalized, Normalizer, Outcome, Stage};
pub use wire::{Envelope, WireError};

/// The Sysmon source definition shipped with this crate.
pub const SYSMON: &str = include_str!("../sources/sysmon.yaml");

/// The Falco source definition shipped with this crate.
pub const FALCO: &str = include_str!("../sources/falco.yaml");

/// The Microsoft Entra ID sign-in log definition shipped with this crate.
pub const ENTRA: &str = include_str!("../sources/entra.yaml");

/// The Linux audit log definition shipped with this crate.
pub const AUDITD: &str = include_str!("../sources/auditd.yaml");

/// Every definition shipped with this crate, by name.
pub const BUILTIN: &[(&str, &str)] = &[
    ("auditd", AUDITD),
    ("entra", ENTRA),
    ("falco", FALCO),
    ("sysmon", SYSMON),
];

/// The shipped definition named `name`, if there is one.
pub fn builtin(name: &str) -> Option<&'static str> {
    BUILTIN
        .iter()
        .find(|(builtin, _)| *builtin == name)
        .map(|(_, text)| *text)
}
