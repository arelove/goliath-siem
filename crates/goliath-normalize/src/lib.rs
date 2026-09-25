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

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod definition;
pub mod error;
pub mod normalizer;

pub use definition::SourceDefinition;
pub use error::DefinitionError;
pub use normalizer::{DeadLetter, Issue, Normalized, Normalizer, Outcome, Stage};

/// The Sysmon source definition shipped with this crate.
pub const SYSMON: &str = include_str!("../sources/sysmon.yaml");
