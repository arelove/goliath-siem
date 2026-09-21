//! OCSF event types, validation, and observable extraction.
//!
//! This crate is the shared vocabulary of the Goliath security platform: every
//! component upstream of storage speaks [`Event`], and every component
//! downstream reads it.
//!
//! Schema version targeted: **OCSF 1.5.0**.
//!
//! # Design notes
//!
//! **Unknown values do not fail.** Enumerations carry an `Unrecognized`
//! variant, and class-specific attributes are preserved verbatim. An event
//! produced against a newer schema must still be ingested, because refusing it
//! loses evidence at the moment it matters.
//!
//! **Validation checks structure, not policy.** The invariants enforced here
//! are the arithmetic relationships OCSF states but JSON Schema cannot express.
//!
//! # Example
//!
//! ```
//! use goliath_ocsf::{Event, Metadata, Observable, ObservableType, Severity};
//! use serde_json::Map;
//!
//! let event = Event {
//!     class_uid: 1007,
//!     category_uid: Event::derive_category_uid(1007),
//!     activity_id: 1,
//!     type_uid: Event::derive_type_uid(1007, 1),
//!     time: 1_758_412_800_000,
//!     severity: Severity::Medium,
//!     metadata: Metadata { version: "1.5.0".to_owned(), ..Metadata::default() },
//!     observables: vec![Observable::new(
//!         "device.hostname",
//!         ObservableType::Hostname,
//!         "WS-001",
//!     )],
//!     message: None,
//!     start_time: None,
//!     end_time: None,
//!     attributes: Map::new(),
//!     unmapped: None,
//! };
//!
//! event.validate()?;
//! assert_eq!(event.matchable_observables().count(), 1);
//! # Ok::<(), goliath_ocsf::ValidationError>(())
//! ```

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic))]

pub mod error;
pub mod event;
pub mod observable;
pub mod severity;

pub use error::ValidationError;
pub use event::{Event, Metadata, Product, SourceDefinition, Timestamp};
pub use observable::{Observable, ObservableType};
pub use severity::Severity;

/// The OCSF schema version this crate targets.
pub const SCHEMA_VERSION: &str = "1.5.0";
