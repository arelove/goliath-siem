//! Detection rules resolved to OCSF paths.
//!
//! A rule language such as Sigma names fields the way a log source names them.
//! Goliath evaluates OCSF events, so every rule is resolved once, at load time,
//! into a form that refers only to OCSF paths. The streaming match engine and
//! the `ClickHouse` backend both consume that form and never the original, which
//! is what keeps them from disagreeing about what a rule means. The decision is
//! `docs/adr/0012-sigma-field-mapping.md`.
//!
//! This crate holds the pieces every execution path shares: paths into an
//! event and the case folding that defines case insensitive comparison.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod error;
pub mod fold;
pub mod path;

pub use error::PathError;
pub use fold::fold;
pub use path::FieldPath;
