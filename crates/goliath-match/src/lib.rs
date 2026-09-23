//! Evaluation of resolved detection rules against OCSF events.
//!
//! Rules arrive resolved by `goliath-rule`: they refer only to OCSF paths, and
//! every modifier of the source language has already been turned into a
//! wildcard pattern or a typed test. This crate decides whether an event
//! matches.
//!
//! For now it holds the [reference evaluator](mod@reference), which defines what
//! a match means. The fast engine will be tested against it.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod error;
pub mod reference;

pub use error::CompileError;
pub use reference::ReferenceRule;
