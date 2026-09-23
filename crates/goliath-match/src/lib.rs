//! Evaluation of resolved detection rules against OCSF events.
//!
//! Rules arrive resolved by `goliath-rule`: they refer only to OCSF paths, and
//! every modifier of the source language has already been turned into a
//! wildcard pattern or a typed test. This crate decides whether an event
//! matches.
//!
//! Two evaluators answer that question:
//!
//! - The [reference evaluator](mod@reference) checks one rule against one
//!   event, written for obvious correctness. It defines what a match means.
//! - The [engine](mod@engine) evaluates many rules against one event,
//!   sharing the work between them, and must return exactly what the
//!   reference evaluator returns.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod engine;
pub mod error;
pub mod reference;
mod semantics;

pub use engine::{Engine, Scratch};
pub use error::CompileError;
pub use reference::ReferenceRule;
