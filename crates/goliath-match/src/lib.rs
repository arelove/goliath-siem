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
//!
//! # Example
//!
//! ```
//! use goliath_match::Engine;
//! use goliath_rule::{MappingSet, sigma};
//! use serde_json::json;
//!
//! let rule = goliath_sigma::parse_rule(
//!     r"
//! title: Notepad opens a script
//! logsource: { category: process_creation, product: windows }
//! detection:
//!   selection:
//!     Image|endswith: '\notepad.exe'
//!     CommandLine|contains: '.ps1'
//!   condition: selection
//! ",
//! )?;
//! let mappings = MappingSet::from_yaml(goliath_rule::SIGMA_WINDOWS)?;
//! let engine = Engine::new(vec![sigma::resolve(&rule, &mappings)?])?;
//!
//! let event = json!({
//!     "class_uid": 1007,
//!     "activity_id": 1,
//!     "device": { "os": { "type_id": 100 } },
//!     "process": {
//!         "file": { "path": r"C:\Windows\System32\NOTEPAD.EXE" },
//!         "cmd_line": r"notepad.exe C:\scripts\Setup.PS1",
//!     },
//! });
//! assert_eq!(engine.matches(&event), [0]);
//!
//! // For a stream, keep one scratch per thread; it stops allocating.
//! let mut scratch = engine.scratch();
//! let mut matched = Vec::new();
//! engine.matches_into(&event, &mut scratch, &mut matched);
//! assert_eq!(matched, [0]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod engine;
pub mod error;
pub mod reference;
mod required;
mod semantics;

pub use engine::{Engine, Scratch};
pub use error::CompileError;
pub use reference::ReferenceRule;
