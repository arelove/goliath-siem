//! Parses [Sigma](https://github.com/SigmaHQ/sigma) detection rules into a
//! typed, inspectable AST.
//!
//! This crate parses and validates. It does not evaluate rules and does not
//! translate them to any query language: evaluation lives in `goliath-match`,
//! and query backends are separate crates.
//!
//! # The condition language
//!
//! A Sigma condition combines the search identifiers defined by a rule.
//! Precedence, loosest first: `or`, `and`, `not`. Parentheses group.
//!
//! ```text
//! selection and not filter
//! 1 of selection_* and not all of filter_*
//! (selection_a or selection_b) and not them
//! ```
//!
//! Keywords are recognized case-insensitively, since rules in the wild do not
//! consistently follow the specification's lower case.
//!
//! # Errors carry spans
//!
//! Every failure names a byte range in the source. Rule authoring is
//! increasingly assisted by tooling and language models, and both correct a
//! mistake far more reliably when told where it is.
//!
//! ```
//! use goliath_sigma::{ConditionError, parse_condition};
//!
//! let source = "selection and";
//! let error = parse_condition(source).unwrap_err();
//! assert!(matches!(error, ConditionError::UnexpectedEnd { .. }));
//! assert_eq!(error.span().start, source.len());
//! ```
//!
//! # What is deliberately refused
//!
//! Legacy aggregation expressions (`| count() by User > 5`) are rejected rather
//! than ignored. Silently dropping an aggregation turns a threshold rule into
//! one that fires on every single event, which is worse than refusing to load
//! the rule at all.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod condition;
pub mod error;
pub mod lexer;
pub mod parser;
pub mod span;

pub use condition::{Condition, Quantifier, Target};
pub use error::ConditionError;
pub use parser::parse_condition;
pub use span::Span;
