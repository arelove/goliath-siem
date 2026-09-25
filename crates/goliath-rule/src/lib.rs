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
//! event, the case folding that defines case insensitive comparison, and the
//! field mappings that translate a rule language's field names into paths.
//!
//! # Example
//!
//! ```
//! use goliath_rule::{FieldPath, MappingSet, sigma};
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
//! let resolved = sigma::resolve(&rule, &mappings)?;
//!
//! // Sigma's `Image` became OCSF paths, and the log source became a class.
//! let text = serde_json::to_string(&resolved)?;
//! assert!(text.contains("process.file.path"));
//! assert!(resolved.class.contains_key(&FieldPath::parse("class_uid")?));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod error;
pub mod fold;
pub mod mapping;
pub mod path;
pub mod resolved;
pub mod sigma;

pub use error::{MappingError, NetworkError, PathError, ResolveError};
pub use fold::{fold, fold_into};

/// The mapping set for Sigma's Windows log sources shipped with this crate,
/// ready for [`MappingSet::from_yaml`].
pub const SIGMA_WINDOWS: &str = include_str!("../mappings/sigma-windows.yaml");
pub use mapping::{ClassValue, LogSourceSelector, MappingSet, SourceMapping};
pub use path::FieldPath;
pub use resolved::{
    Comparison, Expr, MappingVersion, Network, Number, Predicate, ResolvedRule, StringTest, Test,
};
