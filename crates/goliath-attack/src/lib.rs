//! Adversary knowledge frameworks, with MITRE ATT&CK as the first: its
//! tactics, techniques, and the data components that detect them, read from
//! the STIX 2.1 bundles MITRE publishes, and coverage of a rule set against
//! the data a deployment collects.
//!
//! Two questions are answered apart: whether a rule detects a technique,
//! coverage, and whether the data that rule reads is collected, capability.
//! A technique with a rule and none of its data collected is reported as
//! blind: the rule exists and cannot fire. See
//! `docs/adr/0009-attack-knowledge-model.md`.
//!
//! ```no_run
//! use goliath_attack::{Framework, RuleRef, assess, layer};
//!
//! let bundle = std::fs::read_to_string("enterprise-attack-19.2.json")?;
//! let framework = Framework::from_stix(&bundle)?;
//! let rules = [RuleRef::from_sigma_tags(
//!     "Encoded PowerShell",
//!     &["attack.execution".to_owned(), "attack.t1059.001".to_owned()],
//! )];
//! let coverage = assess(&framework, &rules, &["Process Creation".to_owned()])?;
//! let navigator = layer(&framework, &coverage, "Our coverage");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod coverage;
mod framework;
mod navigator;

pub use coverage::{
    Broken, BrokenReference, Coverage, RuleRef, TechniqueCoverage, Verdict, assess,
    technique_of_tag,
};
pub use framework::{DataComponent, Framework, State, Tactic, Technique};
pub use navigator::layer;

/// Why a framework could not be read, or coverage assessed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttackError {
    /// The bundle is not JSON.
    #[error("the bundle is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The JSON is not a framework bundle.
    #[error("the bundle cannot be read: {0}")]
    Bundle(String),
    /// A collected data component the framework does not have.
    #[error("ATT&CK {version} has no data component named `{name}`")]
    UnknownDataComponent {
        /// The name as given.
        name: String,
        /// The framework version.
        version: String,
    },
}
