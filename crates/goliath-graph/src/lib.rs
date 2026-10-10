//! The entity graph of the Goliath security platform, as
//! `docs/adr/0025-entity-graph.md` decides it: what events show of the
//! things they name.
//!
//! An event names an account, a machine, an address, a domain, a file, and
//! each source names them its own way. This crate reads an OCSF event and
//! says, without a lookup and without a decision about identity:
//!
//! - the [`Identifier`]s it gives, each in the one form it is compared in,
//!   and whether each is [strong](Strength) enough to name one thing;
//! - the [`Claim`]s: two identifiers given as one thing, since they were in
//!   one object of the event;
//! - the [`Link`]s: one thing seen to act on another, such as an account
//!   that signed in to a machine.
//!
//! Which identifiers are one entity is decided elsewhere, from the claims,
//! and applied when the graph is read. Nothing here merges.
//!
//! # Example
//!
//! ```
//! use goliath_graph::observe;
//! use serde_json::json;
//!
//! let seen = observe(&json!({
//!     "class_uid": 3002, "category_uid": 3, "activity_id": 1,
//!     "user": { "name": "adam", "domain": "CORP", "uid": "S-1-5-21-1-2-3-1104" },
//!     "device": { "hostname": "dc-1.corp.example" },
//! }));
//!
//! // The SID and the name were one account's.
//! assert_eq!(seen.claims[0].one.to_string(), "user:sid:s-1-5-21-1-2-3-1104");
//! assert_eq!(seen.claims[0].other.to_string(), "user:name:corp\\adam");
//! // The account signed in to the machine.
//! assert_eq!(seen.links[0].kind.as_str(), "logged_on_to");
//! assert_eq!(seen.links[0].to.to_string(), "host:name:dc-1.corp.example");
//! ```

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod identifier;
mod measure;
mod observe;
mod resolve;

pub use identifier::{Form, Identifier, IdentifierError, Kind, Strength};
pub use measure::{Measured, measure};
pub use observe::{Claim, Link, LinkKind, Seen, observe};
pub use resolve::{
    Decision, Decisions, DecisionsError, Evidence, Resolution, Resolved, SHARED_OVER, Said,
    Standing, Summary, resolve,
};
