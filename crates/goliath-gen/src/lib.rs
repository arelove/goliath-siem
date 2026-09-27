//! A synthetic organization's security telemetry, for measuring Goliath.
//!
//! An [`Organization`] is generated from a seed: offices, people with common
//! names in their real proportions, their accounts in each system, and their
//! machines. Its telemetry is written in each source's own format, as the
//! shipped source definitions read it, so that measuring the platform
//! measures normalization too. Beside it, the generator writes what no real
//! dataset records: which identifiers belong to the same person or machine.
//!
//! The design is `docs/adr/0017-benchmark-rig.md`.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod data;
mod org;
mod random;

pub use org::{Host, HostKind, Office, Options, Organization, ServerRole, User};
