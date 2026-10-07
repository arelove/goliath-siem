//! A synthetic organization's security telemetry, for measuring Goliath.
//!
//! An [`Organization`] is generated from a seed: offices, people with common
//! names in their real proportions, their accounts in each system, and their
//! machines. Its telemetry is written in each source's own format, as the
//! shipped source definitions read it, so that measuring the platform
//! measures normalization too. Beside it, the generator writes what no real
//! dataset records: which identifiers belong to the same person or machine.
//!
//! For measuring the detector, [`intel`] numbers indicators that ordinary
//! telemetry never holds, and [`Generator::planted`] writes an event that
//! holds one.
//!
//! The design is `docs/adr/0017-benchmark-rig.md`.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod data;
pub mod entra;
pub mod intel;
mod org;
mod random;
mod stream;
mod suricata;
pub mod sysmon;
mod time;
mod truth;

pub use org::{Host, HostKind, Office, Options, Organization, ServerRole, User};
pub use stream::{Generator, Record};
pub use truth::entities;
