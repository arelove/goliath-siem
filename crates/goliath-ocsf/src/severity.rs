//! Event severity.

use serde::{Deserialize, Serialize};

/// An OCSF severity identifier.
///
/// Severity states how bad the observed activity is, independently of how
/// confident we are that it happened. Confidence is a separate attribute, and
/// conflating the two produces triage queues nobody trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Severity {
    /// Severity is not known to the producer.
    #[default]
    Unknown,
    /// Informational activity, carrying no judgement.
    Informational,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
    /// The event source has failed and is no longer reporting.
    Fatal,
    /// A severity the schema defines as outside the enumerated set.
    Other,
    /// A severity identifier introduced by a schema version newer than this build.
    Unrecognized(u32),
}

impl Severity {
    /// Returns the OCSF numeric identifier for this severity.
    pub const fn to_id(self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::Informational => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
            Self::Fatal => 6,
            Self::Other => 99,
            Self::Unrecognized(id) => id,
        }
    }

    /// Returns the severity for an OCSF numeric identifier.
    pub const fn from_id(id: u32) -> Self {
        match id {
            0 => Self::Unknown,
            1 => Self::Informational,
            2 => Self::Low,
            3 => Self::Medium,
            4 => Self::High,
            5 => Self::Critical,
            6 => Self::Fatal,
            99 => Self::Other,
            other => Self::Unrecognized(other),
        }
    }
}

impl From<u32> for Severity {
    fn from(id: u32) -> Self {
        Self::from_id(id)
    }
}

impl From<Severity> for u32 {
    fn from(severity: Severity) -> Self {
        severity.to_id()
    }
}

impl Serialize for Severity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.to_id())
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self::from_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_round_trip() {
        for id in (0..=6).chain(std::iter::once(99)) {
            assert_eq!(Severity::from_id(id).to_id(), id);
        }
    }

    #[test]
    fn ordering_follows_escalation() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::Informational);
    }

    #[test]
    fn unknown_ids_survive_round_trip() {
        assert_eq!(Severity::from_id(42), Severity::Unrecognized(42));
        assert_eq!(Severity::from_id(42).to_id(), 42);
    }
}
