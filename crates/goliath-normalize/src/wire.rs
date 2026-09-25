//! How outcomes travel between roles.
//!
//! Roles exchange bytes, never shared memory
//! (`docs/adr/0006-deployment-topology.md`), so the normalizer's output is
//! encoded before it enters a pipe, and every role reading it decodes the
//! same format. An encoded outcome starts with a byte naming its format, so
//! that a later, more compact format can be read alongside records already
//! waiting in a durable pipe.

use serde::{Deserialize, Serialize};

use crate::normalizer::Outcome;

/// The first byte of an outcome encoded as JSON.
const JSON: u8 = 1;

/// An outcome, and the source definition that produced it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// The source's name, such as `sysmon`.
    pub source: String,
    /// The version of the source definition.
    pub version: u32,
    /// What became of the record.
    pub outcome: Outcome,
}

/// Bytes that are not an encoded outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an encoded outcome: {0}")]
pub struct WireError(String);

impl Envelope {
    /// An envelope for `outcome` of the source `source` at definition
    /// version `version`.
    pub fn new(source: impl Into<String>, version: u32, outcome: Outcome) -> Self {
        Self {
            source: source.into(),
            version,
            outcome,
        }
    }

    /// The envelope as bytes, for a pipe.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![JSON];
        // Writing JSON into a vector fails only for a map with non-string
        // keys, which no outcome contains.
        if serde_json::to_writer(&mut bytes, self).is_err() {
            bytes.truncate(1);
        }
        bytes
    }

    /// An envelope from bytes [`encode`](Self::encode) wrote.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the bytes are in no known format, or do not
    /// hold an envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        match bytes.split_first() {
            Some((&JSON, json)) => {
                serde_json::from_slice(json).map_err(|error| WireError(error.to_string()))
            }
            Some((format, _)) => Err(WireError(format!("unknown format {format}"))),
            None => Err(WireError("no bytes".to_owned())),
        }
    }
}
