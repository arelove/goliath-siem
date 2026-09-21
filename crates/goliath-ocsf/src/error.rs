//! Errors raised while validating events.

use thiserror::Error;

use crate::event::Timestamp;

/// An OCSF invariant that an event failed to satisfy.
///
/// These describe structural contradictions, not policy. An event failing
/// validation is malformed, and normalization routes it to the dead letter
/// stream with its raw bytes intact rather than discarding it. See ADR-0007.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// `metadata.version` was absent or empty.
    #[error("metadata.version is required and must name an OCSF schema version")]
    MissingSchemaVersion,

    /// `time` was not a positive millisecond timestamp.
    #[error("time must be a positive millisecond timestamp, found {time}")]
    InvalidTime {
        /// The timestamp carried by the event.
        time: Timestamp,
    },

    /// `type_uid` did not equal `class_uid * 100 + activity_id`.
    #[error("type_uid is {found} but class and activity derive {expected}")]
    TypeUidMismatch {
        /// The value carried by the event.
        found: u64,
        /// The value the OCSF derivation rule requires.
        expected: u64,
    },

    /// `category_uid` did not match the category implied by `class_uid`.
    #[error("category_uid is {found} but class_uid derives {expected}")]
    CategoryMismatch {
        /// The value carried by the event.
        found: u32,
        /// The value the OCSF derivation rule requires.
        expected: u32,
    },

    /// `start_time` was later than `end_time`.
    #[error("start_time {start} is later than end_time {end}")]
    InvertedSpan {
        /// The start of the span.
        start: Timestamp,
        /// The end of the span.
        end: Timestamp,
    },
}
