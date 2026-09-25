//! Normalization outcomes, turned into rows.

use std::time::{SystemTime, UNIX_EPOCH};

use clickhouse::Row;
use goliath_normalize::{Normalizer, Outcome};
use serde::Serialize;
use serde_json::Value;

use crate::error::StoreError;

/// The range `DateTime64(3)` holds: 1900-01-01 to 2299-12-31, in
/// milliseconds since the Unix epoch.
const TIMES: std::ops::RangeInclusive<i64> = -2_208_988_800_000..=10_413_791_999_999;

/// The outcomes of normalizing records from one source, ready to write.
///
/// Rows are built as outcomes arrive, so a batch holds no reference to them.
#[derive(Debug, Clone)]
pub struct Batch {
    received: i64,
    source: String,
    source_version: u32,
    pub(crate) events: Vec<EventRow>,
    pub(crate) dead_letters: Vec<DeadLetterRow>,
}

#[derive(Debug, Clone, Row, Serialize)]
pub(crate) struct EventRow {
    received: i64,
    time: i64,
    class_uid: u32,
    category_uid: u32,
    type_uid: u64,
    activity_id: u32,
    severity_id: u8,
    id: [u8; 16],
    source: String,
    source_version: u32,
    kind: String,
    event: String,
    #[serde(rename = "issues.target")]
    issue_targets: Vec<String>,
    #[serde(rename = "issues.source")]
    issue_sources: Vec<String>,
    #[serde(rename = "issues.reason")]
    issue_reasons: Vec<String>,
}

#[derive(Debug, Clone, Row, Serialize)]
pub(crate) struct DeadLetterRow {
    received: i64,
    source: String,
    source_version: u32,
    stage: &'static str,
    error: String,
    #[serde(with = "serde_bytes")]
    raw: Vec<u8>,
}

impl Batch {
    /// An empty batch for records of the source `normalizer` reads, received
    /// now.
    pub fn new(normalizer: &Normalizer) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
            });
        Self::received_at(normalizer, now)
    }

    /// An empty batch for records of the source `normalizer` reads, received
    /// at `received` milliseconds since the Unix epoch.
    pub fn received_at(normalizer: &Normalizer, received: i64) -> Self {
        Self {
            received,
            source: normalizer.name().to_owned(),
            source_version: normalizer.version(),
            events: Vec::new(),
            dead_letters: Vec::new(),
        }
    }

    /// Adds an outcome of the batch's source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownOutcome`] for a kind of outcome this
    /// crate does not know where to store, rather than drop it.
    pub fn push(&mut self, outcome: Outcome) -> Result<(), StoreError> {
        match outcome {
            Outcome::Event(normalized) => {
                let event = &normalized.event;
                let number = |name: &str| event.get(name).and_then(Value::as_u64).unwrap_or(0);
                // The event's own time where it has one that fits, and when
                // it was received otherwise; the event keeps what it held.
                let time = event
                    .get("time")
                    .and_then(Value::as_i64)
                    .filter(|time| TIMES.contains(time))
                    .unwrap_or(self.received);
                let mut issue_targets = Vec::with_capacity(normalized.issues.len());
                let mut issue_sources = Vec::with_capacity(normalized.issues.len());
                let mut issue_reasons = Vec::with_capacity(normalized.issues.len());
                for issue in normalized.issues {
                    issue_targets.push(issue.target);
                    issue_sources.push(issue.source);
                    issue_reasons.push(issue.reason);
                }
                self.events.push(EventRow {
                    received: self.received,
                    time,
                    class_uid: narrow(number("class_uid")),
                    category_uid: narrow(number("category_uid")),
                    type_uid: number("type_uid"),
                    activity_id: narrow(number("activity_id")),
                    severity_id: narrow(number("severity_id")),
                    id: *normalized.id.as_bytes(),
                    source: self.source.clone(),
                    source_version: self.source_version,
                    kind: normalized.kind,
                    event: event.to_string(),
                    issue_targets,
                    issue_sources,
                    issue_reasons,
                });
            }
            Outcome::DeadLetter(dead) => self.dead_letters.push(DeadLetterRow {
                received: self.received,
                source: self.source.clone(),
                source_version: self.source_version,
                stage: dead.stage.as_str(),
                error: dead.error,
                raw: dead.raw,
            }),
            other => return Err(StoreError::UnknownOutcome(format!("{other:?}"))),
        }
        Ok(())
    }

    /// Whether the batch is for records of `normalizer`'s source and
    /// definition version.
    pub(crate) fn is_for(&self, normalizer: &Normalizer) -> bool {
        self.source == normalizer.name() && self.source_version == normalizer.version()
    }

    /// How many events the batch holds.
    pub fn events(&self) -> usize {
        self.events.len()
    }

    /// How many dead letters the batch holds.
    pub fn dead_letters(&self) -> usize {
        self.dead_letters.len()
    }

    /// Whether the batch holds nothing to write.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.dead_letters.is_empty()
    }
}

/// A class attribute in its column type. Out of range means the event did
/// not come from a checked definition; the column then says Unknown, and the
/// event still holds the value.
fn narrow<T: TryFrom<u64> + Default>(value: u64) -> T {
    T::try_from(value).unwrap_or_default()
}
