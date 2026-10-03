//! Stored events read back by when the platform took them, for a role that
//! looks at them a second time: the detector, for what it did not match as
//! it arrived.
//!
//! The rows come as the server reads them, in no order and without `FINAL`:
//! an event stored twice may be read twice. A reader whose work on an event
//! is repeatable needs neither, and a range of any size is read in bounded
//! memory.

use clickhouse::Row;
use clickhouse::query::RowCursor;
use serde::Deserialize;

use crate::error::StoreError;
use crate::store::Store;

/// A stored event, as it is read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// When the platform took its record, in milliseconds since the Unix
    /// epoch.
    pub received: i64,
    /// Its identity.
    pub id: [u8; 16],
    /// The source that produced it.
    pub source: String,
    /// The OCSF event, as JSON text. It is left to the reader to parse, so
    /// that parsing can run off the thread that reads.
    pub event: String,
}

#[derive(Debug, Row, Deserialize)]
struct KeptRow {
    received_ms: i64,
    id: [u8; 16],
    source: String,
    event_json: String,
}

/// The events of a range of receipt time, one at a time.
pub struct Reading {
    cursor: RowCursor<KeptRow>,
}

impl std::fmt::Debug for Reading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reading").finish_non_exhaustive()
    }
}

impl Reading {
    /// The next event, or `None` after the last.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query failed or the
    /// connection was lost. What was read until then is no whole range:
    /// read the range again.
    pub async fn next(&mut self) -> Result<Option<Kept>, StoreError> {
        Ok(self.cursor.next().await?.map(|row| Kept {
            received: row.received_ms,
            id: row.id,
            source: row.source,
            event: row.event_json,
        }))
    }
}

impl Store {
    /// The stored events the platform took from `from` up to and not
    /// including `to`, in milliseconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the request cannot be made. A
    /// query the server refuses is reported by [`Reading::next`].
    pub fn received_between(&self, from: i64, to: i64) -> Result<Reading, StoreError> {
        let cursor = self
            .client()
            .query(
                "SELECT toUnixTimestamp64Milli(received) AS received_ms, id, source, \
                 toJSONString(event) AS event_json FROM events \
                 WHERE received >= fromUnixTimestamp64Milli({start:Int64}, 'UTC') \
                 AND received < fromUnixTimestamp64Milli({end:Int64}, 'UTC')",
            )
            .param("start", from)
            .param("end", to)
            .with_setting("readonly", "2")
            .with_setting("output_format_json_quote_64bit_integers", "0")
            .fetch::<KeptRow>()?;
        Ok(Reading { cursor })
    }

    /// Whether an event is stored that the platform took at `from`
    /// milliseconds since the Unix epoch or later. The writer stores in the
    /// order it reads, so this says it has come as far as `from`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails.
    pub async fn holds_received_from(&self, from: i64) -> Result<bool, StoreError> {
        let found = self
            .client()
            .query(
                "SELECT count() FROM (SELECT 1 FROM events \
                 WHERE received >= fromUnixTimestamp64Milli({start:Int64}, 'UTC') LIMIT 1)",
            )
            .param("start", from)
            .with_setting("readonly", "2")
            .fetch_one::<u64>()
            .await?;
        Ok(found > 0)
    }
}
