//! What the stored events add up to over a span of time, for an overview:
//! counts by time and severity, the most frequent classes, sources, hosts,
//! and users, and what arrived in the last seconds.
//!
//! These are counts to look at, not to audit: they read without `FINAL`, so
//! an event delivered twice counts twice until ClickHouse merges its copies.
//! A search is what finds each event once.

use clickhouse::Row;
use serde::Deserialize;

use crate::error::StoreError;
use crate::search::{SearchLimits, with_limits};
use crate::store::Store;

/// Entries in each most-frequent list.
const TOP: u32 = 5;

/// Events of one severity in one step of the series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Row, Deserialize)]
pub struct Bucket {
    /// The step's start, in milliseconds since the epoch.
    pub at: i64,
    /// The OCSF `severity_id`.
    pub severity_id: u8,
    /// Events.
    pub count: u64,
}

/// A value and how many events hold it.
#[derive(Debug, Clone, PartialEq, Eq, Row, Deserialize)]
pub struct Frequent {
    /// The value, as text.
    pub key: String,
    /// Events that hold it.
    pub count: u64,
}

/// Events that arrived in one second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Row, Deserialize)]
pub struct Arrived {
    /// The second, since the epoch.
    pub second: u32,
    /// Events.
    pub count: u64,
}

/// The stored events over a span of time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overview {
    /// Events by step and severity, oldest step first; steps with none are
    /// absent.
    pub series: Vec<Bucket>,
    /// The most frequent classes, by `class_uid`.
    pub classes: Vec<Frequent>,
    /// The most frequent sources.
    pub sources: Vec<Frequent>,
    /// The most frequent `device.hostname`s.
    pub hosts: Vec<Frequent>,
    /// The most frequent `actor.user.name`s.
    pub users: Vec<Frequent>,
    /// Records that could not become events, received within the span.
    pub dead_letters: u64,
}

/// What each most-frequent list counts. Fixed text, never a client's.
const KEYS: [&str; 4] = [
    "toString(class_uid)",
    "toString(source)",
    "event.device.hostname.:String",
    "event.actor.user.name.:String",
];

impl Store {
    /// The events whose `time` is in `from..to`, in milliseconds since the
    /// epoch, counted in steps of `step` milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a query fails or exceeds
    /// `limits`.
    pub async fn overview(
        &self,
        from: i64,
        to: i64,
        step: i64,
        limits: SearchLimits,
    ) -> Result<Overview, StoreError> {
        const WITHIN: &str = "time >= fromUnixTimestamp64Milli({from:Int64}, 'UTC') \
                              AND time < fromUnixTimestamp64Milli({to:Int64}, 'UTC')";
        let series = with_limits(
            self.client()
                .query(&format!(
                    "SELECT intDiv(toUnixTimestamp64Milli(time), {{step:Int64}}) * {{step:Int64}} AS at, \
                     severity_id, count() AS count \
                     FROM events WHERE {WITHIN} \
                     GROUP BY at, severity_id ORDER BY at, severity_id"
                ))
                .param("from", from)
                .param("to", to)
                .param("step", step.max(1)),
            limits,
        )
        .fetch_all::<Bucket>()
        .await?;
        let mut frequent = Vec::with_capacity(KEYS.len());
        for key in KEYS {
            let rows = with_limits(
                self.client()
                    .query(&format!(
                        "SELECT ifNull({key}, '') AS key, count() AS count \
                         FROM events WHERE {WITHIN} AND key != '' \
                         GROUP BY key ORDER BY count DESC, key LIMIT {TOP}"
                    ))
                    .param("from", from)
                    .param("to", to),
                limits,
            )
            .fetch_all::<Frequent>()
            .await?;
            frequent.push(rows);
        }
        let dead_letters = with_limits(
            self.client()
                .query(
                    "SELECT count() FROM dead_letters \
                     WHERE received >= fromUnixTimestamp64Milli({from:Int64}, 'UTC') \
                     AND received < fromUnixTimestamp64Milli({to:Int64}, 'UTC')",
                )
                .param("from", from)
                .param("to", to),
            limits,
        )
        .fetch_one::<u64>()
        .await?;
        let [classes, sources, hosts, users] =
            <[Vec<Frequent>; 4]>::try_from(frequent).unwrap_or_default();
        Ok(Overview {
            series,
            classes,
            sources,
            hosts,
            users,
            dead_letters,
        })
    }

    /// Events that arrived in each of the last `seconds` seconds, by when
    /// the platform took their records, oldest first; seconds with none are
    /// absent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails or exceeds
    /// `limits`.
    pub async fn arrivals(
        &self,
        seconds: u32,
        limits: SearchLimits,
    ) -> Result<Vec<Arrived>, StoreError> {
        let query = self
            .client()
            .query(
                "SELECT toUnixTimestamp(received) AS second, count() AS count \
                 FROM events WHERE received >= now64(3) - toIntervalSecond({seconds:UInt32}) \
                 GROUP BY second ORDER BY second",
            )
            .param("seconds", seconds);
        Ok(with_limits(query, limits).fetch_all::<Arrived>().await?)
    }
}
