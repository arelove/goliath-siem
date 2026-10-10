//! What events show of the things they name, as rows: links between
//! things, and claims that two identifiers are one thing.
//!
//! See `docs/adr/0025-entity-graph.md`. The rows are counts over an hour or
//! a day under the identifiers the events gave, as text. Nothing here
//! knows what an identifier is or decides which are one entity: that is
//! `goliath-graph` and the resolution that reads these tables.

use clickhouse::Row;
use goliath_search::Cursor;
use serde::{Deserialize, Serialize};

use crate::error::StoreError;
use crate::store::Store;

const DAY: i64 = 86_400_000;
const HOUR: i64 = 3_600_000;

/// How often two things were seen in one way within one hour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkSeen {
    /// The one that acted, as an identifier's text.
    pub src: String,
    /// What it did, such as `logged_on_to`.
    pub link: String,
    /// The one it was done to.
    pub dst: String,
    /// Events that showed it.
    pub events: u64,
    /// The first of them, by its time.
    pub first: Cursor,
    /// The last of them.
    pub last: Cursor,
}

/// How often two identifiers were seen as one thing within one day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSeen {
    /// The strongest identifier of the object that gave both.
    pub one: String,
    /// The other.
    pub other: String,
    /// What read them as one, such as `user`.
    pub rule: String,
    /// Events that showed it.
    pub events: u64,
    /// The first of them, by its time.
    pub first: Cursor,
    /// The last of them.
    pub last: Cursor,
}

/// What a run of events of one scope showed, as it is sent and stored.
///
/// Whoever gathers it adds up what repeats within an hour for links and
/// within a day for claims, by the first event's time; the store adds up
/// across runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Graphed {
    /// The scope of the events, as their source has it; empty for none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// When the platform took the events, in milliseconds since the epoch.
    pub received: i64,
    /// The links.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<LinkSeen>,
    /// The claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimSeen>,
}

#[derive(Debug, Row, Serialize)]
struct LinkRow<'a> {
    received_day: u16,
    scope: &'a str,
    src: &'a str,
    link: &'a str,
    dst: &'a str,
    hour: u32,
    events: u64,
    first_seen: i64,
    last_seen: i64,
    first_event: [u8; 24],
    last_event: [u8; 24],
}

#[derive(Debug, Row, Serialize)]
struct ClaimRow<'a> {
    day: u16,
    scope: &'a str,
    one: &'a str,
    other: &'a str,
    rule: &'a str,
    events: u64,
    first_seen: i64,
    last_seen: i64,
    first_event: [u8; 24],
    last_event: [u8; 24],
}

/// Where an event is, in bytes that order as events do in time: the time
/// in milliseconds, big-endian, then the identifier. A time before the
/// epoch is written as the epoch, so that the order holds.
fn place(at: Cursor) -> [u8; 24] {
    let mut bytes = [0; 24];
    let time = u64::try_from(at.time).unwrap_or(0);
    bytes[..8].copy_from_slice(&time.to_be_bytes());
    bytes[8..].copy_from_slice(&at.id);
    bytes
}

/// The day `milliseconds` is in, counted from the epoch, as a `Date` is
/// stored. A time no `Date` holds is its nearest end.
fn day(milliseconds: i64) -> u16 {
    u16::try_from(milliseconds.div_euclid(DAY).max(0)).unwrap_or(u16::MAX)
}

/// The start of the hour `milliseconds` is in, in seconds since the epoch,
/// as a `DateTime` is stored.
fn hour(milliseconds: i64) -> u32 {
    u32::try_from((milliseconds.div_euclid(HOUR) * 3600).max(0)).unwrap_or(u32::MAX)
}

impl Store {
    /// Writes what runs of events showed: links, then claims.
    ///
    /// A link is written under the hour of its first event and the day it
    /// was received; a claim under the day of its first event. Rows of one
    /// key are added up by the tables, so a run written twice counts its
    /// events twice and changes nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a request fails.
    pub async fn write_graph(&self, graphed: &[Graphed]) -> Result<(), StoreError> {
        if graphed.iter().any(|run| !run.links.is_empty()) {
            let mut insert = self.client().insert::<LinkRow<'_>>("graph_links").await?;
            for run in graphed {
                for seen in &run.links {
                    insert
                        .write(&LinkRow {
                            received_day: day(run.received),
                            scope: &run.scope,
                            src: &seen.src,
                            link: &seen.link,
                            dst: &seen.dst,
                            hour: hour(seen.first.time),
                            events: seen.events,
                            first_seen: seen.first.time,
                            last_seen: seen.last.time,
                            first_event: place(seen.first),
                            last_event: place(seen.last),
                        })
                        .await?;
                }
            }
            insert.end().await?;
        }
        if graphed.iter().any(|run| !run.claims.is_empty()) {
            let mut insert = self.client().insert::<ClaimRow<'_>>("graph_claims").await?;
            for run in graphed {
                for seen in &run.claims {
                    insert
                        .write(&ClaimRow {
                            day: day(seen.first.time),
                            scope: &run.scope,
                            one: &seen.one,
                            other: &seen.other,
                            rule: &seen.rule,
                            events: seen.events,
                            first_seen: seen.first.time,
                            last_seen: seen.last.time,
                            first_event: place(seen.first),
                            last_event: place(seen.last),
                        })
                        .await?;
                }
            }
            insert.end().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(time: i64, id: u8) -> Cursor {
        Cursor { time, id: [id; 16] }
    }

    #[test]
    fn the_places_of_events_order_as_the_events_do_in_time() {
        let times = [0, 1, 255, 256, 1_790_330_000_000, 1_790_330_000_001];
        for pair in times.windows(2) {
            assert!(place(at(pair[0], 9)) < place(at(pair[1], 0)), "{pair:?}");
        }
        // Within one millisecond, by the identifier, as a search pages.
        assert!(place(at(5, 1)) < place(at(5, 2)));
        // Before the epoch is the epoch, and not after everything.
        assert_eq!(place(at(-1, 3)), place(at(0, 3)));
    }

    #[test]
    fn a_row_is_under_the_hour_and_the_day_of_its_first_event() {
        // 2026-09-25T10:33:20Z.
        let time = 1_790_332_400_000;
        assert_eq!(hour(time), 1_790_330_400);
        assert_eq!(i64::from(day(time)), time / DAY);
        assert_eq!((hour(-1), day(-1)), (0, 0));
        assert_eq!(day(i64::MAX), u16::MAX);
    }

    #[test]
    fn what_was_seen_is_sent_as_json_and_read_back() {
        let graphed = Graphed {
            scope: String::new(),
            received: 1_790_330_000_000,
            links: vec![LinkSeen {
                src: "user:name:corp\\adam".to_owned(),
                link: "logged_on_to".to_owned(),
                dst: "host:name:dc-1.corp.example".to_owned(),
                events: 3,
                first: at(1_790_330_000_000, 1),
                last: at(1_790_330_900_000, 2),
            }],
            claims: Vec::new(),
        };
        let sent = serde_json::to_string(&graphed).unwrap();
        assert!(
            !sent.contains("scope") && !sent.contains("claims"),
            "{sent}"
        );
        assert_eq!(serde_json::from_str::<Graphed>(&sent).unwrap(), graphed);
    }
}
