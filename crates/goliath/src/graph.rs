//! The `graph` role: reads every normalized event beside the writer, and
//! sends on what the events show of the things they name, links and claims
//! added up, for the writer to keep.
//!
//! See `docs/adr/0025-entity-graph.md`. Nothing here decides which
//! identifiers are one entity: the rows are under the identifiers the
//! events gave.

use std::collections::BTreeMap;

use goliath_graph::observe;
use goliath_normalize::{Envelope, Outcome};
use goliath_pipe::{Delivery, Receiver, Sender};
use goliath_search::Cursor;
use goliath_store::{ClaimSeen, Graphed, LinkSeen};
use tokio::sync::watch;
use tracing::warn;

use crate::RunError;
use crate::metrics::Metrics;
use crate::roles::{BATCH, Lag, POLL};

const HOUR: i64 = 3_600_000;
const DAY: i64 = 24 * HOUR;

/// How often one thing was seen, and the first and the last event that
/// showed it.
#[derive(Debug, Clone, Copy)]
struct Count {
    events: u64,
    first: Cursor,
    last: Cursor,
}

impl Count {
    fn one(at: Cursor) -> Self {
        Self {
            events: 1,
            first: at,
            last: at,
        }
    }

    fn add(&mut self, at: Cursor) {
        self.events += 1;
        if (at.time, at.id) < (self.first.time, self.first.id) {
            self.first = at;
        }
        if (at.time, at.id) > (self.last.time, self.last.id) {
            self.last = at;
        }
    }
}

/// What a batch of events gave, counted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Events looked at.
    pub(crate) events: u64,
    /// Links they showed, each event's counted.
    pub(crate) links: u64,
    /// Claims they showed.
    pub(crate) claims: u64,
}

/// What `deliveries` show, added up: a link once for each hour its events
/// are in, a claim once for each day.
///
/// The time of an event is its own where it has one, and when the platform
/// took it otherwise, as the store has it. All of it is under the time the
/// last record was received, which decides how long the rows are kept.
///
/// # Errors
///
/// Returns [`RunError::Corrupt`] if a record is not an envelope.
fn gather(deliveries: &[Delivery], now: i64) -> Result<(Graphed, Tally), RunError> {
    let mut links: BTreeMap<(String, &'static str, String, i64), Count> = BTreeMap::new();
    let mut claims: BTreeMap<(String, String, &'static str, i64), Count> = BTreeMap::new();
    let mut tally = Tally::default();
    let mut received = 0;
    for delivery in deliveries {
        let envelope = Envelope::decode(&delivery.payload)
            .map_err(|error| RunError::Corrupt(error.to_string()))?;
        let Outcome::Event(normalized) = &envelope.outcome else {
            continue;
        };
        let taken = envelope.received.unwrap_or(now);
        received = received.max(taken);
        let at = Cursor {
            time: normalized
                .event
                .get("time")
                .and_then(serde_json::Value::as_i64)
                .filter(|time| *time >= 0)
                .unwrap_or(taken),
            id: *normalized.id.as_bytes(),
        };
        let seen = observe(&normalized.event);
        tally.events += 1;
        tally.links += seen.links.len() as u64;
        tally.claims += seen.claims.len() as u64;
        for link in seen.links {
            let key = (
                link.from.to_string(),
                link.kind.as_str(),
                link.to.to_string(),
                at.time.div_euclid(HOUR),
            );
            links
                .entry(key)
                .and_modify(|count| count.add(at))
                .or_insert_with(|| Count::one(at));
        }
        for claim in seen.claims {
            let key = (
                claim.one.to_string(),
                claim.other.to_string(),
                claim.rule,
                at.time.div_euclid(DAY),
            );
            claims
                .entry(key)
                .and_modify(|count| count.add(at))
                .or_insert_with(|| Count::one(at));
        }
    }
    let graphed = Graphed {
        // No scope yet: every source of events is one site's.
        scope: String::new(),
        received,
        links: links
            .into_iter()
            .map(|((src, link, dst, _), count)| LinkSeen {
                src,
                link: link.to_owned(),
                dst,
                events: count.events,
                first: count.first,
                last: count.last,
            })
            .collect(),
        claims: claims
            .into_iter()
            .map(|((one, other, rule, _), count)| ClaimSeen {
                one,
                other,
                rule: rule.to_owned(),
                events: count.events,
                first: count.first,
                last: count.last,
            })
            .collect(),
    };
    Ok((graphed, tally))
}

/// Reads the links and claims of every event, and sends each batch's on,
/// acknowledging events only once theirs are sent.
///
/// It reads as an observer, so it never slows the writer. If it falls
/// further behind than the topic keeps, it is moved past the events
/// between, which is counted and logged: they are stored, and their links
/// are not in the graph.
pub(crate) async fn derive(
    mut events: impl Receiver + Sync,
    graph: impl Sender + Sync,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut lag = Lag::new("normalized".to_owned(), "graph");
    while !*stop.borrow_and_update() {
        lag.report(&events, &metrics).await;
        let deliveries = events.receive(BATCH, POLL).await?;
        let skipped = events.skipped();
        if skipped > 0 {
            warn!(
                skipped,
                "the graph role fell behind what the topic keeps, and was moved past events whose links it did not read"
            );
            metrics.graph_skipped(skipped);
        }
        let Some(last) = deliveries.last().map(|delivery| delivery.offset) else {
            continue;
        };
        let (graphed, tally) =
            tokio::task::spawn_blocking(move || gather(&deliveries, crate::raw::now()))
                .await
                .map_err(|error| RunError::Role(format!("reading the graph: {error}")))??;
        metrics.graphed(&tally, graphed.links.len(), graphed.claims.len());
        if !graphed.links.is_empty() || !graphed.claims.is_empty() {
            let encoded = serde_json::to_vec(&graphed)
                .map_err(|error| RunError::Role(format!("encoding the graph: {error}")))?;
            graph.send(vec![encoded]).await?;
        }
        events.acknowledge(last).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use goliath_normalize::{EventId, Normalized};
    use serde_json::json;

    use super::*;

    fn delivery(offset: u64, raw: &str, received: i64, event: serde_json::Value) -> Delivery {
        let normalized = Normalized::new(EventId::of("test", raw.as_bytes()), event, "kind");
        Delivery {
            offset,
            payload: Envelope::new("test", 1, Outcome::Event(normalized))
                .received_at(received)
                .encode(),
        }
    }

    fn sign_in(minute: i64) -> serde_json::Value {
        json!({
            "class_uid": 3002, "category_uid": 3, "activity_id": 1,
            // 2026-09-25T10:00:00Z, and minutes after it.
            "time": 1_790_330_400_000_i64 + minute * 60_000,
            "user": { "name": "adam", "domain": "CORP", "uid": "S-1-5-21-1-2-3-1104" },
            "device": { "hostname": "dc-1.corp.example" },
        })
    }

    #[test]
    fn what_repeats_within_an_hour_is_one_row_with_its_first_and_last_event() {
        let received = 1_790_340_000_000;
        let deliveries = [
            delivery(0, "b", received, sign_in(20)),
            delivery(1, "a", received, sign_in(5)),
            delivery(2, "c", received + 1, sign_in(50)),
            // The next hour is another row of the link, and the same day's
            // claim.
            delivery(3, "d", received + 2, sign_in(70)),
        ];
        let (graphed, tally) = gather(&deliveries, 0).unwrap();
        assert_eq!(
            tally,
            Tally {
                events: 4,
                links: 4,
                claims: 4
            }
        );
        assert_eq!(graphed.received, received + 2);
        let counts: Vec<(u64, i64, i64)> = graphed
            .links
            .iter()
            .map(|link| (link.events, link.first.time, link.last.time))
            .collect();
        let at = |minute: i64| 1_790_330_400_000 + minute * 60_000;
        assert_eq!(counts, [(3, at(5), at(50)), (1, at(70), at(70))]);
        assert_eq!(graphed.links[0].src, "user:sid:s-1-5-21-1-2-3-1104");
        assert_eq!(graphed.links[0].link, "logged_on_to");
        assert_eq!(graphed.links[0].dst, "host:name:dc-1.corp.example");
        // The first event is the earliest by its time, not by its arrival.
        assert_eq!(
            graphed.links[0].first.id,
            *EventId::of("test", b"a").as_bytes()
        );
        assert_eq!(graphed.claims.len(), 1);
        assert_eq!(
            (graphed.claims[0].events, graphed.claims[0].rule.as_str()),
            (4, "user")
        );
        assert_eq!(graphed.claims[0].other, "user:name:corp\\adam");
    }

    #[test]
    fn an_event_with_no_time_of_its_own_is_under_when_it_was_taken() {
        let mut event = sign_in(0);
        event.as_object_mut().unwrap().remove("time");
        let received = 1_790_340_000_000;
        let (graphed, _) = gather(&[delivery(0, "a", received, event)], 0).unwrap();
        assert_eq!(graphed.links[0].first.time, received);
        // An event that shows nothing gives no row, and is counted.
        let (graphed, tally) = gather(
            &[delivery(0, "a", received, json!({ "class_uid": 1007 }))],
            0,
        )
        .unwrap();
        assert!(graphed.links.is_empty() && graphed.claims.is_empty());
        assert_eq!(tally.events, 1);
        assert!(
            gather(
                &[Delivery {
                    offset: 0,
                    payload: b"not an envelope".to_vec()
                }],
                0
            )
            .is_err()
        );
    }
}
