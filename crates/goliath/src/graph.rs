//! The `graph` role: reads every normalized event beside the writer, and
//! sends on what the events show of the things they name, links and claims
//! added up, for the writer to keep.
//!
//! See `docs/adr/0025-entity-graph.md`. Nothing here decides which
//! identifiers are one entity: the rows are under the identifiers the
//! events gave.

use std::collections::BTreeMap;
use std::path::PathBuf;

use goliath_graph::{Decisions, Evidence, Said, Summary, observe, resolve};
use goliath_normalize::{Envelope, Outcome};
use goliath_pipe::{Delivery, Receiver, Sender};
use goliath_search::Cursor;
use goliath_store::{ClaimSeen, Claimed, Graphed, LinkSeen, Placed, Resolving, Standing, Store};
use tokio::sync::watch;
use tracing::warn;

use crate::RunError;
use crate::config::GraphConfig;
use crate::health::Health;
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

/// What people decided about identity, read from `files` as they are now.
///
/// # Errors
///
/// Returns [`RunError::Config`] naming the file that cannot be read or
/// used.
fn decisions(files: &[PathBuf]) -> Result<(Said, String), RunError> {
    let mut read = Vec::with_capacity(files.len());
    for file in files {
        let refuse = |why: String| RunError::Config(format!("{}: {why}", file.display()));
        let text = std::fs::read_to_string(file).map_err(|error| refuse(error.to_string()))?;
        read.push(Decisions::from_yaml(&text).map_err(|error| refuse(error.to_string()))?);
    }
    let named: Vec<String> = read
        .iter()
        .map(|file| format!("{} {}", file.name, file.version))
        .collect();
    let said = Said::new(&read).map_err(|error| RunError::Config(error.to_string()))?;
    Ok((said, named.join(", ")))
}

/// Decides which identifiers are one entity, scope by scope, from `claimed`
/// and from what people `said`. A claim that names what is not an
/// identifier is passed over and counted.
fn resolve_claims(
    claimed: &[Claimed],
    said: &Said,
    shared_over: usize,
) -> (Vec<Placed>, Summary, u64) {
    let mut by_scope: BTreeMap<&str, Vec<Evidence>> = BTreeMap::new();
    let mut unread = 0;
    for claim in claimed {
        let (Ok(one), Ok(other)) = (claim.one.parse(), claim.other.parse()) else {
            unread += 1;
            continue;
        };
        by_scope.entry(&claim.scope).or_default().push(Evidence {
            one,
            other,
            rule: claim.rule.clone(),
            events: claim.events,
            first_seen: claim.first_seen,
            last_seen: claim.last_seen,
        });
    }
    let mut placed = Vec::new();
    let mut summary = Summary::default();
    for (scope, evidence) in by_scope {
        let resolution = resolve(&evidence, said, shared_over);
        summary.entities += resolution.summary.entities;
        summary.members += resolution.summary.members;
        summary.aliases += resolution.summary.aliases;
        summary.shared += resolution.summary.shared;
        summary.held_apart += resolution.summary.held_apart;
        placed.extend(resolution.resolved.into_iter().map(|resolved| {
            Placed {
                scope: scope.to_owned(),
                identifier: resolved.identifier.to_string(),
                entity: resolved.entity.to_string(),
                standing: resolved.standing.as_str().to_owned(),
                via: resolved
                    .with
                    .map(|with| with.to_string())
                    .unwrap_or_default(),
                rule: resolved.rule,
                said: resolved.by.unwrap_or_default(),
                events: resolved.events,
                first_seen: resolved.first_seen,
                last_seen: resolved.last_seen,
            }
        }));
    }
    (placed, summary, unread)
}

/// One run: reads the decisions and the claims, decides, and writes the
/// mapping as a new version.
async fn resolve_once(store: &Store, settings: &GraphConfig) -> Result<Resolving, RunError> {
    let (said, named) = decisions(&settings.decisions)?;
    let version = u64::try_from(crate::raw::now()).unwrap_or(0);
    let claimed = store.claimed().await?;
    let claims = claimed.len() as u64;
    let shared_over = settings.shared_over();
    let (placed, summary, unread) =
        tokio::task::spawn_blocking(move || resolve_claims(&claimed, &said, shared_over))
            .await
            .map_err(|error| RunError::Role(format!("resolving: {error}")))?;
    if unread > 0 {
        warn!(
            unread,
            "claims that name what is not an identifier were passed over"
        );
    }
    let run = Resolving {
        version,
        finished: crate::raw::now(),
        claims,
        entities: summary.entities,
        members: summary.members,
        aliases: summary.aliases,
        shared: summary.shared,
        held_apart: summary.held_apart,
        decisions: named,
    };
    store.write_resolution(&run, &placed).await?;
    Ok(run)
}

/// Resolves identifiers into entities at the start and then on the
/// schedule of `settings`, and says how that goes as the condition
/// `resolving`.
///
/// A run that fails changes nothing: readers keep the last mapping, and
/// the next run tries again. A decisions file that cannot be used fails
/// the run, so that a mistake in it is seen and not half applied.
pub(crate) async fn resolve_on_schedule(
    store: Store,
    settings: GraphConfig,
    (metrics, health): (Metrics, Health),
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let every = settings.resolve_every();
    while !*stop.borrow_and_update() {
        match resolve_once(&store, &settings).await {
            Ok(run) => {
                metrics.resolved(&run);
                health.set(
                    "graph",
                    "resolving",
                    Standing::Ok,
                    "resolved",
                    format!(
                        "{} claims gave {} entities of more than one identifier, with {} members \
                         and {} aliases; {} identifiers are shared, and {} claims are held apart \
                         by a person's word.",
                        run.claims,
                        run.entities,
                        run.members,
                        run.aliases,
                        run.shared,
                        run.held_apart
                    ),
                );
            }
            Err(error) => {
                warn!(%error, "identifiers were not resolved; the last mapping stands");
                let (reason, what) = match &error {
                    RunError::Config(_) => (
                        "decisions_refused",
                        "A decisions file cannot be used, so nothing was resolved and the last \
                         mapping stands",
                    ),
                    _ => (
                        "store_refused",
                        "The store did not answer, so nothing was resolved and the last mapping \
                         stands",
                    ),
                };
                health.set(
                    "graph",
                    "resolving",
                    Standing::Failing,
                    reason,
                    format!("{what}: {error}"),
                );
            }
        }
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            _ = stop.changed() => {}
        }
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

    fn claimed(scope: &str, one: &str, other: &str) -> Claimed {
        Claimed {
            scope: scope.to_owned(),
            one: one.to_owned(),
            other: other.to_owned(),
            rule: "user".to_owned(),
            events: 3,
            first_seen: 10,
            last_seen: 20,
        }
    }

    #[test]
    fn claims_are_resolved_scope_by_scope_and_what_is_no_identifier_is_passed_over() {
        let sid = "user:sid:s-1-5-21-1-2-3-1104";
        let name = "user:name:corp\\adam";
        let other = "user:name:corp.example\\adam";
        let (placed, summary, unread) = resolve_claims(
            &[
                claimed("", sid, name),
                // The same pair of another scope is another entity, and a
                // claim of another scope does not reach this one.
                claimed("branch", sid, other),
                claimed("", "nonsense", name),
            ],
            &Said::default(),
            3,
        );
        assert_eq!(unread, 1);
        assert_eq!((summary.entities, summary.members), (2, 4));
        let rows: Vec<(&str, &str, &str, &str)> = placed
            .iter()
            .map(|row| {
                (
                    row.scope.as_str(),
                    row.identifier.as_str(),
                    row.standing.as_str(),
                    row.via.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("", sid, "member", ""),
                ("", name, "member", sid),
                ("branch", sid, "member", ""),
                ("branch", other, "member", sid),
            ]
        );
        assert_eq!((placed[1].events, placed[1].rule.as_str()), (3, "user"));
    }

    #[test]
    fn a_decisions_file_that_cannot_be_used_names_itself() {
        let directory = tempfile::tempdir().unwrap();
        let good = directory.path().join("identity.yaml");
        std::fs::write(
            &good,
            "name: identity\nversion: 4\ndecisions:\n  - same: ['user:email:a@x.example', 'user:email:b@x.example']\n    reason: Renamed\n",
        )
        .unwrap();
        let (_, named) = decisions(std::slice::from_ref(&good)).unwrap();
        assert_eq!(named, "identity 4");
        assert_eq!(decisions(&[]).unwrap().1, "");

        let bad = directory.path().join("bad.yaml");
        std::fs::write(
            &bad,
            "name: bad\nversion: 1\ndecisions:\n  - reason: none\n",
        )
        .unwrap();
        let error = decisions(&[good, bad]).unwrap_err().to_string();
        assert!(error.contains("decision 1 of `bad`"), "{error}");
        let missing = directory.path().join("missing.yaml");
        let error = decisions(std::slice::from_ref(&missing))
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing.yaml"), "{error}");
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
