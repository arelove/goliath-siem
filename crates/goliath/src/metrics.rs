//! What each role does, counted, for Prometheus.
//!
//! Every role in a process shares one registry, served as `OpenMetrics` text
//! at `/metrics` on the address `[metrics]` names. The endpoint takes no
//! token: it holds counts and durations, never an event's content, and is
//! meant for a network only the monitoring system reaches.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

use crate::RunError;
use crate::health::Health;

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Source {
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Outcome {
    source: String,
    outcome: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct DeadLetter {
    source: String,
    stage: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Reader {
    topic: String,
    reader: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Answer {
    answer: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Request {
    source: String,
    answer: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Feed {
    feed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct FeedRefresh {
    feed: String,
    result: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Context {
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct ContextRefresh {
    source: String,
    result: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct Hit {
    status: &'static str,
}

/// What the graph role counts: links, or claims.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
struct GraphSeen {
    kind: &'static str,
}

/// The metrics of one process, cheap to clone.
#[derive(Clone)]
pub(crate) struct Metrics(Arc<Inner>);

struct Inner {
    registry: Registry,
    /// What the process says of itself, which some measures are part of.
    health: Health,
    collected_files: Family<Source, Counter>,
    collected_bytes: Family<Source, Counter>,
    rejected_files: Family<Source, Counter>,
    normalized_records: Family<Source, Counter>,
    outcomes: Family<Outcome, Counter>,
    dead_letters: Family<DeadLetter, Counter>,
    stored: Counter,
    lag: Family<Reader, Gauge>,
    detected_events: Counter,
    detected_observables: Counter,
    detector_skipped: Counter,
    graph_events: Counter,
    graph_seen: Family<GraphSeen, Counter>,
    graph_rows: Family<GraphSeen, Counter>,
    graph_skipped: Counter,
    graph_read_back: Counter,
    graph_unread_ranges: Gauge,
    graph_resolved: Family<GraphSeen, Gauge>,
    graph_resolution_timestamp_seconds: Gauge,
    detector_rematched: Counter,
    detector_unmatched_ranges: Gauge,
    detector_look_back_remaining_seconds: Gauge,
    indicator_hits: Family<Hit, Counter>,
    feed_refreshes: Family<FeedRefresh, Counter>,
    feed_indicators: Family<Feed, Gauge>,
    feed_published_timestamp_seconds: Family<Feed, Gauge>,
    feed_checked_timestamp_seconds: Family<Feed, Gauge>,
    context_refreshes: Family<ContextRefresh, Counter>,
    context_records: Family<Context, Gauge>,
    context_written_timestamp_seconds: Family<Context, Gauge>,
    finding_enrichments: Counter,
    receipt_to_stored_seconds: Histogram,
    flush_seconds: Histogram,
    searches: Family<Answer, Counter>,
    search_seconds: Histogram,
    received_requests: Family<Request, Counter>,
    received_bytes: Family<Source, Counter>,
    receive_wait_seconds: Histogram,
}

/// How the receiver answered a request, as the `answer` label counts it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Received {
    /// The batch is in the raw topic.
    Taken,
    /// The token was missing or wrong.
    Unauthorized,
    /// The body was empty, too large, or badly encoded.
    Refused,
    /// The topic stayed full; the sender was asked to come back.
    Busy,
    /// The pipe failed.
    Failed,
}

/// How a search was answered, as the `answer` label counts it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Searched {
    /// Answered with events.
    Found,
    /// Refused as invalid or over its limits.
    Refused,
    /// The store failed.
    Failed,
}

impl Metrics {
    #[allow(
        clippy::too_many_lines,
        reason = "one registration per metric, in one place"
    )]
    pub(crate) fn new() -> Self {
        let mut registry = Registry::with_prefix("goliath");
        let collected_files = Family::default();
        let collected_bytes = Family::default();
        let rejected_files = Family::default();
        let normalized_records = Family::default();
        let outcomes = Family::default();
        let dead_letters = Family::default();
        let stored = Counter::default();
        let lag = Family::default();
        let detected_events = Counter::default();
        let detected_observables = Counter::default();
        let detector_skipped = Counter::default();
        let graph_events = Counter::default();
        let graph_seen = Family::default();
        let graph_rows = Family::default();
        let graph_skipped = Counter::default();
        let graph_read_back = Counter::default();
        let graph_unread_ranges = Gauge::default();
        let graph_resolved = Family::default();
        let graph_resolution_timestamp_seconds = Gauge::default();
        let detector_rematched = Counter::default();
        let detector_unmatched_ranges = Gauge::default();
        let detector_look_back_remaining_seconds = Gauge::default();
        let indicator_hits = Family::default();
        let feed_refreshes = Family::default();
        let feed_indicators = Family::default();
        let feed_published_timestamp_seconds = Family::default();
        let feed_checked_timestamp_seconds = Family::default();
        let context_refreshes = Family::default();
        let context_records = Family::default();
        let context_written_timestamp_seconds = Family::default();
        let finding_enrichments = Counter::default();
        // From 10 milliseconds to about five minutes.
        let receipt_to_stored_seconds = Histogram::new(exponential_buckets(0.01, 2.0, 15));
        // From a millisecond to about 30 seconds.
        let flush_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 16));
        let searches = Family::default();
        let search_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 16));
        let received_requests = Family::default();
        let received_bytes = Family::default();
        let receive_wait_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 15));
        registry.register(
            "received_requests",
            "Requests the receiver answered, by source and how",
            received_requests.clone(),
        );
        registry.register(
            "received_bytes",
            "Bytes of the batches the receiver took into a raw topic",
            received_bytes.clone(),
        );
        registry.register(
            "receive_wait_seconds",
            "Time a request waited for its raw topic to take its batch",
            receive_wait_seconds.clone(),
        );
        registry.register(
            "collected_files",
            "Files the collector sent to a source's raw topic",
            collected_files.clone(),
        );
        registry.register(
            "collected_bytes",
            "Bytes of the files the collector sent",
            collected_bytes.clone(),
        );
        registry.register(
            "rejected_files",
            "Files the collector set aside as too large to send",
            rejected_files.clone(),
        );
        registry.register(
            "normalized_records",
            "Raw records the normalizer read",
            normalized_records.clone(),
        );
        registry.register(
            "outcomes",
            "What normalization made of records: events and dead letters",
            outcomes.clone(),
        );
        registry.register(
            "dead_letters",
            "Records that could not become events, by the stage that refused them",
            dead_letters.clone(),
        );
        registry.register(
            "stored_outcomes",
            "Outcomes the writer stored and acknowledged",
            stored.clone(),
        );
        registry.register(
            "reader_lag_records",
            "Records in a topic its reader has not acknowledged, sampled once a second",
            lag.clone(),
        );
        registry.register(
            "receipt_to_stored_seconds",
            "Time from the platform taking a record to its outcome being stored",
            receipt_to_stored_seconds.clone(),
        );
        registry.register(
            "store_flush_seconds",
            "Time to write one batch to the event store",
            flush_seconds.clone(),
        );
        registry.register(
            "detected_events",
            "Events the detector looked at",
            detected_events.clone(),
        );
        registry.register(
            "detected_observables",
            "Observables the detector looked up among the indicators",
            detected_observables.clone(),
        );
        registry.register(
            "detector_skipped_records",
            "Events stored but not matched as they arrived: the detector fell behind what the topic keeps",
            detector_skipped.clone(),
        );
        registry.register(
            "graph_events",
            "Events the graph role read",
            graph_events.clone(),
        );
        registry.register(
            "graph_seen",
            "Links and claims the events showed, each event's counted",
            graph_seen.clone(),
        );
        registry.register(
            "graph_rows",
            "Rows of links and claims sent to the writer, after adding up what repeats",
            graph_rows.clone(),
        );
        registry.register(
            "graph_read_back_events",
            "Events read back from the store into the graph: stored before the graph role ran, or while it was behind",
            graph_read_back.clone(),
        );
        registry.register(
            "graph_unread_ranges",
            "Ranges of receipt time whose events are stored and wait to be read into the graph",
            graph_unread_ranges.clone(),
        );
        registry.register(
            "graph_resolved",
            "What the last resolution found: entities of more than one identifier, their members, aliases, identifiers set aside as shared, and claims held apart by a person's word",
            graph_resolved.clone(),
        );
        registry.register(
            "graph_resolution_timestamp_seconds",
            "When identifiers were last resolved into entities",
            graph_resolution_timestamp_seconds.clone(),
        );
        registry.register(
            "graph_skipped_records",
            "Events stored whose links were not read: the graph role fell behind what the topic keeps",
            graph_skipped.clone(),
        );
        registry.register(
            "detector_rematched_events",
            "Events read back from the store and matched: what the detector had been moved past",
            detector_rematched.clone(),
        );
        registry.register(
            "detector_unmatched_ranges",
            "Ranges of receipt time whose events are stored and wait to be matched from the store",
            detector_unmatched_ranges.clone(),
        );
        registry.register(
            "detector_look_back_remaining_seconds",
            "Receipt time a look back for late indicators has yet to read from the store; zero when none runs",
            detector_look_back_remaining_seconds.clone(),
        );
        registry.register(
            "indicator_hits",
            "Observables an indicator names, reported or suppressed by an allowlist",
            indicator_hits.clone(),
        );
        registry.register(
            "feed_refreshes",
            "Publications of a feed asked for, by result: loaded, unchanged since it was loaded before a restart, refused as not the feed, or failed to be fetched",
            feed_refreshes.clone(),
        );
        registry.register(
            "context_refreshes",
            "Exports of a source of context looked at after a change, by result: loaded, or refused as not what its definition describes",
            context_refreshes.clone(),
        );
        registry.register(
            "context_records",
            "Records a source of context holds, as last loaded",
            context_records.clone(),
        );
        registry.register(
            "context_written_timestamp_seconds",
            "When the export of a source of context last loaded was written",
            context_written_timestamp_seconds.clone(),
        );
        registry.register(
            "finding_enrichments",
            "Entries of context added to findings",
            finding_enrichments.clone(),
        );
        registry.register(
            "feed_indicators",
            "Indicators a feed asserts, as last loaded",
            feed_indicators.clone(),
        );
        registry.register(
            "feed_published_timestamp_seconds",
            "When the publication of a feed last loaded was written",
            feed_published_timestamp_seconds.clone(),
        );
        registry.register(
            "feed_checked_timestamp_seconds",
            "When a feed was last known to be current: its publication loaded, or found unchanged. A feed is stale when this stops moving",
            feed_checked_timestamp_seconds.clone(),
        );
        registry.register(
            "searches",
            "Searches the API answered, by how",
            searches.clone(),
        );
        registry.register(
            "search_seconds",
            "Time to answer one search",
            search_seconds.clone(),
        );
        Self(Arc::new(Inner {
            registry,
            health: Health::default(),
            collected_files,
            collected_bytes,
            rejected_files,
            normalized_records,
            outcomes,
            dead_letters,
            stored,
            lag,
            detected_events,
            detected_observables,
            detector_skipped,
            graph_events,
            graph_seen,
            graph_rows,
            graph_skipped,
            graph_read_back,
            graph_unread_ranges,
            graph_resolved,
            graph_resolution_timestamp_seconds,
            detector_rematched,
            detector_unmatched_ranges,
            detector_look_back_remaining_seconds,
            indicator_hits,
            feed_refreshes,
            feed_indicators,
            feed_published_timestamp_seconds,
            feed_checked_timestamp_seconds,
            context_refreshes,
            context_records,
            context_written_timestamp_seconds,
            finding_enrichments,
            receipt_to_stored_seconds,
            flush_seconds,
            searches,
            search_seconds,
            received_requests,
            received_bytes,
            receive_wait_seconds,
        }))
    }

    pub(crate) fn received(&self, source: &str, answer: Received, bytes: usize) {
        let answer = match answer {
            Received::Taken => "taken",
            Received::Unauthorized => "unauthorized",
            Received::Refused => "refused",
            Received::Busy => "busy",
            Received::Failed => "failed",
        };
        self.0
            .received_requests
            .get_or_create(&Request {
                source: source.to_owned(),
                answer,
            })
            .inc();
        if bytes > 0 {
            self.0
                .received_bytes
                .get_or_create(&Source {
                    source: source.to_owned(),
                })
                .inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
        }
    }

    pub(crate) fn waited(&self, took: Duration) {
        self.0.receive_wait_seconds.observe(took.as_secs_f64());
    }

    pub(crate) fn collected(&self, source: &str, bytes: u64) {
        let label = Source {
            source: source.to_owned(),
        };
        self.0.collected_files.get_or_create(&label).inc();
        self.0.collected_bytes.get_or_create(&label).inc_by(bytes);
    }

    pub(crate) fn rejected(&self, source: &str) {
        self.0
            .rejected_files
            .get_or_create(&Source {
                source: source.to_owned(),
            })
            .inc();
    }

    pub(crate) fn normalized(&self, source: &str, records: usize) {
        self.0
            .normalized_records
            .get_or_create(&Source {
                source: source.to_owned(),
            })
            .inc_by(records as u64);
    }

    pub(crate) fn events(&self, source: &str, count: u64) {
        self.0.health.outcomes(source, count, 0);
        self.0
            .outcomes
            .get_or_create(&Outcome {
                source: source.to_owned(),
                outcome: "event",
            })
            .inc_by(count);
    }

    pub(crate) fn dead_letters(&self, source: &str, stage: &'static str, count: u64) {
        self.0.health.outcomes(source, 0, count);
        self.0
            .outcomes
            .get_or_create(&Outcome {
                source: source.to_owned(),
                outcome: "dead_letter",
            })
            .inc_by(count);
        self.0
            .dead_letters
            .get_or_create(&DeadLetter {
                source: source.to_owned(),
                stage,
            })
            .inc_by(count);
    }

    /// Outcomes stored at `now`, each with when its record was taken, if
    /// its envelope said; in milliseconds since the Unix epoch.
    pub(crate) fn stored(&self, received: &[Option<i64>], now: i64) {
        self.0.stored.inc_by(received.len() as u64);
        for taken in received.iter().flatten() {
            #[allow(clippy::cast_precision_loss)]
            let seconds = (now - taken).max(0) as f64 / 1000.0;
            self.0.receipt_to_stored_seconds.observe(seconds);
        }
    }

    /// What the process says of itself.
    pub(crate) fn health(&self) -> &Health {
        &self.0.health
    }

    /// How many records of `topic` its reader `reader` has not acknowledged.
    pub(crate) fn lag(&self, topic: &str, reader: &'static str, records: u64) {
        self.0.health.backlog(topic, reader, records);
        self.0
            .lag
            .get_or_create(&Reader {
                topic: topic.to_owned(),
                reader,
            })
            .set(i64::try_from(records).unwrap_or(i64::MAX));
    }

    /// What the detector found in a batch.
    pub(crate) fn detected(&self, tally: &crate::detector::Tally) {
        self.0.detected_events.inc_by(tally.events);
        self.0.finding_enrichments.inc_by(tally.enrichments);
        self.0.detected_observables.inc_by(tally.observables);
        for (status, count) in [
            ("reported", tally.hits - tally.suppressed),
            ("suppressed", tally.suppressed),
        ] {
            if count > 0 {
                self.0
                    .indicator_hits
                    .get_or_create(&Hit { status })
                    .inc_by(count);
            }
        }
    }

    /// The detector was moved past `records` it did not match.
    pub(crate) fn detector_skipped(&self, records: u64) {
        self.0.detector_skipped.inc_by(records);
    }

    /// What the graph role read in a batch, and the rows of links and of
    /// claims it sent for it.
    pub(crate) fn graphed(&self, tally: &crate::graph::Tally, links: usize, claims: usize) {
        self.0.graph_events.inc_by(tally.events);
        for (kind, seen, rows) in [
            ("link", tally.links, links),
            ("claim", tally.claims, claims),
        ] {
            self.0
                .graph_seen
                .get_or_create(&GraphSeen { kind })
                .inc_by(seen);
            self.0
                .graph_rows
                .get_or_create(&GraphSeen { kind })
                .inc_by(rows as u64);
        }
    }

    /// The graph role read `events` back from the store.
    pub(crate) fn graph_read_back(&self, events: u64) {
        self.0.graph_read_back.inc_by(events);
    }

    /// `ranges` of receipt time wait to be read into the graph.
    pub(crate) fn graph_unread_ranges(&self, ranges: usize) {
        self.0
            .graph_unread_ranges
            .set(i64::try_from(ranges).unwrap_or(i64::MAX));
    }

    /// What a run of resolution found.
    pub(crate) fn resolved(&self, run: &goliath_store::Resolving) {
        for (kind, count) in [
            ("entity", run.entities),
            ("member", run.members),
            ("alias", run.aliases),
            ("shared", run.shared),
            ("held_apart", run.held_apart),
        ] {
            self.0
                .graph_resolved
                .get_or_create(&GraphSeen { kind })
                .set(i64::try_from(count).unwrap_or(i64::MAX));
        }
        self.0
            .graph_resolution_timestamp_seconds
            .set(run.finished / 1000);
    }

    /// The graph role was moved past `records` it had not read.
    pub(crate) fn graph_skipped(&self, records: u64) {
        self.0.graph_skipped.inc_by(records);
    }

    /// The detector matched `events` read back from the store.
    pub(crate) fn rematched(&self, events: u64) {
        self.0.detector_rematched.inc_by(events);
    }

    /// `ranges` of receipt time wait to be matched from the store.
    pub(crate) fn unmatched_ranges(&self, ranges: usize) {
        self.0
            .detector_unmatched_ranges
            .set(i64::try_from(ranges).unwrap_or(i64::MAX));
    }

    /// A look back has `seconds` of receipt time yet to read.
    pub(crate) fn look_back_remaining(&self, seconds: i64) {
        self.0.detector_look_back_remaining_seconds.set(seconds);
    }

    /// `feed` is known to be current at `at`, in seconds since the epoch.
    pub(crate) fn feed_checked(&self, feed: &str, at: i64) {
        self.0.health.feed_checked(feed, at);
        self.0
            .feed_checked_timestamp_seconds
            .get_or_create(&Feed {
                feed: feed.to_owned(),
            })
            .set(at);
    }

    /// A publication of `feed` was asked for, with `result`: `loaded`, or
    /// `unchanged` since it was loaded before a restart, with so many
    /// indicators and written at that time, in seconds since the epoch;
    /// `refused`; or `failed`.
    /// The export of `source` was looked at after it changed, with
    /// `result`: `loaded`, with so many records and written at that time, in
    /// seconds since the epoch; or `refused`.
    pub(crate) fn context_refreshed(
        &self,
        source: &str,
        result: &'static str,
        now: Option<(usize, i64)>,
    ) {
        self.0
            .context_refreshes
            .get_or_create(&ContextRefresh {
                source: source.to_owned(),
                result,
            })
            .inc();
        if let Some((records, written)) = now {
            let source = Context {
                source: source.to_owned(),
            };
            self.0
                .context_records
                .get_or_create(&source)
                .set(i64::try_from(records).unwrap_or(i64::MAX));
            self.0
                .context_written_timestamp_seconds
                .get_or_create(&source)
                .set(written);
        }
    }

    pub(crate) fn feed_refreshed(
        &self,
        feed: &str,
        result: &'static str,
        now: Option<(usize, i64)>,
    ) {
        if now.is_some() {
            self.0.health.feed_held(feed);
        }
        self.0
            .feed_refreshes
            .get_or_create(&FeedRefresh {
                feed: feed.to_owned(),
                result,
            })
            .inc();
        if let Some((indicators, published)) = now {
            let feed = Feed {
                feed: feed.to_owned(),
            };
            self.0
                .feed_indicators
                .get_or_create(&feed)
                .set(i64::try_from(indicators).unwrap_or(i64::MAX));
            self.0
                .feed_published_timestamp_seconds
                .get_or_create(&feed)
                .set(published);
        }
    }

    pub(crate) fn flushed(&self, took: Duration) {
        self.0.flush_seconds.observe(took.as_secs_f64());
    }

    pub(crate) fn searched(&self, answer: Searched, took: Duration) {
        let answer = match answer {
            Searched::Found => "found",
            Searched::Refused => "refused",
            Searched::Failed => "failed",
        };
        self.0.searches.get_or_create(&Answer { answer }).inc();
        self.0.search_seconds.observe(took.as_secs_f64());
    }

    /// Everything counted so far, as `OpenMetrics` text.
    pub(crate) fn encode(&self) -> String {
        let mut text = String::new();
        // Writing to a String cannot fail.
        let _ = prometheus_client::encoding::text::encode(&mut text, &self.0.registry);
        text
    }
}

/// Serves `/metrics` and the probes of `health` on `listen` until `stop`
/// turns true.
pub(crate) async fn serve(
    listen: SocketAddr,
    metrics: Metrics,
    health: Health,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| RunError::Io(format!("metrics on {listen}: {error}")))?;
    info!(address = %listen, "metrics listening");
    let app = health.probes().route(
        "/metrics",
        get(move || {
            let text = metrics.encode();
            std::future::ready(
                (
                    [(
                        header::CONTENT_TYPE,
                        "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    )],
                    text,
                )
                    .into_response(),
            )
        }),
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = stop.wait_for(|stopping| *stopping).await;
        })
        .await
        .map_err(|error| RunError::Io(format!("metrics: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_appear_in_the_text_with_their_labels() {
        let metrics = Metrics::new();
        metrics.collected("sysmon", 6_632);
        metrics.normalized("sysmon", 1);
        metrics.events("sysmon", 1);
        metrics.dead_letters("sysmon", "decoding", 1);
        metrics.stored(&[Some(1_000), None], 1_250);
        metrics.lag("normalized", "writer", 42);
        metrics.searched(Searched::Found, Duration::from_millis(38));
        let text = metrics.encode();
        for expected in [
            r#"goliath_collected_bytes_total{source="sysmon"} 6632"#,
            r#"goliath_outcomes_total{source="sysmon",outcome="dead_letter"} 1"#,
            r#"goliath_dead_letters_total{source="sysmon",stage="decoding"} 1"#,
            "goliath_stored_outcomes_total 2",
            "goliath_receipt_to_stored_seconds_count 1",
            r#"goliath_reader_lag_records{topic="normalized",reader="writer"} 42"#,
            "goliath_receipt_to_stored_seconds_sum 0.25",
            r#"goliath_searches_total{answer="found"} 1"#,
            "goliath_search_seconds_count 1",
        ] {
            assert!(text.contains(expected), "{expected} missing from\n{text}");
        }
        assert!(text.ends_with("# EOF\n"));
    }
}
