//! What each role does, counted, for Prometheus.
//!
//! Every role in a process shares one registry, served as `OpenMetrics` text
//! at `/metrics` on the address `[metrics]` names. The endpoint takes no
//! token: it holds counts and durations, never an event's content, and is
//! meant for a network only the monitoring system reaches.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
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

/// The metrics of one process, cheap to clone.
#[derive(Clone)]
pub(crate) struct Metrics(Arc<Inner>);

struct Inner {
    registry: Registry,
    collected_files: Family<Source, Counter>,
    collected_bytes: Family<Source, Counter>,
    rejected_files: Family<Source, Counter>,
    normalized_records: Family<Source, Counter>,
    outcomes: Family<Outcome, Counter>,
    dead_letters: Family<DeadLetter, Counter>,
    stored: Counter,
    lag: Family<Reader, Gauge>,
    receipt_to_stored_seconds: Histogram,
    flush_seconds: Histogram,
    searches: Family<Answer, Counter>,
    search_seconds: Histogram,
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
        // From 10 milliseconds to about five minutes.
        let receipt_to_stored_seconds = Histogram::new(exponential_buckets(0.01, 2.0, 15));
        // From a millisecond to about 30 seconds.
        let flush_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 16));
        let searches = Family::default();
        let search_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 16));
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
            collected_files,
            collected_bytes,
            rejected_files,
            normalized_records,
            outcomes,
            dead_letters,
            stored,
            lag,
            receipt_to_stored_seconds,
            flush_seconds,
            searches,
            search_seconds,
        }))
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

    pub(crate) fn event(&self, source: &str) {
        self.0
            .outcomes
            .get_or_create(&Outcome {
                source: source.to_owned(),
                outcome: "event",
            })
            .inc();
    }

    pub(crate) fn dead_letter(&self, source: &str, stage: &'static str) {
        self.0
            .outcomes
            .get_or_create(&Outcome {
                source: source.to_owned(),
                outcome: "dead_letter",
            })
            .inc();
        self.0
            .dead_letters
            .get_or_create(&DeadLetter {
                source: source.to_owned(),
                stage,
            })
            .inc();
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

    /// How many records of `topic` its reader `reader` has not acknowledged.
    pub(crate) fn lag(&self, topic: &str, reader: &'static str, records: u64) {
        self.0
            .lag
            .get_or_create(&Reader {
                topic: topic.to_owned(),
                reader,
            })
            .set(i64::try_from(records).unwrap_or(i64::MAX));
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

/// Serves `/metrics` on `listen` until `stop` turns true.
pub(crate) async fn serve(
    listen: SocketAddr,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| RunError::Io(format!("metrics on {listen}: {error}")))?;
    info!(address = %listen, "metrics listening");
    let app = Router::new().route(
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
        metrics.event("sysmon");
        metrics.dead_letter("sysmon", "decoding");
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
