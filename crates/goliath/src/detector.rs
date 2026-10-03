//! The detector: reads normalized events beside the writer, looks their
//! observables up among the indicators, and sends each hit on as a finding
//! for the writer to store. See `docs/adr/0021-enrichment-placement.md`.
//!
//! It never rewrites an event, and the writer does not read what it reads
//! through it: the two are separate groups of one topic.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use goliath_intel::{Allowlist, Allowlists, Feed, Matcher, RocksStore, finding, observables};
use goliath_normalize::{Envelope, EventId, Normalized, Outcome};
use goliath_pipe::{Delivery, Receiver, Sender};
use serde_json::Value;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::RunError;
use crate::config::DetectorConfig;
use crate::metrics::Metrics;
use crate::roles::{BATCH, Lag, POLL};

/// The source findings are stored under.
pub(crate) const SOURCE: &str = "goliath-intel";
/// The version of the findings' shape, as a source definition has one.
const VERSION: u32 = 1;
/// The kind of record a finding is.
const KIND: &str = "indicator_match";
/// How often the publications of feeds are looked at for a change.
const REFRESH_EVERY: Duration = Duration::from_secs(30);

/// A feed, and the file its publication is read from.
struct Published {
    feed: Feed,
    file: PathBuf,
    /// The modification time and length of the publication last loaded or
    /// last refused, so that neither is read again until it changes.
    seen: Option<(SystemTime, u64)>,
    /// Whether its missing publication was already reported.
    missing: bool,
}

/// The indicators and allowlists the detector asks, and the feeds that fill
/// them.
pub(crate) struct Intel {
    matcher: Arc<Matcher<RocksStore>>,
    feeds: Vec<Published>,
}

fn io(error: impl std::fmt::Display) -> RunError {
    RunError::Io(error.to_string())
}

impl Intel {
    /// Opens the indicator store in `state` and reads the allowlists and
    /// feed definitions `config` names.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if a definition or an allowlist cannot
    /// be used, and [`RunError::Io`] if the store cannot be opened.
    pub(crate) fn open(config: &DetectorConfig, state: &Path) -> Result<Self, RunError> {
        let lists = config
            .allowlists
            .iter()
            .map(|path| {
                let yaml = std::fs::read_to_string(path)
                    .map_err(|error| RunError::Config(format!("{}: {error}", path.display())))?;
                Allowlist::from_yaml(&yaml)
                    .map_err(|error| RunError::Config(format!("{}: {error}", path.display())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allowlists =
            Allowlists::new(&lists).map_err(|error| RunError::Config(error.to_string()))?;
        let feeds = config
            .feeds
            .iter()
            .map(|feed| {
                Ok(Published {
                    feed: feed.feed()?,
                    file: feed.file.clone(),
                    seen: None,
                    missing: false,
                })
            })
            .collect::<Result<Vec<_>, RunError>>()?;
        std::fs::create_dir_all(state).map_err(io)?;
        let store = match config.cache_mebibytes {
            Some(mebibytes) => RocksStore::open_with(
                state,
                usize::try_from(mebibytes.get()).unwrap_or(1024) << 20,
            ),
            None => RocksStore::open(state),
        }
        .map_err(io)?;
        info!(
            state = %state.display(),
            feeds = feeds.len(),
            allowlist_entries = allowlists.len(),
            "indicator store opened"
        );
        Ok(Self {
            matcher: Arc::new(Matcher::new(store, allowlists)),
            feeds,
        })
    }

    /// The matcher events are looked up in.
    pub(crate) fn matcher(&self) -> Arc<Matcher<RocksStore>> {
        Arc::clone(&self.matcher)
    }

    /// Loads every feed whose publication changed since it was last looked
    /// at. A publication that is missing or refused leaves the feed as the
    /// store has it, and is reported.
    fn refresh(&mut self, metrics: &Metrics) {
        for published in &mut self.feeds {
            let name = published.feed.name.clone();
            let changed = match std::fs::metadata(&published.file) {
                Ok(metadata) => (metadata.modified().unwrap_or(UNIX_EPOCH), metadata.len()),
                Err(error) => {
                    if !published.missing {
                        warn!(feed = name, file = %published.file.display(), %error, "no publication");
                        metrics.feed_refreshed(&name, false, None);
                    }
                    published.missing = true;
                    published.seen = None;
                    continue;
                }
            };
            published.missing = false;
            if published.seen == Some(changed) {
                continue;
            }
            published.seen = Some(changed);
            let now = seconds(SystemTime::now());
            let modified = seconds(changed.0);
            let loaded = std::fs::read(&published.file)
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    published
                        .feed
                        .load(self.matcher.store(), &bytes, &modified.to_string(), now)
                        .map_err(|error| error.to_string())
                });
            match loaded {
                Ok(loaded) => {
                    info!(
                        feed = name,
                        indicators = loaded.indicators,
                        ignored = loaded.ignored,
                        rejected = loaded.rejected,
                        "feed loaded"
                    );
                    metrics.feed_refreshed(&name, true, Some((loaded.indicators, modified)));
                }
                Err(error) => {
                    warn!(
                        feed = name,
                        error, "feed refused; the store keeps what it had"
                    );
                    metrics.feed_refreshed(&name, false, None);
                }
            }
        }
    }
}

fn seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |since| {
        i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
    })
}

/// Loads the feeds, then again whenever a publication changes, until
/// stopped. Reading a publication blocks, so it runs off the async threads.
pub(crate) async fn refresh(
    mut intel: Intel,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    while !*stop.borrow_and_update() {
        let shared = metrics.clone();
        intel = tokio::task::spawn_blocking(move || {
            intel.refresh(&shared);
            intel
        })
        .await
        .map_err(|error| RunError::Role(format!("refreshing feeds: {error}")))?;
        tokio::select! {
            () = tokio::time::sleep(REFRESH_EVERY) => {}
            _ = stop.changed() => {}
        }
    }
    Ok(())
}

/// Looks the observables of every event up, and sends each hit on as a
/// finding, acknowledging events only once their findings are sent.
pub(crate) async fn detect(
    matcher: Arc<Matcher<RocksStore>>,
    threads: NonZeroUsize,
    mut events: impl Receiver + Sync,
    findings: impl Sender + Sync,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut lag = Lag::new("normalized".to_owned(), "detector");
    while !*stop.borrow_and_update() {
        lag.report(&events, &metrics).await;
        let deliveries = events.receive(BATCH, POLL).await?;
        let Some(last) = deliveries.last().map(|delivery| delivery.offset) else {
            continue;
        };
        let shared = Arc::clone(&matcher);
        let (encoded, tally) =
            tokio::task::spawn_blocking(move || detect_batch(&shared, &deliveries, threads))
                .await
                .map_err(|error| RunError::Role(format!("detecting: {error}")))??;
        metrics.detected(&tally);
        if !encoded.is_empty() {
            findings.send(encoded).await?;
        }
        events.acknowledge(last).await?;
    }
    Ok(())
}

/// What a batch of events gave, counted.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Tally {
    /// Events looked at.
    pub(crate) events: u64,
    /// Observables looked up.
    pub(crate) observables: u64,
    /// Hits reported.
    pub(crate) hits: u64,
    /// Hits an allowlist suppressed.
    pub(crate) suppressed: u64,
}

impl Tally {
    fn add(&mut self, other: Self) {
        self.events += other.events;
        self.observables += other.observables;
        self.hits += other.hits;
        self.suppressed += other.suppressed;
    }
}

type Detected = Result<(Vec<Vec<u8>>, Tally), RunError>;

/// Detects in `deliveries` on up to `threads` threads, each taking a run of
/// consecutive records, and joins their findings in the records' order.
fn detect_batch(
    matcher: &Matcher<RocksStore>,
    deliveries: &[Delivery],
    threads: NonZeroUsize,
) -> Detected {
    let per_thread = deliveries.len().div_ceil(threads.get()).max(1);
    let parts: Vec<Detected> = std::thread::scope(|scope| {
        let running: Vec<_> = deliveries
            .chunks(per_thread)
            .map(|chunk| scope.spawn(move || detect_run(matcher, chunk)))
            .collect();
        running
            .into_iter()
            // A panic in detection is a bug; carry it to this task.
            .map(|thread| {
                thread
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    let mut encoded = Vec::new();
    let mut tally = Tally::default();
    for part in parts {
        let (findings, counted) = part?;
        encoded.extend(findings);
        tally.add(counted);
    }
    Ok((encoded, tally))
}

fn detect_run(matcher: &Matcher<RocksStore>, deliveries: &[Delivery]) -> Detected {
    let created = jiff::Timestamp::now().as_millisecond();
    let mut encoded = Vec::new();
    let mut tally = Tally::default();
    for delivery in deliveries {
        let envelope = Envelope::decode(&delivery.payload)
            .map_err(|error| RunError::Corrupt(error.to_string()))?;
        let Outcome::Event(normalized) = &envelope.outcome else {
            continue;
        };
        tally.events += 1;
        let event = &normalized.event;
        // An indicator is asked whether it held when the event happened.
        let at = event
            .get("time")
            .and_then(Value::as_i64)
            .unwrap_or(created)
            .div_euclid(1000);
        let id = normalized.id.to_string();
        for observed in observables(event) {
            tally.observables += 1;
            let hits = matcher
                .lookup(observed.kind, &observed.value, at)
                .map_err(|error| RunError::Io(error.to_string()))?;
            for hit in hits {
                tally.hits += 1;
                tally.suppressed += u64::from(hit.suppressed.is_some());
                let finding = finding(&id, event, &observed, &hit, created);
                // The same event and indicator give the same identity, so a
                // batch detected twice is stored once.
                let uid = finding
                    .pointer("/finding_info/uid")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let identity = EventId::of(SOURCE, uid.as_bytes());
                encoded.push(
                    Envelope::new(
                        SOURCE,
                        VERSION,
                        Outcome::Event(Normalized::new(identity, finding, KIND)),
                    )
                    .received_at(created)
                    .encode(),
                );
            }
        }
    }
    Ok((encoded, tally))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use goliath_normalize::{Envelope, Normalizer, Outcome, SYSMON};
    use goliath_pipe::Delivery;

    use super::{Intel, SOURCE, detect_run};
    use crate::config::Config;
    use crate::metrics::Metrics;

    const KINDS: &str = include_str!("../../goliath-normalize/sources/sysmon/kinds.input.json");

    /// The events the Sysmon definition makes of its fixture, as the
    /// normalizer sends them.
    fn deliveries() -> Vec<Delivery> {
        let sysmon = Normalizer::from_yaml(SYSMON).unwrap();
        let mut deliveries = Vec::new();
        sysmon.normalize(KINDS.as_bytes(), |outcome| {
            deliveries.push(Delivery {
                offset: deliveries.len() as u64,
                payload: Envelope::new("sysmon", 1, outcome).encode(),
            });
        });
        deliveries
    }

    fn config(directory: &std::path::Path) -> Config {
        let path = directory.join("goliath.toml");
        std::fs::write(
            &path,
            r#"
roles = ["detector"]
data = "data"

[detector]
allowlists = ["allow.yaml"]

[[detector.feeds]]
definition = "feodo-tracker"
file = "feeds/feodo.csv"
"#,
        )
        .unwrap();
        std::fs::write(
            directory.join("allow.yaml"),
            "name: infrastructure\nversion: 1\nentries:\n  - { kind: ip, value: 198.51.100.1, reason: Our resolver }\n",
        )
        .unwrap();
        Config::load(&path).unwrap()
    }

    fn publish(directory: &std::path::Path, address: &str) {
        std::fs::create_dir_all(directory.join("feeds")).unwrap();
        // Last online far ahead, so the indicator holds when the fixture's
        // events happened and whenever the test runs.
        std::fs::write(
            directory.join("feeds/feodo.csv"),
            format!(
                "\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\
                 \"2026-01-01 00:00:00\",\"{address}\",\"443\",\"online\",\"2099-01-01\",\"Example\"\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn an_event_with_an_address_a_feed_names_gives_one_finding() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let metrics = Metrics::new();
        let mut intel = Intel::open(
            config.detector.as_ref().unwrap(),
            &config.detector_state().unwrap(),
        )
        .unwrap();

        // No publication yet: nothing matches, and the detector still runs.
        intel.refresh(&metrics);
        let events = deliveries();
        let (findings, tally) = detect_run(&intel.matcher(), &events).unwrap();
        assert!(findings.is_empty());
        assert!(tally.events > 0 && tally.observables > 0);
        assert!(
            metrics.encode().contains(
                "goliath_feed_refreshes_total{feed=\"feodo-tracker\",result=\"refused\"} 1"
            )
        );

        // The address the fixture's network connection goes to.
        publish(directory.path(), "192.0.2.10");
        intel.refresh(&metrics);
        let (findings, tally) = detect_run(&intel.matcher(), &events).unwrap();
        assert_eq!((findings.len(), tally.hits, tally.suppressed), (1, 1, 0));
        let envelope = Envelope::decode(&findings[0]).unwrap();
        assert_eq!(envelope.source, SOURCE);
        let Outcome::Event(finding) = envelope.outcome else {
            panic!("not an event");
        };
        assert_eq!(finding.kind, "indicator_match");
        assert_eq!(finding.event["class_uid"], 2004);
        assert_eq!(finding.event["osint"][0]["vendor_name"], "feodo-tracker");
        assert_eq!(finding.event["observables"][0]["name"], "dst_endpoint.ip");
        // The same batch detected again gives the same identity.
        let (again, _) = detect_run(&intel.matcher(), &events).unwrap();
        let Outcome::Event(second) = Envelope::decode(&again[0]).unwrap().outcome else {
            panic!("not an event");
        };
        assert_eq!(finding.id, second.id);

        // A publication that is not the feed is refused, and what was
        // loaded still matches.
        std::fs::write(
            directory.path().join("feeds/feodo.csv"),
            "<html>error</html>",
        )
        .unwrap();
        intel.refresh(&metrics);
        let (findings, _) = detect_run(&intel.matcher(), &events).unwrap();
        assert_eq!(findings.len(), 1);
        let text = metrics.encode();
        assert!(
            text.contains("goliath_feed_indicators{feed=\"feodo-tracker\"} 1"),
            "{text}"
        );
        assert!(
            text.contains(
                "goliath_feed_refreshes_total{feed=\"feodo-tracker\",result=\"refused\"} 2"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_detector_without_feeds_or_a_place_for_its_store_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("goliath.toml");
        for (body, expected) in [
            (
                "roles = [\"detector\"]\ndata = \"data\"\n",
                "needs a [detector] section",
            ),
            (
                "roles = [\"detector\"]\ndata = \"data\"\n[detector]\n",
                "needs a feed",
            ),
            (
                "roles = [\"detector\"]\ndata = \"data\"\n[[detector.feeds]]\ndefinition = \"nowhere.yaml\"\nfile = \"f\"\n",
                "nowhere.yaml",
            ),
            (
                "roles = [\"detector\"]\ndata = \"data\"\n[[detector.feeds]]\ndefinition = \"sslbl\"\nfile = \"a\"\n[[detector.feeds]]\ndefinition = \"sslbl\"\nfile = \"b\"\n",
                "configured twice",
            ),
        ] {
            std::fs::write(&path, body).unwrap();
            let error = Config::load(&path).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }
}
