//! The detector: reads normalized events beside the writer, looks their
//! observables up among the indicators, and sends each hit on as a finding
//! for the writer to store. See `docs/adr/0021-enrichment-placement.md`.
//!
//! It never rewrites an event, and the writer does not read what it reads
//! through it: the two are separate groups of one topic.

use std::fmt::Write as _;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use goliath_intel::{Allowlist, Allowlists, Feed, Matcher, RocksStore, finding, observables};
use goliath_normalize::{Envelope, EventId, Normalized, Outcome};
use goliath_pipe::{Delivery, Receiver, Sender};
use goliath_store::Kept;
use serde_json::Value;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::RunError;
use crate::config::DetectorConfig;
use crate::fetch::{self, Fetched, Fetcher};
use crate::metrics::Metrics;
use crate::rematch::{self, Shared};
use crate::roles::{BATCH, Lag, POLL};

/// The source findings are stored under.
pub(crate) const SOURCE: &str = "goliath-intel";
/// The version of the findings' shape, as a source definition has one.
const VERSION: u32 = 1;
/// The kind of record a finding is.
const KIND: &str = "indicator_match";
/// How often the publications of feeds are looked at for a change.
const REFRESH_EVERY: Duration = Duration::from_secs(30);

/// How soon a fetch that failed is tried again.
const RETRY_AFTER: Duration = Duration::from_secs(300);

/// A feed, and the file its publication is read from.
struct Published {
    feed: Feed,
    file: PathBuf,
    /// Where the file is fetched from, if this process fetches it.
    remote: Option<Remote>,
    /// The modification time and length of the publication last loaded or
    /// last refused, so that neither is read again until it changes.
    seen: Option<(SystemTime, u64)>,
    /// Whether its missing publication was already reported.
    missing: bool,
}

/// Where a publication is fetched from, and when it was last.
struct Remote {
    url: String,
    /// The tag of the publication last fetched, to ask whether it changed.
    etag: Option<String>,
    /// When the publication was last fetched or found unchanged.
    checked: Option<SystemTime>,
    /// Not before this, after a fetch that failed.
    retry_at: Option<Instant>,
}

impl Published {
    /// Fetches the publication into its file, if it is fetched and due:
    /// never fetched, or last checked longer ago than the feed's interval.
    fn fetch(&mut self, fetcher: &Fetcher, metrics: &Metrics) {
        let name = &self.feed.name;
        let Some(remote) = &mut self.remote else {
            return;
        };
        let every = Duration::from_secs(u64::from(self.feed.refresh_minutes) * 60);
        let due = remote
            .checked
            .is_none_or(|checked| checked.elapsed().is_ok_and(|since| since >= every));
        if !due || remote.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        let outcome = fetcher
            .get(&remote.url, remote.etag.as_deref())
            .and_then(|fetched| match fetched {
                Fetched::Unchanged => Ok(()),
                Fetched::Publication { bytes, etag } => {
                    fetch::publish(&self.file, &bytes).map_err(|error| error.to_string())?;
                    remote.etag = etag;
                    info!(feed = name, bytes = bytes.len(), "feed fetched");
                    Ok(())
                }
            });
        match outcome {
            Ok(()) => {
                remote.checked = Some(SystemTime::now());
                remote.retry_at = None;
                metrics.feed_checked(name, seconds(SystemTime::now()));
            }
            Err(error) => {
                warn!(
                    feed = name,
                    url = remote.url,
                    error,
                    "feed not fetched; the store keeps what it had"
                );
                remote.retry_at = Some(Instant::now() + RETRY_AFTER);
                metrics.feed_refreshed(name, "failed", None);
            }
        }
    }
}

/// The indicators and allowlists the detector asks, and the feeds that fill
/// them.
pub(crate) struct Intel {
    matcher: Arc<Matcher<RocksStore>>,
    feeds: Vec<Published>,
    fetcher: Fetcher,
    /// Where it is noted that a feed added indicators, for a look back over
    /// the events stored before them.
    noted: Option<Shared>,
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
            .map(|configured| {
                let feed = configured.feed()?;
                // A fetched publication is kept beside the store, and a
                // restart within the feed's interval does not fetch again.
                let file = configured
                    .file
                    .clone()
                    .unwrap_or_else(|| state.join("publications").join(&feed.name));
                let remote = configured.fetched_from(&feed)?.map(|url| Remote {
                    url,
                    etag: None,
                    checked: std::fs::metadata(&file)
                        .and_then(|metadata| metadata.modified())
                        .ok(),
                    retry_at: None,
                });
                Ok(Published {
                    feed,
                    file,
                    remote,
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
            fetcher: Fetcher::new(),
            noted: None,
        })
    }

    /// Notes in `unmatched` whenever a feed adds indicators.
    pub(crate) fn notes(&mut self, unmatched: Shared) {
        self.noted = Some(unmatched);
    }

    /// The matcher events are looked up in.
    pub(crate) fn matcher(&self) -> Arc<Matcher<RocksStore>> {
        Arc::clone(&self.matcher)
    }

    /// Fetches every feed that is due, and loads every feed whose
    /// publication changed since it was last looked at. A publication that
    /// is missing, not fetched, or refused leaves the feed as the store has
    /// it, and is reported.
    fn refresh(&mut self, metrics: &Metrics) {
        for published in &mut self.feeds {
            published.fetch(&self.fetcher, metrics);
            let name = published.feed.name.clone();
            let changed = match std::fs::metadata(&published.file) {
                Ok(metadata) => (metadata.modified().unwrap_or(UNIX_EPOCH), metadata.len()),
                Err(error) => {
                    // A fetch that failed has said so already.
                    if !published.missing && published.remote.is_none() {
                        warn!(feed = name, file = %published.file.display(), %error, "no publication");
                        metrics.feed_refreshed(&name, "refused", None);
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
                        added = loaded.added,
                        ignored = loaded.ignored,
                        rejected = loaded.rejected,
                        "feed loaded"
                    );
                    // Events stored before these indicators were never
                    // matched against them.
                    if let Some(noted) = self.noted.as_ref().filter(|_| loaded.added > 0) {
                        rematch::lock(noted).added(now, crate::raw::now());
                    }
                    metrics.feed_refreshed(&name, "loaded", Some((loaded.indicators, modified)));
                    // A file put there by other means is current as of when
                    // it was written; a fetched one as of its fetch.
                    if published.remote.is_none() {
                        metrics.feed_checked(&name, modified);
                    }
                }
                Err(error) => {
                    warn!(
                        feed = name,
                        error, "feed refused; the store keeps what it had"
                    );
                    metrics.feed_refreshed(&name, "refused", None);
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
/// Says through `looked` when every feed was looked at once.
pub(crate) async fn refresh(
    mut intel: Intel,
    looked: watch::Sender<bool>,
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
        looked.send_replace(true);
        tokio::select! {
            () = tokio::time::sleep(REFRESH_EVERY) => {}
            _ = stop.changed() => {}
        }
    }
    Ok(())
}

/// Waits until every feed was looked at once, or until stopped. An event
/// matched before that is matched against a store that may be empty, and
/// nothing matches it again. Events wait in the topic meanwhile; a feed that
/// could not be had does not hold them longer than its fetch takes to fail.
pub(crate) async fn feeds_looked_at(
    looked: &mut watch::Receiver<bool>,
    stop: &mut watch::Receiver<bool>,
) {
    tokio::select! {
        _ = looked.wait_for(|looked| *looked) => {}
        _ = stop.wait_for(|stop| *stop) => {}
    }
}

/// Runs `role` once every feed was looked at.
pub(crate) async fn after_feeds(
    mut looked: watch::Receiver<bool>,
    mut stop: watch::Receiver<bool>,
    role: impl Future<Output = Result<(), RunError>>,
) -> Result<(), RunError> {
    feeds_looked_at(&mut looked, &mut stop).await;
    role.await
}

/// Looks the observables of every event up, and sends each hit on as a
/// finding, acknowledging events only once their findings are sent.
///
/// It reads as an observer, so it never slows the writer. If it falls
/// further behind than the topic keeps, it is moved past the events between,
/// which is counted and logged: they are stored, and not matched. The range
/// of receipt time they lie in is noted in `unmatched`, to be matched from
/// the store.
pub(crate) async fn detect(
    matcher: Arc<Matcher<RocksStore>>,
    threads: NonZeroUsize,
    mut events: impl Receiver + Sync,
    findings: impl Sender + Sync,
    unmatched: Shared,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut lag = Lag::new("normalized".to_owned(), "detector");
    while !*stop.borrow_and_update() {
        lag.report(&events, &metrics).await;
        let deliveries = events.receive(BATCH, POLL).await?;
        let skipped = events.skipped();
        if skipped > 0 {
            // Stored all the same; only not matched as they arrived.
            warn!(
                skipped,
                "the detector fell behind what the topic keeps, and was moved past events it did not match"
            );
            metrics.detector_skipped(skipped);
            // Up to the first record it was moved to; with none yet, up to
            // now, which nothing it missed can be later than.
            let resumed = deliveries
                .first()
                .and_then(received)
                .unwrap_or_else(crate::raw::now);
            let mut unmatched = rematch::lock(&unmatched);
            unmatched.skipped(resumed);
            metrics.unmatched_ranges(unmatched.len());
        }
        let Some(last) = deliveries.last() else {
            continue;
        };
        let (last, through) = (last.offset, received(last));
        let shared = Arc::clone(&matcher);
        let (encoded, tally) = tokio::task::spawn_blocking(move || {
            detect_batch(&shared, &deliveries, threads, detect_run)
        })
        .await
        .map_err(|error| RunError::Role(format!("detecting: {error}")))??;
        metrics.detected(&tally);
        if !encoded.is_empty() {
            findings.send(encoded).await?;
        }
        events.acknowledge(last).await?;
        if let Some(through) = through {
            rematch::lock(&unmatched).matched(through);
        }
    }
    rematch::lock(&unmatched).save();
    Ok(())
}

/// When the platform took the record of `delivery`, if it says.
fn received(delivery: &Delivery) -> Option<i64> {
    Envelope::decode(&delivery.payload).ok()?.received
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

pub(crate) type Detected = Result<(Vec<Vec<u8>>, Tally), RunError>;

/// Detects in `records` on up to `threads` threads, each taking a run of
/// consecutive records through `run`, and joins their findings in the
/// records' order.
pub(crate) fn detect_batch<T: Sync>(
    matcher: &Matcher<RocksStore>,
    records: &[T],
    threads: NonZeroUsize,
    run: impl Fn(&Matcher<RocksStore>, &[T]) -> Detected + Sync,
) -> Detected {
    let run = &run;
    let per_thread = records.len().div_ceil(threads.get()).max(1);
    let parts: Vec<Detected> = std::thread::scope(|scope| {
        let running: Vec<_> = records
            .chunks(per_thread)
            .map(|chunk| scope.spawn(move || run(matcher, chunk)))
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
        let seen = Seen {
            id: &normalized.id.to_string(),
            event: &normalized.event,
            received: envelope.received.unwrap_or(created),
        };
        detect_event(matcher, &seen, created, None, &mut encoded, &mut tally)?;
    }
    Ok((encoded, tally))
}

/// Detects in events read back from the store, as [`detect_run`] does in
/// events from the topic: the same event gives the same findings.
///
/// With `since`, in seconds since the epoch, only indicators the store has
/// held since then or later are reported: the ones that arrived after the
/// events were matched.
pub(crate) fn detect_kept(
    matcher: &Matcher<RocksStore>,
    kept: &[Kept],
    since: Option<i64>,
) -> Detected {
    let created = jiff::Timestamp::now().as_millisecond();
    let mut encoded = Vec::new();
    let mut tally = Tally::default();
    for kept in kept {
        // The store holds events as JSON; one that is not was not stored
        // by the writer, and is left alone.
        let Ok(event) = serde_json::from_str::<Value>(&kept.event) else {
            continue;
        };
        let id = kept.id.iter().fold(String::new(), |mut id, byte| {
            let _ = write!(id, "{byte:02x}");
            id
        });
        let seen = Seen {
            id: &id,
            event: &event,
            received: kept.received,
        };
        detect_event(matcher, &seen, created, since, &mut encoded, &mut tally)?;
    }
    Ok((encoded, tally))
}

/// An event to detect in.
struct Seen<'a> {
    /// Its identity, as text.
    id: &'a str,
    event: &'a Value,
    /// When the platform took it, in milliseconds since the epoch.
    received: i64,
}

/// Looks the observables of an event up, and adds each hit to `encoded` as
/// a finding. A finding is taken when its event was: the two are kept as
/// long as each other, and a finding made twice, as the event arrived and
/// from the store, is stored once. With `since`, a hit of an indicator the
/// store held before then is passed over.
fn detect_event(
    matcher: &Matcher<RocksStore>,
    seen: &Seen<'_>,
    created: i64,
    since: Option<i64>,
    encoded: &mut Vec<Vec<u8>>,
    tally: &mut Tally,
) -> Result<(), RunError> {
    let Seen {
        id,
        event,
        received,
    } = *seen;
    tally.events += 1;
    // An indicator is asked whether it held when the event happened.
    let at = event
        .get("time")
        .and_then(Value::as_i64)
        .unwrap_or(created)
        .div_euclid(1000);
    for observed in observables(event) {
        tally.observables += 1;
        let hits = matcher
            .lookup(observed.kind, &observed.value, at)
            .map_err(|error| RunError::Io(error.to_string()))?;
        for hit in hits {
            // Held before: the event was matched against it as it arrived.
            if since.is_some_and(|since| hit.known_since().is_none_or(|added| added < since)) {
                continue;
            }
            tally.hits += 1;
            tally.suppressed += u64::from(hit.suppressed.is_some());
            let finding = finding(id, event, &observed, &hit, created);
            // The same event and indicator give the same identity, so an
            // event detected twice is stored once.
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
                .received_at(received)
                .encode(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use goliath_normalize::{Envelope, Normalizer, Outcome, SYSMON};
    use goliath_pipe::Delivery;

    use super::{Intel, SOURCE, detect_kept, detect_run};
    use crate::config::Config;
    use crate::metrics::Metrics;

    const KINDS: &str = include_str!("../../goliath-normalize/sources/sysmon/kinds.input.json");
    /// When the platform took the fixture, where a test says.
    const TAKEN: i64 = 1_790_000_000_000;

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

    #[tokio::test]
    async fn matching_waits_until_the_feeds_were_looked_at() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let intel = Intel::open(
            config.detector.as_ref().unwrap(),
            &config.detector_state().unwrap(),
        )
        .unwrap();
        publish(directory.path(), "192.0.2.10");
        let matcher = intel.matcher();
        let (looked, mut is_looked) = tokio::sync::watch::channel(false);
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let refreshing = tokio::spawn(super::refresh(
            intel,
            looked,
            Metrics::new(),
            stopped.clone(),
        ));

        // Whoever waited finds the feed in the store.
        super::feeds_looked_at(&mut is_looked, &mut stopped).await;
        assert!(*is_looked.borrow());
        assert_eq!(detect_run(&matcher, &deliveries()).unwrap().0.len(), 1);
        stop.send(true).unwrap();
        refreshing.await.unwrap().unwrap();

        // Stopped before any feed was looked at: the wait ends.
        let (_never, mut is_looked) = tokio::sync::watch::channel(false);
        super::feeds_looked_at(&mut is_looked, &mut stopped).await;
        assert!(!*is_looked.borrow());
    }

    #[test]
    fn an_event_read_back_from_the_store_gives_the_finding_it_gave_as_it_arrived() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let mut intel = Intel::open(
            config.detector.as_ref().unwrap(),
            &config.detector_state().unwrap(),
        )
        .unwrap();
        publish(directory.path(), "192.0.2.10");
        intel.refresh(&Metrics::new());

        let sysmon = Normalizer::from_yaml(SYSMON).unwrap();
        let (mut arriving, mut kept) = (Vec::new(), Vec::new());
        sysmon.normalize(KINDS.as_bytes(), |outcome| {
            if let Outcome::Event(normalized) = &outcome {
                // As the writer stores it and the store gives it back.
                kept.push(goliath_store::Kept {
                    received: TAKEN,
                    id: *normalized.id.as_bytes(),
                    source: "sysmon".to_owned(),
                    event: normalized.event.to_string(),
                });
            }
            arriving.push(Delivery {
                offset: arriving.len() as u64,
                payload: Envelope::new("sysmon", 1, outcome)
                    .received_at(TAKEN)
                    .encode(),
            });
        });
        // What is not JSON is no stored event, and is passed over.
        kept.push(goliath_store::Kept {
            received: TAKEN,
            id: [0; 16],
            source: "sysmon".to_owned(),
            event: "not json".to_owned(),
        });

        let (arrived, counted) = detect_run(&intel.matcher(), &arriving).unwrap();
        let (read_back, recounted) = detect_kept(&intel.matcher(), &kept, None).unwrap();
        assert_eq!((arrived.len(), read_back.len()), (1, 1));
        assert_eq!(
            (counted.events, counted.observables),
            (recounted.events, recounted.observables)
        );
        let finding = |encoded: &[u8]| {
            let envelope = Envelope::decode(encoded).unwrap();
            let Outcome::Event(finding) = envelope.outcome else {
                panic!("not an event");
            };
            (envelope.received, finding.id, finding.event)
        };
        let (first, second) = (finding(&arrived[0]), finding(&read_back[0]));
        // Taken when its event was, and the same identity: stored once.
        assert_eq!((first.0, second.0), (Some(TAKEN), Some(TAKEN)));
        assert_eq!(first.1, second.1);
        assert_eq!(first.2["evidences"], second.2["evidences"]);
        assert_eq!(first.2["osint"], second.2["osint"]);

        // Looking back for indicators added since some time: one the store
        // held before is passed over, one added then or later is reported.
        let added = intel
            .matcher()
            .lookup(goliath_intel::Kind::Ip, "192.0.2.10", 0)
            .unwrap()[0]
            .known_since()
            .unwrap();
        let late = |since: i64| {
            detect_kept(&intel.matcher(), &kept, Some(since))
                .unwrap()
                .1
                .hits
        };
        assert_eq!((late(added), late(added + 1)), (1, 0));
    }

    /// Serves `body` on a port of this host, with a tag, and answers 304 to
    /// a request that names the tag. Counts the requests it answered.
    fn serve(body: &'static str) -> (u16, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
                let answer = if request.contains("if-none-match: \"v1\"") {
                    "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"
                        .to_owned()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(answer.as_bytes());
            }
        });
        (port, requests)
    }

    #[test]
    fn a_feed_is_fetched_when_due_and_asked_whether_it_changed() {
        let (port, requests) = serve(
            "\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\
             \"2026-01-01 00:00:00\",\"192.0.2.10\",\"443\",\"online\",\"2099-01-01\",\"Example\"\n",
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("goliath.toml");
        std::fs::write(
            &path,
            format!(
                "roles = [\"detector\"]\ndata = \"data\"\n\n[[detector.feeds]]\ndefinition = \"feodo-tracker\"\nurl = \"http://127.0.0.1:{port}/ipblocklist.csv\"\n"
            ),
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let state = config.detector_state().unwrap();
        let metrics = Metrics::new();
        let mut intel = Intel::open(config.detector.as_ref().unwrap(), &state).unwrap();
        let events = deliveries();
        let hits = |intel: &Intel| detect_run(&intel.matcher(), &events).unwrap().0.len();

        // Never fetched: fetched now, kept beside the store, and loaded.
        intel.refresh(&metrics);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(state.join("publications/feodo-tracker").exists());
        assert_eq!(hits(&intel), 1);

        // Within the feed's interval nothing is asked.
        intel.refresh(&metrics);
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        // Due again: the server is asked with the tag, says it is unchanged,
        // and nothing is loaded a second time.
        intel.feeds[0].remote.as_mut().unwrap().checked = None;
        intel.refresh(&metrics);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        let text = metrics.encode();
        assert!(
            text.contains(
                "goliath_feed_refreshes_total{feed=\"feodo-tracker\",result=\"loaded\"} 1"
            ),
            "{text}"
        );
        assert!(text.contains("goliath_feed_checked_timestamp_seconds{feed=\"feodo-tracker\"}"));

        // The server gone: the fetch fails, is counted, is not tried again
        // at once, and the store keeps the feed.
        let remote = intel.feeds[0].remote.as_mut().unwrap();
        remote.checked = None;
        remote.url = "http://127.0.0.1:1/ipblocklist.csv".to_owned();
        intel.refresh(&metrics);
        intel.feeds[0].remote.as_mut().unwrap().checked = None;
        intel.refresh(&metrics);
        let text = metrics.encode();
        assert!(
            text.contains(
                "goliath_feed_refreshes_total{feed=\"feodo-tracker\",result=\"failed\"} 1"
            ),
            "{text}"
        );
        assert_eq!(hits(&intel), 1);

        // Started again within the interval, with the publication kept: no
        // fetch, and the feed is in the store.
        drop(intel);
        let intel = {
            let mut intel = Intel::open(config.detector.as_ref().unwrap(), &state).unwrap();
            intel.refresh(&metrics);
            intel
        };
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert_eq!(hits(&intel), 1);
    }

    #[test]
    fn a_feed_needs_a_file_or_a_url_it_may_be_fetched_from() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("goliath.toml");
        std::fs::write(
            directory.path().join("list.yaml"),
            "name: list\nconfidence: 50\nformat: stix\n",
        )
        .unwrap();
        let feed = |body: &str| {
            format!("roles = [\"detector\"]\ndata = \"data\"\n[[detector.feeds]]\n{body}")
        };
        for (body, expected) in [
            (
                feed("definition = \"list.yaml\"\n"),
                "needs a `file` or a `url`",
            ),
            (
                feed("definition = \"list.yaml\"\nurl = \"http://feeds.example.com/list\"\n"),
                "without TLS from another host",
            ),
        ] {
            std::fs::write(&path, body).unwrap();
            let error = Config::load(&path).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
        // The shipped definitions name their own URL, over HTTPS; a file
        // alone means nothing is fetched.
        for body in [
            feed("definition = \"urlhaus\"\n"),
            feed("definition = \"list.yaml\"\nfile = \"list.json\"\n"),
            feed("definition = \"list.yaml\"\nurl = \"https://feeds.example.com/list\"\n"),
        ] {
            std::fs::write(&path, body).unwrap();
            Config::load(&path).unwrap();
        }
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
