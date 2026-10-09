//! The roles, each a loop over the pipe.
//!
//! Every loop has the same shape: receive, handle, hand on durably, and only
//! then acknowledge. A crash anywhere repeats work; it never loses records
//! (`docs/adr/0015-pipe-semantics.md`).

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use goliath_normalize::{Envelope, Normalizer, Outcome};
use goliath_pipe::{Delivery, Receiver, Sender};
use goliath_store::{Batch, Limits, Report, Standing, Store, StoreError, Writer};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::RunError;
use crate::health::Health;
use crate::metrics::Metrics;

/// How long a loop waits for records before checking for shutdown.
pub(crate) const POLL: Duration = Duration::from_millis(200);

/// Records a normalizer or writer takes at once.
pub(crate) const BATCH: usize = 1024;

/// How often a reader reports how far behind it is. Asking costs a request
/// to the broker when topics are in Kafka.
const LAG_EVERY: Duration = Duration::from_secs(1);

/// Reports a reader's lag at most every [`LAG_EVERY`]. A failure to learn it
/// is not the reader's failure: the next receive reports what is wrong.
pub(crate) struct Lag {
    topic: String,
    reader: &'static str,
    last: Option<std::time::Instant>,
}

impl Lag {
    pub(crate) fn new(topic: String, reader: &'static str) -> Self {
        Self {
            topic,
            reader,
            last: None,
        }
    }

    pub(crate) async fn report(&mut self, receiver: &impl Receiver, metrics: &Metrics) {
        if self.last.is_some_and(|last| last.elapsed() < LAG_EVERY) {
            return;
        }
        self.last = Some(std::time::Instant::now());
        if let Ok(records) = receiver.lag().await {
            metrics.lag(&self.topic, self.reader, records);
        }
    }
}

/// The largest file the collector takes, since it travels as one record.
const MAX_FILE: u64 = 64 << 20;

/// Takes finished files from `inbox` into the source's raw topic.
///
/// A file is picked up once it appears; a producer writes it under a name
/// starting with `.` or ending in `.tmp`, and renames it when complete. After
/// it is sent, it moves to `inbox/done`, or to `inbox/rejected` if it is too
/// large to send. A crash between sending and moving sends it again, and
/// storage drops the duplicates by identity.
pub(crate) async fn collect(
    source: String,
    inbox: PathBuf,
    raw: impl Sender + Sync,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let done = inbox.join("done");
    let rejected = inbox.join("rejected");
    for directory in [&inbox, &done, &rejected] {
        tokio::fs::create_dir_all(directory)
            .await
            .map_err(|error| io(directory, &error))?;
    }
    while !*stop.borrow() {
        for path in ready_files(&inbox).await? {
            let size = tokio::fs::metadata(&path)
                .await
                .map_err(|error| io(&path, &error))?
                .len();
            if size > MAX_FILE {
                warn!(file = %path.display(), size, "file larger than 64 MiB rejected; split it and drop it again");
                move_into(&path, &rejected).await?;
                metrics.rejected(&source);
                continue;
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|error| io(&path, &error))?;
            raw.send(vec![crate::raw::stamp(crate::raw::now(), &bytes)])
                .await?;
            move_into(&path, &done).await?;
            metrics.collected(&source, size);
            info!(file = %path.display(), size, "collected");
        }
        // Woken early by shutdown; otherwise look again after a pause.
        let _ = tokio::time::timeout(POLL, stop.changed()).await;
    }
    Ok(())
}

/// Files in `inbox` ready to collect, oldest name first.
async fn ready_files(inbox: &Path) -> Result<Vec<PathBuf>, RunError> {
    let mut entries = tokio::fs::read_dir(inbox)
        .await
        .map_err(|error| io(inbox, &error))?;
    let mut files = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| io(inbox, &error))?
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_file = entry
            .file_type()
            .await
            .map_err(|error| io(inbox, &error))?
            .is_file();
        if is_file && !name.starts_with('.') && !name.ends_with(".tmp") {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

async fn move_into(path: &Path, directory: &Path) -> Result<(), RunError> {
    let target = directory.join(path.file_name().unwrap_or_default());
    tokio::fs::rename(path, &target)
        .await
        .map_err(|error| io(path, &error))
}

/// Normalizes the raw records of one source into the normalized topic.
///
/// A batch is normalized on `threads` threads at once, off the runtime's own
/// threads; outcomes keep the order of their records, and the batch is
/// acknowledged only once all of it is sent, as before.
pub(crate) async fn normalize(
    normalizer: Normalizer,
    threads: NonZeroUsize,
    mut raw: impl Receiver + Sync,
    outcomes: impl Sender + Sync,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let normalizer = Arc::new(normalizer);
    let source = normalizer.name().to_owned();
    let mut lag = Lag::new(format!("raw-{source}"), "normalizer");
    while !*stop.borrow_and_update() {
        lag.report(&raw, &metrics).await;
        let deliveries = raw.receive(BATCH, POLL).await?;
        let Some(last) = deliveries.last().map(|delivery| delivery.offset) else {
            continue;
        };
        let records = deliveries.len();
        let shared = Arc::clone(&normalizer);
        let (encoded, tally) =
            tokio::task::spawn_blocking(move || normalize_batch(&shared, &deliveries, threads))
                .await
                .map_err(|error| RunError::Role(format!("normalizing: {error}")))?;
        metrics.events(&source, tally.events);
        for (stage, count) in tally.dead_letters {
            metrics.dead_letters(&source, stage, count);
        }
        let count = encoded.len();
        outcomes.send(encoded).await?;
        raw.acknowledge(last).await?;
        metrics.normalized(&source, records);
        info!(source, records, outcomes = count, "normalized");
    }
    Ok(())
}

/// What a batch became, counted.
#[derive(Default)]
struct Tally {
    events: u64,
    dead_letters: BTreeMap<&'static str, u64>,
}

impl Tally {
    fn add(&mut self, other: Self) {
        self.events += other.events;
        for (stage, count) in other.dead_letters {
            *self.dead_letters.entry(stage).or_default() += count;
        }
    }
}

/// Normalizes `deliveries` on up to `threads` threads, each taking a run of
/// consecutive records, and joins their outcomes in the records' order.
fn normalize_batch(
    normalizer: &Normalizer,
    deliveries: &[Delivery],
    threads: NonZeroUsize,
) -> (Vec<Vec<u8>>, Tally) {
    let per_thread = deliveries.len().div_ceil(threads.get()).max(1);
    let parts: Vec<(Vec<Vec<u8>>, Tally)> = std::thread::scope(|scope| {
        let running: Vec<_> = deliveries
            .chunks(per_thread)
            .map(|chunk| scope.spawn(move || normalize_run(normalizer, chunk)))
            .collect();
        running
            .into_iter()
            // A panic in normalization is a bug; carry it to this task.
            .map(|thread| {
                thread
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    let mut encoded = Vec::with_capacity(parts.iter().map(|(part, _)| part.len()).sum());
    let mut tally = Tally::default();
    for (part, counted) in parts {
        encoded.extend(part);
        tally.add(counted);
    }
    (encoded, tally)
}

fn normalize_run(normalizer: &Normalizer, deliveries: &[Delivery]) -> (Vec<Vec<u8>>, Tally) {
    let mut encoded = Vec::new();
    let mut tally = Tally::default();
    for delivery in deliveries {
        let (received, bytes) = crate::raw::read(&delivery.payload);
        let received = received.unwrap_or_else(crate::raw::now);
        normalizer.normalize(bytes, |outcome| {
            match &outcome {
                Outcome::Event(_) => tally.events += 1,
                Outcome::DeadLetter(dead) => {
                    *tally.dead_letters.entry(dead.stage.as_str()).or_default() += 1;
                }
                _ => {}
            }
            encoded.push(
                Envelope::new(normalizer.name(), normalizer.version(), outcome)
                    .received_at(received)
                    .encode(),
            );
        });
    }
    (encoded, tally)
}

/// Inserts the writer keeps in flight at once. While they run it goes on
/// receiving and decoding, and ClickHouse takes several inserts in parallel.
const INSERTS: usize = 4;

/// Writes normalized outcomes to the store, acknowledging only what is
/// written. While the store is unavailable it retries, holding what it has.
///
/// What the writer holds is handed to an insert of its own once it is full
/// or due, with up to [`INSERTS`] running at once. Inserts may finish in any
/// order; they are acknowledged in the order they were started, so an
/// acknowledgement never covers an outcome still being written.
pub(crate) async fn write(
    store: Store,
    limits: Limits,
    threads: NonZeroUsize,
    topic: &'static str,
    mut outcomes: impl Receiver + Sync,
    (metrics, health): (Metrics, Health),
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    // The condition of storing what this topic holds.
    let storing = Storing {
        health,
        kind: if topic == "findings" {
            "storing_findings"
        } else {
            "storing"
        },
    };
    let mut writer = Writer::new(store.clone(), limits);
    // The last offset the writer holds, and when the platform took each
    // outcome it holds.
    let mut received = None;
    let mut pending = Vec::new();
    let mut inserts = VecDeque::new();
    let mut lag = Lag::new(topic.to_owned(), "writer");
    loop {
        lag.report(&outcomes, &metrics).await;
        let stopping = *stop.borrow_and_update();
        if !stopping && inserts.len() < INSERTS {
            let wait = writer.deadline().map_or(POLL, |deadline| {
                deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(POLL)
            });
            let deliveries = outcomes.receive(WRITE_BATCH, wait).await?;
            if let Some(last) = deliveries.last().map(|delivery| delivery.offset) {
                let shared = store.clone();
                let parts = tokio::task::spawn_blocking(move || {
                    rows_of(&shared, limits, &deliveries, threads)
                })
                .await
                .map_err(|error| RunError::Role(format!("decoding: {error}")))??;
                for (batches, taken) in parts {
                    writer.absorb(batches);
                    pending.extend(taken);
                }
                received = Some(last);
            }
        }
        // Due, or everything on shutdown; a full writer that found no free
        // insert waits here for one.
        let hand_over = if stopping {
            writer.waiting() > 0
        } else {
            writer.is_due() || writer.is_full()
        };
        if hand_over && (stopping || inserts.len() < INSERTS) {
            inserts.push_back(Insert::start(
                &store,
                &mut writer,
                &mut received,
                &mut pending,
                &storing,
                &stop,
            ));
        }
        // Acknowledge inserts that finished, oldest first. When no more can
        // start, or on shutdown, wait for the oldest.
        while let Some(oldest) = inserts.front() {
            let wait = stopping || inserts.len() >= INSERTS;
            if !wait && !oldest.task.is_finished() {
                break;
            }
            let Some(insert) = inserts.pop_front() else {
                break;
            };
            let took = insert
                .task
                .await
                .map_err(|error| RunError::Role(format!("writing: {error}")))??;
            outcomes.acknowledge(insert.through).await?;
            storing.stored(took);
            metrics.flushed(took);
            metrics.stored(&insert.received, crate::raw::now());
            info!(through = insert.through, "stored");
        }
        if stopping {
            return Ok(());
        }
    }
}

/// Outcomes the writer receives at once. Larger than [`BATCH`], so that
/// decoding them is worth spreading over threads; an insert may exceed
/// `max_rows` by up to this many rows.
const WRITE_BATCH: usize = 8 * BATCH;

/// A run of outcomes as rows, with when the platform took each.
type Rows = (Vec<Batch>, Vec<Option<i64>>);

/// Decodes `deliveries` into rows on up to `threads` threads, each taking a
/// run of consecutive outcomes into a writer of its own, and returns each
/// run's rows and receipt times in the outcomes' order.
fn rows_of(
    store: &Store,
    limits: Limits,
    deliveries: &[Delivery],
    threads: NonZeroUsize,
) -> Result<Vec<Rows>, RunError> {
    // Below this, a thread costs more than it saves.
    const FEWEST: usize = 256;
    let per_thread = deliveries.len().div_ceil(threads.get()).max(FEWEST);
    std::thread::scope(|scope| {
        let running: Vec<_> = deliveries
            .chunks(per_thread)
            .map(|chunk| {
                scope.spawn(move || {
                    let mut rows = Writer::new(store.clone(), limits);
                    let mut taken = Vec::with_capacity(chunk.len());
                    for delivery in chunk {
                        let envelope = Envelope::decode(&delivery.payload).map_err(|error| {
                            RunError::Corrupt(format!(
                                "normalized offset {}: {error}",
                                delivery.offset
                            ))
                        })?;
                        taken.push(envelope.received);
                        rows.add(envelope).map_err(RunError::Store)?;
                    }
                    Ok((rows.take(), taken))
                })
            })
            .collect();
        running
            .into_iter()
            // A panic in decoding is a bug; carry it to this task.
            .map(|thread| {
                thread
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    })
}

/// Outcomes on their way to the store, through the offset `through`.
struct Insert {
    through: u64,
    received: Vec<Option<i64>>,
    task: tokio::task::JoinHandle<Result<Duration, RunError>>,
}

impl Insert {
    /// Starts writing everything `writer` holds.
    fn start(
        store: &Store,
        writer: &mut Writer,
        through: &mut Option<u64>,
        received: &mut Vec<Option<i64>>,
        storing: &Storing,
        stop: &watch::Receiver<bool>,
    ) -> Self {
        let batches = writer.take();
        let task = tokio::spawn(insert(
            store.clone(),
            batches,
            storing.clone(),
            stop.clone(),
        ));
        Self {
            // Something was added before anything is taken.
            through: through.take().unwrap_or_default(),
            received: std::mem::take(received),
            task,
        }
    }
}

/// Writes `batches` until they are written, waiting longer after each store
/// failure, up to 30 seconds, and returns how long the writing took. On
/// shutdown it gives up instead: what it holds is not acknowledged, so it is
/// delivered again when the writer next starts.
async fn insert(
    store: Store,
    batches: Vec<Batch>,
    storing: Storing,
    mut stop: watch::Receiver<bool>,
) -> Result<Duration, RunError> {
    let mut pause = Duration::from_millis(250);
    let mut written = 0;
    loop {
        let started = std::time::Instant::now();
        let mut failed = None;
        for batch in &batches[written..] {
            if let Err(error) = store.write(batch).await {
                failed = Some(error);
                break;
            }
            written += 1;
        }
        match failed {
            None => return Ok(started.elapsed()),
            Some(StoreError::ClickHouse(error)) if !*stop.borrow() => {
                warn!(%error, retry_in = ?pause, "store unavailable; holding records and retrying");
                storing.refused(&error);
                let _ = tokio::time::timeout(pause, stop.changed()).await;
                pause = (pause * 2).min(Duration::from_secs(30));
            }
            Some(error) => return Err(RunError::Store(error)),
        }
    }
}

/// A batch that takes the store longer than this is told.
const SLOW: Duration = Duration::from_secs(10);

/// How storing goes, as the writer's condition says it.
#[derive(Clone)]
struct Storing {
    health: Health,
    kind: &'static str,
}

impl Storing {
    /// A batch was stored, in `took`.
    fn stored(&self, took: Duration) {
        if took > SLOW {
            self.health.set(
                "writer",
                self.kind,
                Standing::Degraded,
                "store_slow",
                format!(
                    "The store took {} seconds for the last batch. Look at its load and its disk.",
                    took.as_secs()
                ),
            );
        } else {
            self.health.set(
                "writer",
                self.kind,
                Standing::Ok,
                "stored",
                "The last batch was stored.".to_owned(),
            );
        }
    }

    /// The store refused a batch, which is held and tried again.
    fn refused(&self, error: &impl std::fmt::Display) {
        self.health.set(
            "writer",
            self.kind,
            Standing::Failing,
            "store_refused",
            format!("The store refused the last batch, which is held and tried again: {error}"),
        );
    }
}

/// Keeps what the processes of the platform report of themselves, from the
/// `health` topic.
///
/// A report is worth what it says now: one that cannot be read or stored
/// is given up and not held, and the next one of its process says more.
pub(crate) async fn keep_reports(
    store: Store,
    mut reports: impl Receiver + Sync,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    while !*stop.borrow_and_update() {
        let deliveries = reports.receive(BATCH, POLL).await?;
        let Some(last) = deliveries.last().map(|delivery| delivery.offset) else {
            continue;
        };
        let read: Vec<Report> = deliveries
            .iter()
            .filter_map(|delivery| match serde_json::from_slice(&delivery.payload) {
                Ok(report) => Some(report),
                Err(error) => {
                    warn!(%error, "a report on the health topic cannot be read");
                    None
                }
            })
            .collect();
        if let Err(error) = store.write_reports(&read, crate::raw::now()).await {
            warn!(%error, reports = read.len(), "reports of the platform were not stored");
        }
        reports.acknowledge(last).await?;
    }
    Ok(())
}

fn io(path: &Path, error: &std::io::Error) -> RunError {
    RunError::Io(format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    const DEFINITION: &str = r#"
name: test
version: 1
framing: lines
decoding: json
common:
  time: { from: at, as: unix-seconds }
  severity_id: { value: 1 }
  metadata.version: { value: "1.5.0" }
  metadata.product.name: { value: Test }
kinds:
  - name: launch
    when: { type: launch }
    class: { class_uid: 1007, activity_id: 1 }
    fields:
      process.pid: { from: pid, as: integer }
"#;

    fn deliveries() -> Vec<Delivery> {
        (0..97_u64)
            .map(|offset| {
                let mut lines = String::new();
                for line in 0..10 {
                    // Every seventh record is not JSON, so dead letters are
                    // interleaved with events.
                    if (offset + line) % 7 == 0 {
                        lines.push_str("not json\n");
                    } else {
                        let _ = writeln!(
                            lines,
                            "{{\"type\": \"launch\", \"at\": {}, \"pid\": {}}}",
                            1_790_000_000 + offset,
                            offset * 10 + line
                        );
                    }
                }
                Delivery {
                    offset,
                    payload: crate::raw::stamp(1_790_000_000_000, lines.as_bytes()),
                }
            })
            .collect()
    }

    #[test]
    fn any_number_of_threads_gives_the_same_outcomes_in_the_same_order() {
        let normalizer = Normalizer::from_yaml(DEFINITION).unwrap();
        let deliveries = deliveries();
        let (alone, counted) = normalize_batch(&normalizer, &deliveries, NonZeroUsize::MIN);
        assert_eq!(alone.len(), 970);
        assert!(counted.events > 0);
        assert!(counted.dead_letters.values().sum::<u64>() > 0);
        for threads in [2, 3, 8, 200] {
            let (together, tally) = normalize_batch(
                &normalizer,
                &deliveries,
                NonZeroUsize::new(threads).unwrap(),
            );
            assert!(together == alone, "{threads} threads changed the outcomes");
            assert_eq!(tally.events, counted.events);
            assert_eq!(tally.dead_letters, counted.dead_letters);
        }
    }
}
