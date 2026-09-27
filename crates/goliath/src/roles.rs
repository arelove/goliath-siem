//! The roles, each a loop over the pipe.
//!
//! Every loop has the same shape: receive, handle, hand on durably, and only
//! then acknowledge. A crash anywhere repeats work; it never loses records
//! (`docs/adr/0015-pipe-semantics.md`).

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use goliath_normalize::{Envelope, Normalizer, Outcome};
use goliath_pipe::{Delivery, Receiver, Sender};
use goliath_store::{Limits, Store, StoreError, Writer};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::RunError;
use crate::metrics::Metrics;

/// How long a loop waits for records before checking for shutdown.
const POLL: Duration = Duration::from_millis(200);

/// Records a normalizer or writer takes at once.
const BATCH: usize = 1024;

/// How often a reader reports how far behind it is. Asking costs a request
/// to the broker when topics are in Kafka.
const LAG_EVERY: Duration = Duration::from_secs(1);

/// Reports a reader's lag at most every [`LAG_EVERY`]. A failure to learn it
/// is not the reader's failure: the next receive reports what is wrong.
struct Lag {
    topic: String,
    reader: &'static str,
    last: Option<std::time::Instant>,
}

impl Lag {
    fn new(topic: String, reader: &'static str) -> Self {
        Self {
            topic,
            reader,
            last: None,
        }
    }

    async fn report(&mut self, receiver: &impl Receiver, metrics: &Metrics) {
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

/// Writes normalized outcomes to the store, acknowledging only what is
/// written. While the store is unavailable it retries, holding what it has.
pub(crate) async fn write(
    store: Store,
    limits: Limits,
    mut outcomes: impl Receiver + Sync,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut writer = Writer::new(store, limits);
    // The last offset received, and the last known to be written: every
    // outcome up to it has been flushed.
    let mut received = None;
    let mut written = None;
    // When the platform took each outcome's record, for those received but
    // not yet written, and for those written but not yet acknowledged.
    let mut pending = Vec::new();
    let mut stored = Vec::new();
    let mut lag = Lag::new("normalized".to_owned(), "writer");
    loop {
        lag.report(&outcomes, &metrics).await;
        let stopping = *stop.borrow_and_update();
        if stopping {
            flush(&mut writer, &mut stop, Flush::All, &metrics).await?;
        } else {
            let wait = writer.deadline().map_or(POLL, |deadline| {
                deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(POLL)
            });
            for delivery in outcomes.receive(BATCH, wait).await? {
                let envelope = Envelope::decode(&delivery.payload).map_err(|error| {
                    RunError::Corrupt(format!("normalized offset {}: {error}", delivery.offset))
                })?;
                received = Some(delivery.offset);
                pending.push(envelope.received);
                // A push that fails to flush has kept its outcome; only the
                // flush is repeated.
                let started = std::time::Instant::now();
                match writer.push(envelope).await {
                    // It filled the writer, and flushed.
                    Ok(()) if writer.waiting() == 0 => metrics.flushed(started.elapsed()),
                    Ok(()) => {}
                    Err(StoreError::ClickHouse(error)) => {
                        warn!(%error, "store unavailable; holding records and retrying");
                        flush(&mut writer, &mut stop, Flush::All, &metrics).await?;
                    }
                    Err(other) => return Err(RunError::Store(other)),
                }
                // A push that filled the writer flushed everything so far.
                // Under steady load the writer is never empty at the end of
                // a receive, so this is where most of it becomes
                // acknowledgeable.
                if writer.waiting() == 0 {
                    written = Some(delivery.offset);
                    stored.append(&mut pending);
                }
            }
            flush(&mut writer, &mut stop, Flush::IfDue, &metrics).await?;
        }
        if writer.waiting() == 0
            && let Some(offset) = received.take()
        {
            written = Some(offset);
            stored.append(&mut pending);
        }
        if let Some(offset) = written.take() {
            outcomes.acknowledge(offset).await?;
            metrics.stored(&std::mem::take(&mut stored), crate::raw::now());
            info!(through = offset, "stored");
        }
        if stopping {
            return Ok(());
        }
    }
}

#[derive(Clone, Copy)]
enum Flush {
    All,
    IfDue,
}

/// Flushes until it succeeds, waiting longer after each store failure, up
/// to 30 seconds. On shutdown it gives up instead: what it holds is not
/// acknowledged, so it is delivered again when the writer next starts.
async fn flush(
    writer: &mut Writer,
    stop: &mut watch::Receiver<bool>,
    which: Flush,
    metrics: &Metrics,
) -> Result<(), RunError> {
    let mut pause = Duration::from_millis(250);
    loop {
        let holding = writer.waiting();
        let started = std::time::Instant::now();
        let result = match which {
            Flush::All => writer.flush().await,
            Flush::IfDue => writer.flush_if_due().await,
        };
        match result {
            Ok(()) => {
                // Only a flush that wrote something is a write worth timing.
                if holding > 0 && writer.waiting() == 0 {
                    metrics.flushed(started.elapsed());
                }
                return Ok(());
            }
            Err(StoreError::ClickHouse(error)) if !*stop.borrow() => {
                warn!(%error, retry_in = ?pause, "store unavailable; holding records and retrying");
                let _ = tokio::time::timeout(pause, stop.changed()).await;
                pause = (pause * 2).min(Duration::from_secs(30));
            }
            Err(error) => return Err(RunError::Store(error)),
        }
    }
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
