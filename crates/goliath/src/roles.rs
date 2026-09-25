//! The roles, each a loop over the pipe.
//!
//! Every loop has the same shape: receive, handle, hand on durably, and only
//! then acknowledge. A crash anywhere repeats work; it never loses records
//! (`docs/adr/0015-pipe-semantics.md`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use goliath_normalize::{Envelope, Normalizer};
use goliath_pipe::{Receiver, Sender};
use goliath_store::{Limits, Store, StoreError, Writer};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::RunError;

/// How long a loop waits for records before checking for shutdown.
const POLL: Duration = Duration::from_millis(200);

/// Records a normalizer or writer takes at once.
const BATCH: usize = 1024;

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
    inbox: PathBuf,
    raw: impl Sender + Sync,
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
                continue;
            }
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|error| io(&path, &error))?;
            raw.send(vec![bytes]).await?;
            move_into(&path, &done).await?;
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
pub(crate) async fn normalize(
    normalizer: Normalizer,
    mut raw: impl Receiver,
    outcomes: impl Sender + Sync,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    while !*stop.borrow_and_update() {
        let deliveries = raw.receive(BATCH, POLL).await?;
        let Some(last) = deliveries.last().map(|delivery| delivery.offset) else {
            continue;
        };
        let mut encoded = Vec::new();
        for delivery in &deliveries {
            normalizer.normalize(&delivery.payload, |outcome| {
                encoded
                    .push(Envelope::new(normalizer.name(), normalizer.version(), outcome).encode());
            });
        }
        let count = encoded.len();
        outcomes.send(encoded).await?;
        raw.acknowledge(last).await?;
        info!(
            source = normalizer.name(),
            records = deliveries.len(),
            outcomes = count,
            "normalized"
        );
    }
    Ok(())
}

/// Writes normalized outcomes to the store, acknowledging only what is
/// written. While the store is unavailable it retries, holding what it has.
pub(crate) async fn write(
    store: Store,
    limits: Limits,
    mut outcomes: impl Receiver,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut writer = Writer::new(store, limits);
    let mut received = None;
    loop {
        let stopping = *stop.borrow_and_update();
        if stopping {
            flush(&mut writer, &mut stop, Flush::All).await?;
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
                // A push that fails to flush has kept its outcome; only the
                // flush is repeated.
                match writer.push(envelope).await {
                    Ok(()) => {}
                    Err(StoreError::ClickHouse(error)) => {
                        warn!(%error, "store unavailable; holding records and retrying");
                        flush(&mut writer, &mut stop, Flush::All).await?;
                    }
                    Err(other) => return Err(RunError::Store(other)),
                }
            }
            flush(&mut writer, &mut stop, Flush::IfDue).await?;
        }
        if writer.waiting() == 0
            && let Some(offset) = received.take()
        {
            outcomes.acknowledge(offset).await?;
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
) -> Result<(), RunError> {
    let mut pause = Duration::from_millis(250);
    loop {
        let result = match which {
            Flush::All => writer.flush().await,
            Flush::IfDue => writer.flush_if_due().await,
        };
        match result {
            Ok(()) => return Ok(()),
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
