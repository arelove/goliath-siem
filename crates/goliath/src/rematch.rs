//! Matching, from the store, the events the detector was moved past.
//!
//! The detector reads as an observer, and one that falls further behind
//! than the topic keeps is moved forward (`docs/adr/0015-pipe-semantics.md`).
//! The events between were stored like every other. The detector notes the
//! range of receipt time they lie in, in a file beside its indicator store,
//! and this role reads each range back from the event store and matches it.
//! The same event and indicator give the same finding, so an event matched
//! twice is stored once.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use goliath_intel::{Matcher, RocksStore};
use goliath_pipe::Sender;
use goliath_store::Store;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::RunError;
use crate::detector::{self, SOURCE};
use crate::metrics::Metrics;
use crate::roles::BATCH;

/// How far the order of records in the topic may differ from the order the
/// platform took them in, in milliseconds. Each role stamps a record before
/// it sends it, and the writer keeps several inserts in flight, so neither
/// order is exact. A range is widened by this much at both ends; what is
/// matched twice for it is stored once.
const DISORDER: i64 = 60_000;
/// The receipt time read from the store at once, in milliseconds. A range
/// is given up to here after each, so a restart goes on from there.
const WINDOW: i64 = 60_000;
/// How often the ranges are looked at, and how soon a read that failed is
/// tried again.
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// How often the time matched up to is written down. A value that is behind
/// only widens the next range.
const SAVE_EVERY: Duration = Duration::from_secs(10);

/// Receipt times from `from` up to and not including `to`, in milliseconds
/// since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Range {
    pub(crate) from: i64,
    pub(crate) to: i64,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Noted {
    /// The latest receipt time among the records the detector matched.
    matched_until: i64,
    /// What it did not match, oldest first, none overlapping another.
    #[serde(default)]
    ranges: Vec<Range>,
}

/// The ranges of receipt time whose events were stored and not matched,
/// kept in a file so that a restart forgets none.
#[derive(Debug)]
pub(crate) struct Unmatched {
    file: PathBuf,
    noted: Noted,
    saved: Instant,
}

/// The ranges, shared by the detector, which notes them, and the role that
/// matches them.
pub(crate) type Shared = Arc<Mutex<Unmatched>>;

/// The ranges, whatever became of a thread that held them: each change
/// leaves them whole.
pub(crate) fn lock(shared: &Shared) -> MutexGuard<'_, Unmatched> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Unmatched {
    /// Opens the ranges noted in `state`, the directory of the indicator
    /// store. A detector that starts for the first time has matched nothing
    /// and missed nothing: its ranges begin at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Io`] if the file is there and cannot be read.
    pub(crate) fn open(state: &Path, now: i64) -> Result<Self, RunError> {
        let file = state.join("unmatched.json");
        let noted = match std::fs::read(&file) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| RunError::Io(format!("{}: {error}", file.display())))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Noted {
                matched_until: now,
                ranges: Vec::new(),
            },
            Err(error) => return Err(RunError::Io(format!("{}: {error}", file.display()))),
        };
        let mut unmatched = Self {
            file,
            noted,
            saved: Instant::now(),
        };
        unmatched.save();
        Ok(unmatched)
    }

    /// The detector matched records the platform took up to `received`.
    pub(crate) fn matched(&mut self, received: i64) {
        self.noted.matched_until = self.noted.matched_until.max(received);
        if self.saved.elapsed() >= SAVE_EVERY {
            self.save();
        }
    }

    /// The detector was moved past records, to one the platform took at
    /// `resumed`: what lies between the last it matched and that one is
    /// noted, widened by [`DISORDER`].
    pub(crate) fn skipped(&mut self, resumed: i64) {
        let from = self.noted.matched_until.min(resumed) - DISORDER;
        self.noted.ranges.push(Range {
            from,
            to: resumed + DISORDER,
        });
        self.noted.ranges.sort_unstable_by_key(|range| range.from);
        let mut merged: Vec<Range> = Vec::with_capacity(self.noted.ranges.len());
        for range in self.noted.ranges.drain(..) {
            match merged.last_mut() {
                Some(last) if range.from <= last.to => last.to = last.to.max(range.to),
                _ => merged.push(range),
            }
        }
        self.noted.ranges = merged;
        self.save();
    }

    /// The oldest range not yet matched.
    pub(crate) fn first(&self) -> Option<Range> {
        self.noted.ranges.first().copied()
    }

    /// How many ranges wait.
    pub(crate) fn len(&self) -> usize {
        self.noted.ranges.len()
    }

    /// The oldest range was matched up to `until`.
    pub(crate) fn matched_from_store(&mut self, until: i64) {
        if let Some(first) = self.noted.ranges.first_mut() {
            first.from = first.from.max(until);
            if first.from >= first.to {
                self.noted.ranges.remove(0);
            }
        }
        self.save();
    }

    /// Writes the ranges down. A failure is reported and tried again at the
    /// next change: the ranges in memory are still matched.
    pub(crate) fn save(&mut self) {
        self.saved = Instant::now();
        let written = serde_json::to_vec(&self.noted)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                crate::fetch::publish(&self.file, &bytes).map_err(|error| error.to_string())
            });
        if let Err(error) = written {
            warn!(file = %self.file.display(), error, "unmatched ranges not written down");
        }
    }
}

/// Reads each noted range from the store once the writer is past it, and
/// matches its events, until stopped. While the store is unavailable it
/// tries again, and the ranges wait.
pub(crate) async fn rematch(
    store: Store,
    matcher: Arc<Matcher<RocksStore>>,
    threads: NonZeroUsize,
    unmatched: Shared,
    findings: impl Sender + Sync,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    while !*stop.borrow_and_update() {
        let (first, waiting) = {
            let unmatched = lock(&unmatched);
            (unmatched.first(), unmatched.len())
        };
        metrics.unmatched_ranges(waiting);
        if let Some(range) = first {
            // An event taken after the range is stored: so is the range.
            match store.holds_received_from(range.to).await {
                Ok(true) => {
                    let until = range.to.min(range.from.saturating_add(WINDOW));
                    let read = read(
                        &store, &matcher, threads, range.from, until, &findings, &metrics, &stop,
                    )
                    .await;
                    match read {
                        Ok(Some(events)) => {
                            info!(
                                from = range.from,
                                until, events, "matched from the store what the detector missed"
                            );
                            lock(&unmatched).matched_from_store(until);
                            continue;
                        }
                        // Stopped before the end: the window is read again.
                        Ok(None) => continue,
                        Err(RunError::Store(error)) => {
                            warn!(%error, "unmatched events not read; trying again");
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(false) => {}
                Err(error) => warn!(%error, "store not asked; trying again"),
            }
        }
        tokio::select! {
            () = tokio::time::sleep(CHECK_EVERY) => {}
            _ = stop.changed() => {}
        }
    }
    Ok(())
}

/// Matches the stored events taken from `from` up to `until`, and returns
/// how many, or `None` if stopped before the last.
#[allow(clippy::too_many_arguments)]
async fn read(
    store: &Store,
    matcher: &Arc<Matcher<RocksStore>>,
    threads: NonZeroUsize,
    from: i64,
    until: i64,
    findings: &(impl Sender + Sync),
    metrics: &Metrics,
    stop: &watch::Receiver<bool>,
) -> Result<Option<u64>, RunError> {
    let mut reading = store.received_between(from, until)?;
    let mut batch = Vec::with_capacity(BATCH);
    let mut events = 0;
    loop {
        let kept = reading.next().await?;
        let last = kept.is_none();
        // What the detector found before is no event to match.
        batch.extend(kept.filter(|kept| kept.source != SOURCE));
        if batch.len() == BATCH || (last && !batch.is_empty()) {
            if *stop.borrow() {
                return Ok(None);
            }
            let rows = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
            let shared = Arc::clone(matcher);
            let (encoded, tally) = tokio::task::spawn_blocking(move || {
                detector::detect_batch(&shared, &rows, threads, detector::detect_kept)
            })
            .await
            .map_err(|error| RunError::Role(format!("matching stored events: {error}")))??;
            events += tally.events;
            metrics.detected(&tally);
            metrics.rematched(tally.events);
            if !encoded.is_empty() {
                findings.send(encoded).await?;
            }
        }
        if last {
            return Ok(Some(events));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::{DISORDER, Range, Unmatched};

    const START: i64 = 1_790_000_000_000;
    const MINUTE: i64 = 60_000;

    #[test]
    fn what_lies_between_the_last_matched_and_the_resumed_is_noted() {
        let directory = tempfile::tempdir().unwrap();
        let mut unmatched = Unmatched::open(directory.path(), START).unwrap();
        assert_eq!((unmatched.first(), unmatched.len()), (None, 0));

        unmatched.matched(START + 10 * MINUTE);
        // Never backwards: records are not in the exact order of receipt.
        unmatched.matched(START + 9 * MINUTE);
        unmatched.skipped(START + 30 * MINUTE);
        assert_eq!(
            unmatched.first(),
            Some(Range {
                from: START + 10 * MINUTE - DISORDER,
                to: START + 30 * MINUTE + DISORDER,
            })
        );

        // Moved again soon after: one range, not two that overlap.
        unmatched.matched(START + 31 * MINUTE);
        unmatched.skipped(START + 40 * MINUTE);
        assert_eq!(unmatched.len(), 1);
        // And again much later: a range of its own.
        unmatched.matched(START + 100 * MINUTE);
        unmatched.skipped(START + 120 * MINUTE);
        assert_eq!(unmatched.len(), 2);
        assert_eq!(
            unmatched.first(),
            Some(Range {
                from: START + 10 * MINUTE - DISORDER,
                to: START + 40 * MINUTE + DISORDER,
            })
        );
    }

    #[test]
    fn a_range_is_given_up_as_it_is_matched_and_a_restart_forgets_none() {
        let directory = tempfile::tempdir().unwrap();
        let mut unmatched = Unmatched::open(directory.path(), START).unwrap();
        unmatched.skipped(START + 5 * MINUTE);
        unmatched.matched(START + 60 * MINUTE);
        unmatched.skipped(START + 90 * MINUTE);
        let first = unmatched.first().unwrap();

        // Matched in part, then the process ends.
        unmatched.matched_from_store(first.from + MINUTE);
        drop(unmatched);
        let mut unmatched = Unmatched::open(directory.path(), START + 999 * MINUTE).unwrap();
        assert_eq!(unmatched.len(), 2);
        assert_eq!(
            unmatched.first(),
            Some(Range {
                from: first.from + MINUTE,
                to: first.to,
            })
        );
        // A detector moved at its first receive after the restart starts
        // the range where it had matched up to, not at the restart.
        unmatched.skipped(START + 300 * MINUTE);
        assert_eq!(unmatched.len(), 2);

        // Matched to the end: the next range is the oldest.
        unmatched.matched_from_store(first.to);
        assert_eq!(unmatched.len(), 1);
        assert_eq!(
            unmatched.first().map(|range| range.from),
            Some(START + 60 * MINUTE - DISORDER)
        );
    }

    #[test]
    fn a_file_that_is_not_the_ranges_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("unmatched.json"), "not json").unwrap();
        let error = Unmatched::open(directory.path(), START).unwrap_err();
        assert!(error.to_string().contains("unmatched.json"), "{error}");
    }
}
