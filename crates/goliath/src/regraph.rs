//! Reading, from the store, the events whose links the graph role did not
//! read from the stream.
//!
//! Two kinds of events are stored and not in the graph: those stored before
//! the role first ran, and those it was moved past when it fell further
//! behind than the topic keeps (`docs/adr/0015-pipe-semantics.md`). The
//! role notes the ranges of receipt time they lie in, in a file, and this
//! reads each range back from the event store and sends on what its events
//! show, as the role does for the stream.
//!
//! An event read twice, here and from the stream, is counted twice in the
//! rows it gives. Nothing else about a link or a claim changes by that; see
//! `docs/adr/0025-entity-graph.md`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use goliath_pipe::Sender;
use goliath_store::Store;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::RunError;
use crate::graph;
use crate::metrics::Metrics;
use crate::roles::BATCH;

/// How far the order of records in the topic may differ from the order the
/// platform took them in, in milliseconds; a range is widened by this much
/// at both ends, as the detector's are.
const DISORDER: i64 = 60_000;
/// The receipt time read from the store at once, in milliseconds. A range
/// is given up to here after each, so a restart goes on from there.
const WINDOW: i64 = 3_600_000;
/// How long after a time the writer is taken to have stored everything the
/// platform took before it, in milliseconds, where no later event says so.
const SETTLED: i64 = 600_000;
/// How often the ranges are looked at, and how soon a read that failed is
/// tried again.
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// How often the time read up to is written down.
const SAVE_EVERY: Duration = Duration::from_secs(10);
const DAY: i64 = 86_400_000;

/// Receipt times from `from` up to and not including `to`, in milliseconds
/// since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Range {
    pub(crate) from: i64,
    pub(crate) to: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Noted {
    /// The role read from the stream what the platform took up to here.
    read_until: i64,
    /// What was stored and not read, the oldest first.
    ranges: Vec<Range>,
    /// Whether what was stored before the role first ran was asked for.
    #[serde(default)]
    asked_for_stored: bool,
}

/// The ranges of receipt time whose events are stored and not in the
/// graph, kept in a file so that a restart forgets none.
#[derive(Debug)]
pub(crate) struct Unread {
    file: PathBuf,
    noted: Noted,
    saved: Instant,
}

/// The ranges, shared by the role, which notes them, and the task that
/// reads them.
pub(crate) type Shared = Arc<Mutex<Unread>>;

/// The ranges, whatever became of a thread that held them: each change
/// leaves them whole.
pub(crate) fn lock(shared: &Shared) -> MutexGuard<'_, Unread> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Unread {
    /// Opens the ranges noted in `state`. A role that starts for the first
    /// time has read nothing from the stream: its ranges begin at `now`,
    /// and what was stored before is still to be asked for.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Io`] if the file is there and cannot be read.
    pub(crate) fn open(state: &Path, now: i64) -> Result<Self, RunError> {
        let file = state.join("unread.json");
        let noted = match std::fs::read(&file) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| RunError::Io(format!("{}: {error}", file.display())))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Noted {
                read_until: now,
                ..Noted::default()
            },
            Err(error) => return Err(RunError::Io(format!("{}: {error}", file.display()))),
        };
        let mut unread = Self {
            file,
            noted,
            saved: Instant::now(),
        };
        unread.save();
        Ok(unread)
    }

    /// The role read records the platform took up to `received`.
    pub(crate) fn read(&mut self, received: i64) {
        self.noted.read_until = self.noted.read_until.max(received);
        if self.saved.elapsed() >= SAVE_EVERY {
            self.save();
        }
    }

    /// The role was moved past records, to one the platform took at
    /// `resumed`: what lies between the last it read and that one is
    /// noted, widened by [`DISORDER`].
    pub(crate) fn skipped(&mut self, resumed: i64) {
        let from = self.noted.read_until.min(resumed) - DISORDER;
        self.note(Range {
            from,
            to: resumed + DISORDER,
        });
    }

    fn note(&mut self, range: Range) {
        self.noted.ranges.push(range);
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

    /// Whether what was stored before the role first ran is still to be
    /// asked for.
    pub(crate) fn asks_for_stored(&self) -> bool {
        !self.noted.asked_for_stored
    }

    /// What was stored before the role first ran begins at `first`, if
    /// anything was: it is noted from there, or from `days` before now if
    /// that is later, up to where the role began to read the stream.
    pub(crate) fn stored_from(&mut self, first: Option<i64>, days: Option<u16>, now: i64) {
        self.noted.asked_for_stored = true;
        let to = self.noted.read_until;
        let from = first.map(|first| match days {
            Some(days) => first.max(now - i64::from(days) * DAY),
            None => first,
        });
        match from {
            Some(from) if from < to && days != Some(0) => self.note(Range { from, to }),
            _ => self.save(),
        }
    }

    /// The oldest range to read.
    pub(crate) fn first(&self) -> Option<Range> {
        self.noted.ranges.first().copied()
    }

    /// How many ranges wait.
    pub(crate) fn len(&self) -> usize {
        self.noted.ranges.len()
    }

    /// The oldest range was read up to `until`.
    pub(crate) fn read_from_store(&mut self, until: i64) {
        if let Some(first) = self.noted.ranges.first_mut() {
            first.from = first.from.max(until);
            if first.from >= first.to {
                self.noted.ranges.remove(0);
            }
        }
        self.save();
    }

    /// Writes the ranges down. A failure is reported and tried again at the
    /// next change: the ranges in memory are still read.
    pub(crate) fn save(&mut self) {
        self.saved = Instant::now();
        let written = serde_json::to_vec(&self.noted)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                crate::fetch::publish(&self.file, &bytes).map_err(|error| error.to_string())
            });
        if let Err(error) = written {
            warn!(file = %self.file.display(), error, "unread ranges not written down");
        }
    }
}

/// Reads each noted range from the store once the writer is past it, and
/// sends on what its events show, until stopped. At its first run it asks
/// the store where what it holds begins, and notes that too, `days` back at
/// most. While the store is unavailable it tries again, and the ranges
/// wait.
pub(crate) async fn read_back(
    store: Store,
    unread: Shared,
    days: Option<u16>,
    graphed: impl Sender + Sync,
    metrics: Metrics,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    while !*stop.borrow_and_update() {
        if lock(&unread).asks_for_stored() {
            match store.first_received().await {
                Ok(first) => {
                    let mut unread = lock(&unread);
                    unread.stored_from(first, days, crate::raw::now());
                    if let Some(range) = unread.first() {
                        info!(
                            from = range.from,
                            to = range.to,
                            "what was stored before the graph role ran is read into the graph"
                        );
                    }
                }
                Err(error) => warn!(%error, "store not asked where it begins; trying again"),
            }
        }
        let first = {
            let unread = lock(&unread);
            metrics.graph_unread_ranges(unread.len());
            unread.first()
        };
        if let Some(range) = first {
            let until = range.to.min(range.from.saturating_add(WINDOW));
            // An event taken after the window is stored, or long enough has
            // passed: so is the window.
            let settled = crate::raw::now() - until > SETTLED;
            match store.holds_received_from(until).await {
                Ok(later) if later || settled => {
                    match read(&store, range.from, until, &graphed, &metrics, &stop).await {
                        Ok(Some(events)) => {
                            if events > 0 {
                                info!(from = range.from, until, events, "read from the store");
                            }
                            lock(&unread).read_from_store(until);
                            continue;
                        }
                        // Stopped before the end: the window is read again.
                        Ok(None) => continue,
                        Err(RunError::Store(error)) => {
                            warn!(%error, "stored events not read; trying again");
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "store not asked; trying again"),
            }
        }
        tokio::select! {
            () = tokio::time::sleep(CHECK_EVERY) => {}
            _ = stop.changed() => {}
        }
    }
    lock(&unread).save();
    Ok(())
}

/// Sends on what the stored events the platform took from `from` up to
/// `until` show, and returns how many they were, or `None` if stopped
/// before the last.
async fn read(
    store: &Store,
    from: i64,
    until: i64,
    graphed: &(impl Sender + Sync),
    metrics: &Metrics,
    stop: &watch::Receiver<bool>,
) -> Result<Option<u64>, RunError> {
    let mut reading = store.received_between(from, until)?;
    let mut batch = Vec::with_capacity(BATCH);
    let mut events = 0;
    loop {
        let kept = reading.next().await?;
        let last = kept.is_none();
        // What the detector found is no event of a source.
        batch.extend(kept.filter(|kept| kept.source != crate::detector::SOURCE));
        if batch.len() == BATCH || (last && !batch.is_empty()) {
            if *stop.borrow() {
                return Ok(None);
            }
            let rows = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
            let (seen, tally) = tokio::task::spawn_blocking(move || graph::gather_kept(&rows))
                .await
                .map_err(|error| RunError::Role(format!("reading stored events: {error}")))?;
            events += tally.events;
            metrics.graphed(&tally, seen.links.len(), seen.claims.len());
            metrics.graph_read_back(tally.events);
            if !seen.links.is_empty() || !seen.claims.is_empty() {
                let encoded = serde_json::to_vec(&seen)
                    .map_err(|error| RunError::Role(format!("encoding the graph: {error}")))?;
                graphed.send(vec![encoded]).await?;
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

    use super::{DAY, DISORDER, Range, Unread};

    const START: i64 = 1_790_000_000_000;
    const MINUTE: i64 = 60_000;

    #[test]
    fn what_was_stored_before_the_first_run_is_noted_once() {
        let directory = tempfile::tempdir().unwrap();
        let mut unread = Unread::open(directory.path(), START).unwrap();
        assert!(unread.asks_for_stored());
        assert_eq!(unread.first(), None);

        // The store begins three days before; all of it is noted, up to
        // where the stream is read from.
        unread.stored_from(Some(START - 3 * DAY), None, START);
        assert!(!unread.asks_for_stored());
        assert_eq!(
            unread.first(),
            Some(Range {
                from: START - 3 * DAY,
                to: START
            })
        );
        // It is given up window by window, and a restart goes on from there.
        unread.read_from_store(START - 2 * DAY);
        let again = Unread::open(directory.path(), START + DAY).unwrap();
        assert!(!again.asks_for_stored());
        assert_eq!(
            again.first(),
            Some(Range {
                from: START - 2 * DAY,
                to: START
            })
        );
    }

    #[test]
    fn how_far_back_is_bounded_by_days_and_an_empty_store_gives_nothing() {
        let open = || {
            let directory = tempfile::tempdir().unwrap();
            Unread::open(directory.path(), START).unwrap()
        };
        let mut bounded = open();
        bounded.stored_from(Some(START - 30 * DAY), Some(7), START);
        assert_eq!(bounded.first().unwrap().from, START - 7 * DAY);
        let mut none = open();
        none.stored_from(Some(START - 30 * DAY), Some(0), START);
        assert_eq!((none.first(), none.asks_for_stored()), (None, false));
        let mut empty = open();
        empty.stored_from(None, None, START);
        assert_eq!((empty.first(), empty.asks_for_stored()), (None, false));
        // A store that begins after the role did holds nothing to read.
        let mut later = open();
        later.stored_from(Some(START + MINUTE), None, START + 2 * MINUTE);
        assert_eq!(later.first(), None);
    }

    #[test]
    fn what_the_role_was_moved_past_is_noted_between_what_it_read() {
        let directory = tempfile::tempdir().unwrap();
        let mut unread = Unread::open(directory.path(), START).unwrap();
        unread.stored_from(None, None, START);
        unread.read(START + 10 * MINUTE);
        // Never backwards: records are not in the exact order of receipt.
        unread.read(START + 9 * MINUTE);
        unread.skipped(START + 30 * MINUTE);
        assert_eq!(
            unread.first(),
            Some(Range {
                from: START + 10 * MINUTE - DISORDER,
                to: START + 30 * MINUTE + DISORDER
            })
        );
        // Ranges that touch are one.
        unread.read(START + 31 * MINUTE);
        unread.skipped(START + 40 * MINUTE);
        assert_eq!(unread.len(), 1);
        assert_eq!(unread.first().unwrap().to, START + 40 * MINUTE + DISORDER);
        unread.read_from_store(START + 41 * MINUTE);
        assert_eq!((unread.first(), unread.len()), (None, 0));
    }
}
