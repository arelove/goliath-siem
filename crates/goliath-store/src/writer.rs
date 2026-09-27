//! Batching outcomes from many sources into few, large inserts.

use std::time::{Duration, Instant};

use goliath_normalize::Envelope;

use crate::batch::{Batch, now};
use crate::error::StoreError;
use crate::store::Store;

/// When a writer flushes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Flush once this many rows are waiting. ClickHouse favours inserts of
    /// thousands of rows or more: every insert creates a part on disk.
    pub max_rows: usize,
    /// Flush once the oldest waiting row has waited this long, so that a
    /// quiet source still reaches storage promptly.
    pub max_delay: Duration,
}

impl Default for Limits {
    /// 50,000 rows or one second, whichever comes first.
    fn default() -> Self {
        Self {
            max_rows: 50_000,
            max_delay: Duration::from_secs(1),
        }
    }
}

/// Collects outcomes from any number of sources and writes them in batches.
///
/// Nothing is acknowledged until it is written: [`flush`](Self::flush)
/// returns only once every waiting row is stored, and a failed flush keeps
/// the rows for the next attempt. A caller acknowledges its input after a
/// successful flush, and so delivers at least once.
#[derive(Debug)]
pub struct Writer {
    store: Store,
    limits: Limits,
    /// One batch per source and definition version, in order of arrival.
    pending: Vec<Batch>,
    rows: usize,
    oldest: Option<Instant>,
}

impl Writer {
    /// A writer to `store`, flushing at `limits`.
    pub fn new(store: Store, limits: Limits) -> Self {
        Self {
            store,
            limits,
            pending: Vec::new(),
            rows: 0,
            oldest: None,
        }
    }

    /// Adds an outcome, as the normalizer role sends it, and flushes if that
    /// fills the writer.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownOutcome`] for an outcome the store has
    /// no table for, and the errors of [`flush`](Self::flush). If the flush
    /// fails, the outcome is already kept: do not push it again.
    pub async fn push(&mut self, envelope: Envelope) -> Result<(), StoreError> {
        self.add(envelope)?;
        if self.is_full() {
            self.flush().await?;
        }
        Ok(())
    }

    /// Adds an outcome without flushing, for a caller that writes what the
    /// writer holds itself, through [`take`](Self::take).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownOutcome`] for an outcome the store has
    /// no table for.
    pub fn add(&mut self, envelope: Envelope) -> Result<(), StoreError> {
        let Envelope {
            source,
            version,
            outcome,
            received,
            ..
        } = envelope;
        // When the platform took the record, as the role that took it said;
        // for envelopes that do not say, when they reached the writer.
        let received = received.unwrap_or_else(now);
        let index = if let Some(index) = self
            .pending
            .iter()
            .position(|batch| batch.is_for(&source, version))
        {
            index
        } else {
            self.pending
                .push(Batch::for_source(&source, version, received));
            self.pending.len() - 1
        };
        self.pending[index].push_received(outcome, received)?;
        self.rows += 1;
        self.oldest.get_or_insert_with(Instant::now);
        Ok(())
    }

    /// Whether the writer holds `max_rows` rows or more.
    pub fn is_full(&self) -> bool {
        self.rows >= self.limits.max_rows
    }

    /// Whether the oldest waiting row has waited `max_delay`.
    pub fn is_due(&self) -> bool {
        self.deadline()
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Hands over every waiting row, in batches to write with
    /// [`Store::write`], leaving the writer empty. Until they are written,
    /// they are the caller's to keep.
    pub fn take(&mut self) -> Vec<Batch> {
        self.rows = 0;
        self.oldest = None;
        std::mem::take(&mut self.pending)
    }

    /// Adds the rows of `batches`, as another writer's [`take`](Self::take)
    /// handed them over, after those already waiting. Lets several threads
    /// turn outcomes into rows at once, each with a writer of its own.
    pub fn absorb(&mut self, batches: Vec<Batch>) {
        for batch in batches {
            if batch.is_empty() {
                continue;
            }
            self.rows += batch.events() + batch.dead_letters();
            self.oldest.get_or_insert_with(Instant::now);
            if let Some(waiting) = self
                .pending
                .iter_mut()
                .find(|waiting| waiting.is_for(&batch.source, batch.source_version))
            {
                waiting.append(batch);
            } else {
                self.pending.push(batch);
            }
        }
    }

    /// When the waiting rows must be written by, if any wait.
    pub fn deadline(&self) -> Option<Instant> {
        self.oldest.map(|oldest| oldest + self.limits.max_delay)
    }

    /// Flushes if the oldest waiting row has waited `max_delay`. Meant to be
    /// called when [`deadline`](Self::deadline) passes.
    ///
    /// # Errors
    ///
    /// The errors of [`flush`](Self::flush).
    pub async fn flush_if_due(&mut self) -> Result<(), StoreError> {
        if self.is_due() {
            self.flush().await
        } else {
            Ok(())
        }
    }

    /// Writes every waiting row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a write fails. Batches written
    /// before the failure are not kept; the failed batch and those after it
    /// are, for the next flush. Writing a batch again is safe, since events
    /// are deduplicated by identity.
    pub async fn flush(&mut self) -> Result<(), StoreError> {
        while let Some(batch) = self.pending.first() {
            self.store.write(batch).await?;
            let written = self.pending.remove(0);
            self.rows -= written.events() + written.dead_letters();
        }
        self.oldest = None;
        Ok(())
    }

    /// How many rows wait to be written.
    pub fn waiting(&self) -> usize {
        self.rows
    }
}
