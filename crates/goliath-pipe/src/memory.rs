//! A topic in memory, for roles in one process.
//!
//! It keeps the whole contract except durability: what it holds is lost when
//! the process ends. See `docs/adr/0015-pipe-semantics.md` for where that is
//! acceptable.

use std::collections::{BTreeMap, VecDeque};
use std::future::{self, Future};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::{Delivery, PipeError, Receiver, Sender};

/// A topic held in memory, bounded to a number of records.
///
/// Cheap to clone; clones are the same topic.
#[derive(Debug, Clone)]
pub struct MemoryTopic {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    /// Woken when records arrive.
    arrived: Notify,
    /// Woken when records are released.
    released: Notify,
}

#[derive(Debug)]
struct State {
    /// The offset of `records[0]`.
    base: u64,
    records: VecDeque<Vec<u8>>,
    capacity: usize,
    /// Each group's first unacknowledged offset.
    groups: BTreeMap<String, u64>,
}

impl State {
    /// The offset the next record will get.
    fn end(&self) -> u64 {
        self.base + self.records.len() as u64
    }

    /// Releases records every group has acknowledged. Returns whether any
    /// were released.
    fn release(&mut self) -> bool {
        let floor = self.groups.values().copied().min().unwrap_or(self.base);
        let mut released = false;
        while self.base < floor && self.records.pop_front().is_some() {
            self.base += 1;
            released = true;
        }
        released
    }
}

impl MemoryTopic {
    /// An empty topic holding at most `capacity` records.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    base: 0,
                    records: VecDeque::new(),
                    capacity: capacity.get(),
                    groups: BTreeMap::new(),
                }),
                arrived: Notify::new(),
                released: Notify::new(),
            }),
        }
    }

    /// A sender to this topic.
    pub fn sender(&self) -> MemorySender {
        MemorySender {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A receiver for `group`. A new group starts at the end of the topic:
    /// it receives what is sent from now on. A known group resumes at its
    /// first unacknowledged record.
    ///
    /// Groups must subscribe before records they need are sent. While no
    /// group reads a topic, nothing is released, and sending waits once the
    /// topic is full.
    pub fn subscribe(&self, group: &str) -> MemoryReceiver {
        let mut state = lock(&self.shared.state);
        let end = state.end();
        let position = *state.groups.entry(group.to_owned()).or_insert(end);
        MemoryReceiver {
            shared: Arc::clone(&self.shared),
            group: group.to_owned(),
            next: position,
        }
    }

    /// Removes `group`, releasing what only it held. Its receivers fail from
    /// then on.
    pub fn unsubscribe(&self, group: &str) {
        let mut state = lock(&self.shared.state);
        state.groups.remove(group);
        if state.release() {
            self.shared.released.notify_waiters();
        }
    }

    /// How many records the topic holds.
    pub fn len(&self) -> usize {
        lock(&self.shared.state).records.len()
    }

    /// Whether the topic holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Sends to a [`MemoryTopic`].
#[derive(Debug, Clone)]
pub struct MemorySender {
    shared: Arc<Shared>,
}

impl Sender for MemorySender {
    async fn send(&self, payloads: Vec<Vec<u8>>) -> Result<(), PipeError> {
        if payloads.is_empty() {
            return Ok(());
        }
        loop {
            // Registered before the check, so a release between the check
            // and the wait is not missed.
            let released = self.shared.released.notified();
            {
                let mut state = lock(&self.shared.state);
                if state.records.is_empty()
                    || state.records.len() + payloads.len() <= state.capacity
                {
                    state.records.extend(payloads);
                    drop(state);
                    self.shared.arrived.notify_waiters();
                    return Ok(());
                }
            }
            released.await;
        }
    }
}

/// Reads a [`MemoryTopic`] as one group.
#[derive(Debug)]
pub struct MemoryReceiver {
    shared: Arc<Shared>,
    group: String,
    /// The next offset to deliver to this receiver.
    next: u64,
}

impl Receiver for MemoryReceiver {
    async fn receive(&mut self, max: usize, wait: Duration) -> Result<Vec<Delivery>, PipeError> {
        let deadline = Instant::now() + wait;
        loop {
            let arrived = self.shared.arrived.notified();
            {
                let state = lock(&self.shared.state);
                if !state.groups.contains_key(&self.group) {
                    return Err(PipeError::Unsubscribed(self.group.clone()));
                }
                // Records below `base` were acknowledged by this group, so
                // this receiver has nothing to redeliver from there.
                let from = self.next.max(state.base);
                if from < state.end() || max == 0 {
                    let skip = usize::try_from(from - state.base).unwrap_or(usize::MAX);
                    let batch: Vec<Delivery> = state
                        .records
                        .iter()
                        .skip(skip)
                        .take(max)
                        .zip(from..)
                        .map(|(payload, offset)| Delivery {
                            offset,
                            payload: payload.clone(),
                        })
                        .collect();
                    self.next = from + batch.len() as u64;
                    return Ok(batch);
                }
            }
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                return Ok(Vec::new());
            }
        }
    }

    fn acknowledge(&mut self, offset: u64) -> impl Future<Output = Result<(), PipeError>> + Send {
        // Nothing here waits; the trait is asynchronous for durable
        // implementations, which write the position before returning.
        future::ready(self.acknowledge_now(offset))
    }
}

impl MemoryReceiver {
    fn acknowledge_now(&mut self, offset: u64) -> Result<(), PipeError> {
        if offset >= self.next {
            return Err(PipeError::NotReceived {
                offset,
                received: self.next,
            });
        }
        let mut state = lock(&self.shared.state);
        let Some(position) = state.groups.get_mut(&self.group) else {
            return Err(PipeError::Unsubscribed(self.group.clone()));
        };
        *position = (*position).max(offset + 1);
        if state.release() {
            drop(state);
            self.shared.released.notify_waiters();
        }
        Ok(())
    }
}

/// Locks the state. A panic while holding the lock cannot leave it
/// inconsistent: every change is a single push, pop, or assignment.
fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}
