//! Transport between the roles of the Goliath security platform.
//!
//! Every hop between roles goes through a topic. Every implementation keeps
//! the same contract, set out in `docs/adr/0015-pipe-semantics.md`:
//!
//! - records are opaque bytes, delivered in the order they were sent, each
//!   with an offset that increases by one;
//! - each reading role reads under a group of its own, at its own pace;
//! - a group acknowledges what it has handled, and after a restart receives
//!   again everything it had not acknowledged: delivery is at least once;
//! - a topic holds a bounded amount, and sending waits while it is full.
//!
//! # Example
//!
//! ```
//! use std::num::NonZeroUsize;
//! use std::time::Duration;
//!
//! use goliath_pipe::{MemoryTopic, Receiver, Sender};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # tokio::runtime::Builder::new_current_thread().enable_time().build()?.block_on(async {
//! let topic = MemoryTopic::new(NonZeroUsize::new(1024).ok_or("zero")?);
//! let mut writer = topic.subscribe("writer");
//! let mut detector = topic.subscribe("detector");
//!
//! topic.sender().send(vec![b"one".to_vec(), b"two".to_vec()]).await?;
//!
//! // Each group reads everything, independently.
//! let batch = writer.receive(10, Duration::from_millis(10)).await?;
//! assert_eq!(batch.len(), 2);
//! writer.acknowledge(batch[1].offset).await?;
//! assert_eq!(detector.receive(10, Duration::from_millis(10)).await?.len(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # })
//! # }
//! ```

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use std::future::Future;
use std::time::Duration;

mod disk;
mod memory;

pub use disk::{DiskOptions, DiskReceiver, DiskSender, DiskTopic};
pub use memory::{MemoryReceiver, MemorySender, MemoryTopic};

/// A record as a group receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The record's position in its topic.
    pub offset: u64,
    /// The record.
    pub payload: Vec<u8>,
}

/// Why a pipe operation failed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipeError {
    /// A group acknowledged an offset it has not received.
    #[error("offset {offset} was acknowledged but only offsets below {received} were received")]
    NotReceived {
        /// The offset acknowledged.
        offset: u64,
        /// The first offset not yet received.
        received: u64,
    },
    /// The group was removed from its topic while a receiver still used it.
    #[error("group `{0}` no longer reads this topic")]
    Unsubscribed(String),
    /// A group name that cannot name a file: use letters, digits, `-`, and
    /// `_`.
    #[error("`{0}` is not a valid group name: use letters, digits, `-`, and `_`")]
    GroupName(String),
    /// A durable topic could not read or write its files, or found them
    /// damaged.
    #[error("{0}")]
    Io(String),
}

impl From<std::io::Error> for PipeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Sends records to a topic.
pub trait Sender {
    /// Appends `payloads` to the topic, in order, waiting while the topic is
    /// full.
    ///
    /// A batch larger than the topic's bound is accepted once the topic is
    /// empty, so that no batch waits forever.
    fn send(&self, payloads: Vec<Vec<u8>>) -> impl Future<Output = Result<(), PipeError>> + Send;
}

/// Reads a topic as one consumer group.
pub trait Receiver {
    /// The next records for this group, at most `max`, waiting up to `wait`
    /// for the first one. Returns an empty batch if none arrived in time.
    ///
    /// Records are delivered once per receiver; acknowledging is what makes
    /// that permanent for the group.
    fn receive(
        &mut self,
        max: usize,
        wait: Duration,
    ) -> impl Future<Output = Result<Vec<Delivery>, PipeError>> + Send;

    /// Records that everything up to and including `offset` is handled, so
    /// the group will not receive it again after a restart.
    fn acknowledge(&mut self, offset: u64) -> impl Future<Output = Result<(), PipeError>> + Send;
}
