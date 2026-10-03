//! The memory topic: the shared contract, and when it releases memory.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod contract;

use std::future::ready;
use std::num::NonZeroUsize;

use contract::{Fixture, SHORT, receive_all, records};
use goliath_pipe::{MemoryReceiver, MemorySender, MemoryTopic, Receiver, Sender};

struct Memory(MemoryTopic);

// Nothing here waits; the trait is asynchronous for implementations whose
// topics live on a server.
impl Fixture for Memory {
    type Sender = MemorySender;
    type Receiver = MemoryReceiver;

    fn create(records: usize) -> impl Future<Output = Self> + Send {
        ready(Self(MemoryTopic::new(NonZeroUsize::new(records).unwrap())))
    }

    fn sender(&self) -> MemorySender {
        self.0.sender()
    }

    fn subscribe(&self, group: &str) -> impl Future<Output = MemoryReceiver> + Send {
        ready(self.0.subscribe(group))
    }

    fn observe(&self, group: &str) -> impl Future<Output = MemoryReceiver> + Send {
        ready(self.0.observe(group))
    }

    fn unsubscribe(&self, group: &str) -> impl Future<Output = ()> + Send {
        self.0.unsubscribe(group);
        ready(())
    }
}

contract!(Memory);

#[tokio::test]
async fn records_are_released_once_every_group_acknowledged_them() {
    let topic = MemoryTopic::new(NonZeroUsize::new(100).unwrap());
    let mut writer = topic.subscribe("writer");
    let mut detector = topic.subscribe("detector");
    topic.sender().send(records(&["a", "b"])).await.unwrap();

    let batch = receive_all(&mut writer, 2).await;
    writer.acknowledge(batch[1].offset).await.unwrap();
    assert_eq!(topic.len(), 2, "the detector still needs them");
    let batch = receive_all(&mut detector, 2).await;
    detector.acknowledge(batch[1].offset).await.unwrap();
    assert!(topic.is_empty());
}

#[tokio::test]
async fn unsubscribing_releases_what_only_that_group_held() {
    let topic = MemoryTopic::new(NonZeroUsize::new(10).unwrap());
    let mut writer = topic.subscribe("writer");
    let _gone = topic.subscribe("gone");
    topic.sender().send(records(&["a"])).await.unwrap();
    let batch = receive_all(&mut writer, 1).await;
    writer.acknowledge(batch[0].offset).await.unwrap();
    assert_eq!(topic.len(), 1);
    topic.unsubscribe("gone");
    assert!(topic.is_empty());
    assert!(writer.receive(10, SHORT).await.unwrap().is_empty());
}

#[tokio::test]
async fn an_observer_is_kept_the_bound_and_no_more() {
    let topic = MemoryTopic::new(NonZeroUsize::new(4).unwrap());
    let mut writer = topic.subscribe("writer");
    let mut observer = topic.observe("observer");
    let sender = topic.sender();
    for _ in 0..3 {
        sender.send(records(&["a", "b", "c", "d"])).await.unwrap();
        let batch = receive_all(&mut writer, 4).await;
        writer.acknowledge(batch[3].offset).await.unwrap();
        // Everything the writer acknowledged, kept for the observer, up to
        // the bound.
        assert_eq!(topic.len(), 4);
    }
    // Of 12 records the newest 4 are kept, and it missed the 8 before.
    let batch = receive_all(&mut observer, 4).await;
    assert_eq!(batch[0].offset, 8);
    assert_eq!(observer.skipped(), 8);
    observer.acknowledge(batch[3].offset).await.unwrap();
    assert!(topic.is_empty());

    // Subscribed again as a group that holds the topic, senders wait for it.
    let _holding = topic.subscribe("observer");
    sender.send(records(&["a", "b", "c", "d"])).await.unwrap();
    let batch = receive_all(&mut writer, 4).await;
    writer.acknowledge(batch[3].offset).await.unwrap();
    let blocked = tokio::time::timeout(SHORT, sender.send(records(&["e"]))).await;
    assert!(
        blocked.is_err(),
        "the topic is full of what it has not read"
    );
}
