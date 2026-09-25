//! The pipe contract of `docs/adr/0015-pipe-semantics.md`, as tests every
//! implementation must pass unchanged.
//!
//! An implementation provides a [`Fixture`] and invokes [`contract!`], which
//! generates one test per clause. Tests of what only one implementation does,
//! such as surviving a restart on disk, stay beside it.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, dead_code)]

use std::collections::HashSet;
use std::time::Duration;

use goliath_pipe::{Delivery, PipeError, Receiver, Sender};

pub(crate) const SHORT: Duration = Duration::from_millis(50);
pub(crate) const LONG: Duration = Duration::from_secs(10);

/// One empty topic of an implementation under test.
pub(crate) trait Fixture: Send + Sync + 'static {
    /// Sends to the topic.
    type Sender: Sender + Clone + Send + Sync + 'static;
    /// Reads the topic as one group.
    type Receiver: Receiver + Send + 'static;

    /// A fresh topic that holds `records` records of at most 8 bytes before
    /// sending waits.
    fn create(records: usize) -> impl Future<Output = Self> + Send;
    /// A sender.
    fn sender(&self) -> Self::Sender;
    /// A receiver for `group`.
    fn subscribe(&self, group: &str) -> impl Future<Output = Self::Receiver> + Send;
    /// Removes `group`.
    fn unsubscribe(&self, group: &str) -> impl Future<Output = ()> + Send;
}

pub(crate) fn records(texts: &[&str]) -> Vec<Vec<u8>> {
    texts.iter().map(|text| text.as_bytes().to_vec()).collect()
}

pub(crate) fn payloads(batch: &[Delivery]) -> Vec<&[u8]> {
    batch
        .iter()
        .map(|delivery| delivery.payload.as_slice())
        .collect()
}

/// Receives until `count` records arrived, since an implementation may hand
/// them out in several batches.
pub(crate) async fn receive_all<R: Receiver>(receiver: &mut R, count: usize) -> Vec<Delivery> {
    let mut all = Vec::new();
    while all.len() < count {
        let batch = receiver.receive(count - all.len(), LONG).await.unwrap();
        assert!(
            !batch.is_empty(),
            "stalled after {} of {count} records",
            all.len()
        );
        all.extend(batch);
    }
    all
}

pub(crate) async fn records_arrive_in_order_with_consecutive_offsets<F: Fixture>() {
    let topic = F::create(100).await;
    let mut group = topic.subscribe("writer").await;
    topic.sender().send(records(&["a", "b"])).await.unwrap();
    topic.sender().send(records(&["c"])).await.unwrap();

    let batch = receive_all(&mut group, 3).await;
    assert_eq!(payloads(&batch), [b"a", b"b", b"c"]);
    let first = batch[0].offset;
    assert_eq!(
        batch
            .iter()
            .map(|delivery| delivery.offset)
            .collect::<Vec<_>>(),
        [first, first + 1, first + 2]
    );
    // Delivered once per receiver.
    assert!(group.receive(10, SHORT).await.unwrap().is_empty());
}

pub(crate) async fn receive_honours_its_maximum<F: Fixture>() {
    let topic = F::create(100).await;
    let mut group = topic.subscribe("writer").await;
    topic
        .sender()
        .send(records(&["a", "b", "c"]))
        .await
        .unwrap();
    let mut seen = Vec::new();
    while seen.len() < 3 {
        let batch = group.receive(2, LONG).await.unwrap();
        assert!(!batch.is_empty() && batch.len() <= 2, "{}", batch.len());
        seen.extend(batch);
    }
    assert_eq!(payloads(&seen), [b"a", b"b", b"c"]);
}

pub(crate) async fn groups_read_independently<F: Fixture>() {
    let topic = F::create(100).await;
    let mut writer = topic.subscribe("writer").await;
    let mut detector = topic.subscribe("detector").await;
    topic.sender().send(records(&["a", "b"])).await.unwrap();

    let batch = receive_all(&mut writer, 2).await;
    writer.acknowledge(batch[1].offset).await.unwrap();
    assert_eq!(payloads(&receive_all(&mut detector, 2).await), [b"a", b"b"]);
}

pub(crate) async fn a_group_that_restarts_receives_what_it_had_not_acknowledged<F: Fixture>() {
    let topic = F::create(100).await;
    let mut group = topic.subscribe("writer").await;
    topic
        .sender()
        .send(records(&["a", "b", "c"]))
        .await
        .unwrap();
    let batch = receive_all(&mut group, 3).await;
    group.acknowledge(batch[0].offset).await.unwrap();
    drop(group);

    let mut again = topic.subscribe("writer").await;
    let batch = receive_all(&mut again, 2).await;
    assert_eq!(payloads(&batch), [b"b", b"c"]);
}

pub(crate) async fn a_new_group_starts_at_the_end<F: Fixture>() {
    let topic = F::create(100).await;
    let _writer = topic.subscribe("writer").await;
    topic.sender().send(records(&["old"])).await.unwrap();
    let mut late = topic.subscribe("late").await;
    topic.sender().send(records(&["new"])).await.unwrap();
    assert_eq!(payloads(&receive_all(&mut late, 1).await), [b"new"]);
}

pub(crate) async fn a_full_topic_makes_senders_wait_until_records_are_acknowledged<F: Fixture>() {
    let topic = F::create(2).await;
    let mut group = topic.subscribe("writer").await;
    topic.sender().send(records(&["a", "b"])).await.unwrap();

    let sender = topic.sender();
    let waiting = tokio::spawn(async move { sender.send(records(&["c"])).await });
    tokio::time::sleep(SHORT * 4).await;
    assert!(
        !waiting.is_finished(),
        "the topic is full, so sending must wait"
    );

    let batch = receive_all(&mut group, 2).await;
    group.acknowledge(batch[0].offset).await.unwrap();
    tokio::time::timeout(LONG, waiting)
        .await
        .expect("acknowledging makes room")
        .unwrap()
        .unwrap();
    assert_eq!(payloads(&receive_all(&mut group, 1).await), [b"c"]);
}

pub(crate) async fn a_batch_larger_than_the_bound_waits_for_an_empty_topic_only<F: Fixture>() {
    let topic = F::create(2).await;
    let mut group = topic.subscribe("writer").await;
    tokio::time::timeout(LONG, topic.sender().send(records(&["a", "b", "c"])))
        .await
        .expect("an oversize batch into an empty topic is accepted")
        .unwrap();
    assert_eq!(receive_all(&mut group, 3).await.len(), 3);
}

pub(crate) async fn a_waiting_receiver_wakes_when_records_arrive<F: Fixture>() {
    let topic = F::create(10).await;
    let mut group = topic.subscribe("writer").await;
    let reading = tokio::spawn(async move { group.receive(10, LONG).await });
    tokio::time::sleep(SHORT).await;
    topic.sender().send(records(&["a"])).await.unwrap();
    let batch = tokio::time::timeout(LONG, reading)
        .await
        .expect("the receiver wakes")
        .unwrap()
        .unwrap();
    assert_eq!(payloads(&batch), [b"a"]);
}

pub(crate) async fn acknowledging_what_was_not_received_is_refused<F: Fixture>() {
    let topic = F::create(10).await;
    let mut group = topic.subscribe("writer").await;
    topic.sender().send(records(&["a"])).await.unwrap();
    assert!(matches!(
        group.acknowledge(u64::MAX - 1).await,
        Err(PipeError::NotReceived { .. })
    ));
}

pub(crate) async fn an_unsubscribed_group_s_receivers_fail<F: Fixture>() {
    let topic = F::create(10).await;
    let _writer = topic.subscribe("writer").await;
    let mut gone = topic.subscribe("gone").await;
    topic.unsubscribe("gone").await;
    assert_eq!(
        gone.receive(10, SHORT).await,
        Err(PipeError::Unsubscribed("gone".to_owned()))
    );
}

pub(crate) async fn many_senders_lose_nothing<F: Fixture>() {
    let topic = F::create(64).await;
    let mut group = topic.subscribe("writer").await;
    let mut senders = Vec::new();
    for sender_index in 0..4u32 {
        let sender = topic.sender();
        senders.push(tokio::spawn(async move {
            for record in 0..250u32 {
                sender
                    .send(vec![format!("{sender_index}:{record}").into_bytes()])
                    .await
                    .unwrap();
            }
        }));
    }
    let mut seen = HashSet::new();
    let mut last: Option<u64> = None;
    while seen.len() < 1000 {
        let batch = group.receive(100, LONG).await.unwrap();
        assert!(!batch.is_empty(), "stalled at {} records", seen.len());
        for delivery in &batch {
            if let Some(last) = last {
                assert_eq!(delivery.offset, last + 1);
            }
            last = Some(delivery.offset);
            assert!(seen.insert(delivery.payload.clone()), "delivered twice");
        }
        group.acknowledge(last.unwrap()).await.unwrap();
    }
    for sender in senders {
        sender.await.unwrap();
    }
}

/// One test per clause of the contract, for the fixture `$fixture`.
#[macro_export]
macro_rules! contract {
    ($fixture:ty) => {
        $crate::contract!(@tests $fixture;
            records_arrive_in_order_with_consecutive_offsets,
            receive_honours_its_maximum,
            groups_read_independently,
            a_group_that_restarts_receives_what_it_had_not_acknowledged,
            a_new_group_starts_at_the_end,
            a_full_topic_makes_senders_wait_until_records_are_acknowledged,
            a_batch_larger_than_the_bound_waits_for_an_empty_topic_only,
            a_waiting_receiver_wakes_when_records_arrive,
            acknowledging_what_was_not_received_is_refused,
            an_unsubscribed_group_s_receivers_fail,
            many_senders_lose_nothing,
        );
    };
    (@tests $fixture:ty; $($name:ident),* $(,)?) => {
        mod contract_tests {
            use super::*;
            $(
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn $name() {
                    contract::$name::<$fixture>().await;
                }
            )*
        }
    };
}
