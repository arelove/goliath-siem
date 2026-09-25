//! The pipe contract, on the memory topic.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::num::NonZeroUsize;
use std::time::Duration;

use goliath_pipe::{Delivery, MemoryTopic, PipeError, Receiver, Sender};

const SHORT: Duration = Duration::from_millis(20);

fn topic(capacity: usize) -> MemoryTopic {
    MemoryTopic::new(NonZeroUsize::new(capacity).unwrap())
}

fn records(texts: &[&str]) -> Vec<Vec<u8>> {
    texts.iter().map(|text| text.as_bytes().to_vec()).collect()
}

fn payloads(batch: &[Delivery]) -> Vec<&[u8]> {
    batch
        .iter()
        .map(|delivery| delivery.payload.as_slice())
        .collect()
}

#[tokio::test]
async fn records_arrive_in_order_with_consecutive_offsets() {
    let topic = topic(100);
    let mut group = topic.subscribe("writer");
    topic.sender().send(records(&["a", "b"])).await.unwrap();
    topic.sender().send(records(&["c"])).await.unwrap();

    let batch = group.receive(10, SHORT).await.unwrap();
    assert_eq!(payloads(&batch), [b"a", b"b", b"c"]);
    assert_eq!(
        batch
            .iter()
            .map(|delivery| delivery.offset)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    // Delivered once per receiver.
    assert!(group.receive(10, SHORT).await.unwrap().is_empty());
}

#[tokio::test]
async fn receive_honours_its_maximum() {
    let topic = topic(100);
    let mut group = topic.subscribe("writer");
    topic
        .sender()
        .send(records(&["a", "b", "c"]))
        .await
        .unwrap();
    assert_eq!(
        payloads(&group.receive(2, SHORT).await.unwrap()),
        [b"a", b"b"]
    );
    assert_eq!(payloads(&group.receive(2, SHORT).await.unwrap()), [b"c"]);
}

#[tokio::test]
async fn groups_read_independently() {
    let topic = topic(100);
    let mut writer = topic.subscribe("writer");
    let mut detector = topic.subscribe("detector");
    topic.sender().send(records(&["a", "b"])).await.unwrap();

    let batch = writer.receive(10, SHORT).await.unwrap();
    writer.acknowledge(batch[1].offset).await.unwrap();
    // The detector has not acknowledged, so nothing is released yet.
    assert_eq!(topic.len(), 2);
    assert_eq!(
        payloads(&detector.receive(10, SHORT).await.unwrap()),
        [b"a", b"b"]
    );
    detector.acknowledge(1).await.unwrap();
    assert!(topic.is_empty());
}

#[tokio::test]
async fn a_group_that_restarts_receives_what_it_had_not_acknowledged() {
    let topic = topic(100);
    let mut group = topic.subscribe("writer");
    topic
        .sender()
        .send(records(&["a", "b", "c"]))
        .await
        .unwrap();
    let batch = group.receive(10, SHORT).await.unwrap();
    group.acknowledge(batch[0].offset).await.unwrap();
    drop(group);

    let mut again = topic.subscribe("writer");
    let batch = again.receive(10, SHORT).await.unwrap();
    assert_eq!(payloads(&batch), [b"b", b"c"]);
    assert_eq!(batch[0].offset, 1);
}

#[tokio::test]
async fn a_new_group_starts_at_the_end() {
    let topic = topic(100);
    let _writer = topic.subscribe("writer");
    topic.sender().send(records(&["old"])).await.unwrap();
    let mut late = topic.subscribe("late");
    topic.sender().send(records(&["new"])).await.unwrap();
    assert_eq!(payloads(&late.receive(10, SHORT).await.unwrap()), [b"new"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_topic_makes_senders_wait_until_records_are_released() {
    let topic = topic(2);
    let mut group = topic.subscribe("writer");
    topic.sender().send(records(&["a", "b"])).await.unwrap();

    let sender = topic.sender();
    let waiting = tokio::spawn(async move { sender.send(records(&["c"])).await });
    tokio::time::sleep(SHORT).await;
    assert!(
        !waiting.is_finished(),
        "the topic is full, so sending must wait"
    );

    let batch = group.receive(10, SHORT).await.unwrap();
    group.acknowledge(batch[0].offset).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("released space lets the sender through")
        .unwrap()
        .unwrap();
    assert_eq!(payloads(&group.receive(10, SHORT).await.unwrap()), [b"c"]);
}

#[tokio::test]
async fn a_batch_larger_than_the_bound_waits_for_an_empty_topic_only() {
    let topic = topic(2);
    let mut group = topic.subscribe("writer");
    topic
        .sender()
        .send(records(&["a", "b", "c"]))
        .await
        .unwrap();
    assert_eq!(group.receive(10, SHORT).await.unwrap().len(), 3);
}

#[tokio::test]
async fn a_waiting_receiver_wakes_when_records_arrive() {
    let topic = topic(10);
    let mut group = topic.subscribe("writer");
    let reading = tokio::spawn(async move { group.receive(10, Duration::from_secs(5)).await });
    tokio::time::sleep(SHORT).await;
    topic.sender().send(records(&["a"])).await.unwrap();
    let batch = tokio::time::timeout(Duration::from_secs(5), reading)
        .await
        .expect("the receiver wakes on arrival")
        .unwrap()
        .unwrap();
    assert_eq!(payloads(&batch), [b"a"]);
}

#[tokio::test]
async fn acknowledging_what_was_not_received_is_refused() {
    let topic = topic(10);
    let mut group = topic.subscribe("writer");
    topic.sender().send(records(&["a"])).await.unwrap();
    assert_eq!(
        group.acknowledge(0).await,
        Err(PipeError::NotReceived {
            offset: 0,
            received: 0
        })
    );
}

#[tokio::test]
async fn an_unsubscribed_group_releases_its_records_and_its_receivers_fail() {
    let topic = topic(10);
    let mut writer = topic.subscribe("writer");
    let mut gone = topic.subscribe("gone");
    topic.sender().send(records(&["a"])).await.unwrap();
    let batch = writer.receive(10, SHORT).await.unwrap();
    writer.acknowledge(batch[0].offset).await.unwrap();
    assert_eq!(topic.len(), 1, "held for the other group");

    topic.unsubscribe("gone");
    assert!(topic.is_empty());
    assert_eq!(
        gone.receive(10, SHORT).await,
        Err(PipeError::Unsubscribed("gone".to_owned()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_senders_and_receivers_lose_nothing() {
    let topic = topic(64);
    let mut group = topic.subscribe("writer");
    let mut senders = Vec::new();
    for sender_index in 0..8u32 {
        let sender = topic.sender();
        senders.push(tokio::spawn(async move {
            for record in 0..500u32 {
                let payload = format!("{sender_index}:{record}").into_bytes();
                sender.send(vec![payload]).await.unwrap();
            }
        }));
    }
    let mut seen = std::collections::HashSet::new();
    let mut last = None;
    while seen.len() < 4000 {
        let batch = group.receive(100, Duration::from_secs(5)).await.unwrap();
        assert!(!batch.is_empty(), "stalled at {} records", seen.len());
        for delivery in &batch {
            assert_eq!(delivery.offset, last.map_or(0, |last: u64| last + 1));
            last = Some(delivery.offset);
            assert!(seen.insert(delivery.payload.clone()), "delivered twice");
        }
        group.acknowledge(last.unwrap()).await.unwrap();
    }
    for sender in senders {
        sender.await.unwrap();
    }
    assert!(topic.is_empty());
}
