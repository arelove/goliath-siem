//! The Kafka topic runs the same contract as the memory and disk topics.
//!
//! Built with `--features kafka`, and run against a broker named by
//! `GOLIATH_KAFKA_BROKERS`, such as a Redpanda container:
//!
//! ```text
//! docker run -d -p 9092:9092 redpandadata/redpanda redpanda start --mode dev-container \
//!     --kafka-addr PLAINTEXT://0.0.0.0:9092 --advertise-kafka-addr PLAINTEXT://localhost:9092
//! GOLIATH_KAFKA_BROKERS=localhost:9092 cargo test -p goliath-pipe --features kafka --test kafka
//! ```
//!
//! With the feature on, a missing broker is a failure, not a skip: turning
//! the feature on is asking for these tests.

#![cfg(feature = "kafka")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod contract;

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use goliath_pipe::{KafkaOptions, KafkaReceiver, KafkaSender, KafkaTopic};

/// A topic of its own per test, and group names prefixed with it: Kafka
/// group names are global to the cluster.
struct Kafka {
    topic: KafkaTopic,
    name: String,
}

fn brokers() -> String {
    std::env::var("GOLIATH_KAFKA_BROKERS")
        .expect("set GOLIATH_KAFKA_BROKERS to run the Kafka tests")
}

fn unique(prefix: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{prefix}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

impl contract::Fixture for Kafka {
    type Sender = KafkaSender;
    type Receiver = KafkaReceiver;

    async fn create(records: usize) -> Self {
        let name = unique("goliath-test");
        let mut options = KafkaOptions::new(brokers());
        options.capacity = NonZeroU64::new(u64::try_from(records).unwrap()).unwrap();
        let topic = KafkaTopic::open(&name, options).await.unwrap();
        Self { topic, name }
    }

    fn sender(&self) -> KafkaSender {
        self.topic.sender()
    }

    async fn subscribe(&self, group: &str) -> KafkaReceiver {
        self.topic
            .subscribe(&format!("{}-{group}", self.name))
            .await
            .unwrap()
    }

    async fn unsubscribe(&self, group: &str) {
        self.topic
            .unsubscribe(&format!("{}-{group}", self.name))
            .await
            .unwrap();
    }
}

contract!(Kafka);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_topic_with_several_partitions_is_refused() {
    use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
    use rdkafka::client::DefaultClientContext;

    let name = unique("goliath-test-partitioned");
    let admin: AdminClient<DefaultClientContext> = rdkafka::ClientConfig::new()
        .set("bootstrap.servers", brokers())
        .create()
        .unwrap();
    admin
        .create_topics(
            [&NewTopic::new(&name, 3, TopicReplication::Fixed(1))],
            &AdminOptions::new(),
        )
        .await
        .unwrap();
    let error = KafkaTopic::open(&name, KafkaOptions::new(brokers()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exactly one"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_elsewhere_that_starts_late_receives_what_was_sent() {
    use std::time::Duration;

    use goliath_pipe::{Receiver, Sender};

    let name = unique("goliath-test-late");
    let group = format!("{name}-normalizer");
    let mut options = KafkaOptions::new(brokers());
    options.readers.insert(group.clone());
    let collector = KafkaTopic::open(&name, options).await.unwrap();
    collector
        .sender()
        .send(vec![b"one".to_vec(), b"two".to_vec()])
        .await
        .unwrap();

    // The reader's own process opens the topic only now.
    let normalizer = KafkaTopic::open(&name, KafkaOptions::new(brokers()))
        .await
        .unwrap();
    let mut receiver = normalizer.subscribe(&group).await.unwrap();
    let mut payloads = Vec::new();
    while payloads.len() < 2 {
        let batch = receiver.receive(10, Duration::from_secs(5)).await.unwrap();
        assert!(
            !batch.is_empty(),
            "records sent before the reader started were skipped"
        );
        payloads.extend(batch.into_iter().map(|delivery| delivery.payload));
    }
    assert_eq!(payloads, [b"one".to_vec(), b"two".to_vec()]);
}
