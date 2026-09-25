//! A topic in Kafka or Redpanda, for roles on several hosts.
//!
//! The contract maps onto Kafka as follows:
//!
//! - **Order and offsets.** A topic has one partition, written by an
//!   idempotent producer with `acks=all`, so offsets are Kafka's own and
//!   consecutive, and a batch is replicated before `send` returns.
//! - **Groups.** Each group's position is its committed offset in Kafka. A
//!   receiver assigns the partition itself instead of joining the group, so
//!   there are no rebalances; a new group commits the end of the topic at
//!   once, and so starts there, as on disk.
//! - **Bound.** Kafka deletes by age or size, whether or not a group has read
//!   the records. So a sender measures how far the slowest reading group is
//!   behind, and waits while that exceeds the capacity; Kafka's own retention
//!   must be set well beyond it, as a safety net only.
//!
//! The groups a sender waits for are those subscribed through the same
//! [`KafkaTopic`], and those named in [`KafkaOptions::readers`], for readers
//! in other processes. A reader named there that has no position yet gets
//! one when the topic is opened: the end of the topic at that moment. So a
//! reader that starts after a sender has sent still receives what was sent,
//! rather than starting after it as a new group otherwise would.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rdkafka::ClientConfig;
use rdkafka::Offset;
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::client::DefaultClientContext;
use rdkafka::consumer::{BaseConsumer, CommitMode, Consumer};
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::Message;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::topic_partition_list::TopicPartitionList;
use tokio::time::Instant;

use crate::{Delivery, PipeError, Receiver, Sender};

/// How long a request to the brokers may take.
const REQUEST: Duration = Duration::from_secs(10);

/// How often a waiting sender looks at the readers' positions again.
const RECHECK: Duration = Duration::from_millis(20);

/// Where a topic lives and how it is sized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaOptions {
    /// The bootstrap servers, such as `localhost:9092`.
    pub brokers: String,
    /// Records not yet acknowledged by the slowest reading group that the
    /// topic holds before sending waits.
    pub capacity: NonZeroU64,
    /// Groups in other processes that read the topic, and that senders must
    /// therefore wait for.
    pub readers: BTreeSet<String>,
    /// Replicas of a topic this creates; 3 in production, 1 for a single
    /// broker.
    pub replication: i32,
    /// Further client settings, such as `security.protocol` and SASL
    /// credentials, passed to librdkafka unchanged.
    pub client: BTreeMap<String, String>,
}

impl KafkaOptions {
    /// Options for `brokers`, holding one million records, with no readers
    /// elsewhere and one replica.
    pub fn new(brokers: impl Into<String>) -> Self {
        Self {
            brokers: brokers.into(),
            capacity: NonZeroU64::new(1_000_000).unwrap_or(NonZeroU64::MIN),
            readers: BTreeSet::new(),
            replication: 1,
            client: BTreeMap::new(),
        }
    }

    fn config(&self) -> ClientConfig {
        let mut config = ClientConfig::new();
        config.set("bootstrap.servers", &self.brokers);
        for (key, value) in &self.client {
            config.set(key, value);
        }
        config
    }
}

/// A topic in Kafka.
///
/// Cheap to clone; clones are the same topic.
#[derive(Clone)]
pub struct KafkaTopic {
    shared: Arc<Shared>,
}

struct Shared {
    name: String,
    options: KafkaOptions,
    producer: FutureProducer,
    /// Groups subscribed through this topic.
    local: Mutex<BTreeSet<String>>,
    /// One idle consumer per group, to read its committed offset.
    lookups: Mutex<BTreeMap<String, Arc<BaseConsumer>>>,
}

impl std::fmt::Debug for KafkaTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaTopic")
            .field("name", &self.shared.name)
            .finish_non_exhaustive()
    }
}

impl KafkaTopic {
    /// Opens the topic `name`, creating it with one partition if it does not
    /// exist, and gives each group in [`KafkaOptions::readers`] that has no
    /// position the end of the topic as its position.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::Io`] if the brokers cannot be reached, the topic
    /// cannot be created, or it exists with more than one partition.
    pub async fn open(name: &str, options: KafkaOptions) -> Result<Self, PipeError> {
        let admin: AdminClient<DefaultClientContext> = options.config().create().map_err(kafka)?;
        let topic = NewTopic::new(name, 1, TopicReplication::Fixed(options.replication));
        let created = admin
            .create_topics(
                [&topic],
                &AdminOptions::new().request_timeout(Some(REQUEST)),
            )
            .await
            .map_err(kafka)?;
        for result in created {
            match result {
                Ok(_) | Err((_, RDKafkaErrorCode::TopicAlreadyExists)) => {}
                Err((topic, code)) => {
                    return Err(PipeError::Io(format!("creating topic {topic}: {code}")));
                }
            }
        }

        let producer: FutureProducer = options
            .config()
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .set("compression.type", "lz4")
            .set("linger.ms", "5")
            .create()
            .map_err(kafka)?;
        let partitions = blocking({
            let producer = producer.clone();
            let name = name.to_owned();
            move || {
                use rdkafka::producer::Producer;
                let metadata = producer
                    .client()
                    .fetch_metadata(Some(&name), REQUEST)
                    .map_err(kafka)?;
                Ok(metadata
                    .topics()
                    .first()
                    .map_or(0, |topic| topic.partitions().len()))
            }
        })
        .await?;
        if partitions != 1 {
            return Err(PipeError::Io(format!(
                "topic {name} has {partitions} partitions; the pipe needs exactly one for its order"
            )));
        }
        let topic = Self {
            shared: Arc::new(Shared {
                name: name.to_owned(),
                options,
                producer,
                local: Mutex::new(BTreeSet::new()),
                lookups: Mutex::new(BTreeMap::new()),
            }),
        };
        topic.place_readers().await?;
        Ok(topic)
    }

    /// Commits the end of the topic for each reader elsewhere that has no
    /// position yet.
    async fn place_readers(&self) -> Result<(), PipeError> {
        let sender = self.sender();
        let lookups: Vec<Arc<BaseConsumer>> = self
            .shared
            .options
            .readers
            .iter()
            .map(|group| sender.lookup(group))
            .collect::<Result<_, _>>()?;
        if lookups.is_empty() {
            return Ok(());
        }
        let name = self.shared.name.clone();
        blocking(move || {
            for consumer in lookups {
                if committed(&consumer, &name)?.is_none() {
                    let (_, end) = consumer
                        .fetch_watermarks(&name, 0, REQUEST)
                        .map_err(kafka)?;
                    commit(&consumer, &name, u64::try_from(end).unwrap_or(0))?;
                }
            }
            Ok(())
        })
        .await
    }

    /// A sender to this topic.
    pub fn sender(&self) -> KafkaSender {
        KafkaSender {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A receiver for `group`. A new group starts at the end of the topic; a
    /// known one resumes after its last acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::Io`] if the brokers cannot be reached.
    pub async fn subscribe(&self, group: &str) -> Result<KafkaReceiver, PipeError> {
        let consumer: BaseConsumer = self
            .shared
            .options
            .config()
            .set("group.id", group)
            .set("enable.auto.commit", "false")
            .set("enable.auto.offset.store", "false")
            .set("enable.partition.eof", "false")
            .create()
            .map_err(kafka)?;
        let consumer = Arc::new(consumer);
        let name = self.shared.name.clone();
        let next = blocking({
            let consumer = Arc::clone(&consumer);
            move || {
                let next = if let Some(offset) = committed(&consumer, &name)? {
                    offset
                } else {
                    // A new group: it starts at the end, and says so at once,
                    // so that it resumes there after a restart.
                    let (_, end) = consumer
                        .fetch_watermarks(&name, 0, REQUEST)
                        .map_err(kafka)?;
                    let end = u64::try_from(end).unwrap_or(0);
                    commit(&consumer, &name, end)?;
                    end
                };
                let mut assignment = TopicPartitionList::new();
                assignment
                    .add_partition_offset(&name, 0, Offset::Offset(signed(next)))
                    .map_err(kafka)?;
                consumer.assign(&assignment).map_err(kafka)?;
                Ok(next)
            }
        })
        .await?;
        lock(&self.shared.local).insert(group.to_owned());
        Ok(KafkaReceiver {
            shared: Arc::clone(&self.shared),
            consumer,
            group: group.to_owned(),
            next,
        })
    }

    /// Removes `group`: its position is deleted, and senders stop waiting
    /// for it. Its receivers in this process fail from then on.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::Io`] if the brokers refuse.
    pub async fn unsubscribe(&self, group: &str) -> Result<(), PipeError> {
        lock(&self.shared.local).remove(group);
        lock(&self.shared.lookups).remove(group);
        let admin: AdminClient<DefaultClientContext> =
            self.shared.options.config().create().map_err(kafka)?;
        let deleted = admin
            .delete_groups(
                &[group],
                &AdminOptions::new().request_timeout(Some(REQUEST)),
            )
            .await
            .map_err(kafka)?;
        for result in deleted {
            match result {
                Ok(_) | Err((_, RDKafkaErrorCode::GroupIdNotFound)) => {}
                Err((group, code)) => {
                    return Err(PipeError::Io(format!("deleting group {group}: {code}")));
                }
            }
        }
        Ok(())
    }
}

/// Sends to a [`KafkaTopic`].
#[derive(Clone)]
pub struct KafkaSender {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for KafkaSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaSender")
            .field("topic", &self.shared.name)
            .finish_non_exhaustive()
    }
}

impl KafkaSender {
    /// Records the slowest reading group has not acknowledged.
    async fn behind(&self) -> Result<u64, PipeError> {
        let mut groups: BTreeSet<String> = lock(&self.shared.local).clone();
        groups.extend(self.shared.options.readers.iter().cloned());
        let lookups: Vec<Arc<BaseConsumer>> = groups
            .iter()
            .map(|group| self.lookup(group))
            .collect::<Result<_, _>>()?;
        let name = self.shared.name.clone();
        let producer = self.shared.producer.clone();
        blocking(move || {
            use rdkafka::producer::Producer;
            let (_, end) = producer
                .client()
                .fetch_watermarks(&name, 0, REQUEST)
                .map_err(kafka)?;
            let end = u64::try_from(end).unwrap_or(0);
            let mut behind = 0;
            for consumer in lookups {
                // A group that never committed has read nothing.
                let position = committed(&consumer, &name)?.unwrap_or(0);
                behind = behind.max(end.saturating_sub(position));
            }
            Ok(behind)
        })
        .await
    }

    fn lookup(&self, group: &str) -> Result<Arc<BaseConsumer>, PipeError> {
        let mut lookups = lock(&self.shared.lookups);
        if let Some(consumer) = lookups.get(group) {
            return Ok(Arc::clone(consumer));
        }
        let consumer: BaseConsumer = self
            .shared
            .options
            .config()
            .set("group.id", group)
            .set("enable.auto.commit", "false")
            .create()
            .map_err(kafka)?;
        let consumer = Arc::new(consumer);
        lookups.insert(group.to_owned(), Arc::clone(&consumer));
        Ok(consumer)
    }
}

impl Sender for KafkaSender {
    async fn send(&self, payloads: Vec<Vec<u8>>) -> Result<(), PipeError> {
        if payloads.is_empty() {
            return Ok(());
        }
        let incoming = payloads.len() as u64;
        let capacity = self.shared.options.capacity.get();
        loop {
            let behind = self.behind().await?;
            if behind == 0 || behind + incoming <= capacity {
                break;
            }
            tokio::time::sleep(RECHECK).await;
        }
        // Queued in order to the one partition; the idempotent producer keeps
        // that order through retries.
        let mut deliveries = Vec::with_capacity(payloads.len());
        for payload in &payloads {
            let record: FutureRecord<'_, (), [u8]> = FutureRecord::to(&self.shared.name)
                .partition(0)
                .payload(payload.as_slice());
            let delivery = self
                .shared
                .producer
                .send_result(record)
                .map_err(|(error, _)| kafka(error))?;
            deliveries.push(delivery);
        }
        for delivery in deliveries {
            match delivery.await {
                Ok(Ok(_)) => {}
                Ok(Err((error, _))) => return Err(kafka(error)),
                Err(_) => {
                    return Err(PipeError::Io(
                        "the producer stopped before delivery".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Reads a [`KafkaTopic`] as one group.
pub struct KafkaReceiver {
    shared: Arc<Shared>,
    consumer: Arc<BaseConsumer>,
    group: String,
    next: u64,
}

impl std::fmt::Debug for KafkaReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaReceiver")
            .field("topic", &self.shared.name)
            .field("group", &self.group)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl Receiver for KafkaReceiver {
    async fn receive(&mut self, max: usize, wait: Duration) -> Result<Vec<Delivery>, PipeError> {
        if !lock(&self.shared.local).contains(&self.group) {
            return Err(PipeError::Unsubscribed(self.group.clone()));
        }
        if max == 0 {
            return Ok(Vec::new());
        }
        let consumer = Arc::clone(&self.consumer);
        let deadline = Instant::now() + wait;
        let batch = blocking(move || {
            let mut batch = Vec::new();
            // Wait for the first record, then take what is already there.
            let mut timeout = deadline.saturating_duration_since(Instant::now());
            while batch.len() < max {
                let Some(message) = consumer.poll(timeout) else {
                    break;
                };
                let message = message.map_err(kafka)?;
                batch.push(Delivery {
                    offset: u64::try_from(message.offset()).unwrap_or(0),
                    payload: message.payload().unwrap_or_default().to_vec(),
                });
                timeout = Duration::ZERO;
            }
            Ok(batch)
        })
        .await?;
        if let Some(last) = batch.last() {
            self.next = last.offset + 1;
        }
        Ok(batch)
    }

    async fn acknowledge(&mut self, offset: u64) -> Result<(), PipeError> {
        if offset >= self.next {
            return Err(PipeError::NotReceived {
                offset,
                received: self.next,
            });
        }
        if !lock(&self.shared.local).contains(&self.group) {
            return Err(PipeError::Unsubscribed(self.group.clone()));
        }
        let consumer = Arc::clone(&self.consumer);
        let name = self.shared.name.clone();
        blocking(move || commit(&consumer, &name, offset + 1)).await
    }
}

/// The group's committed offset for the topic's partition, if any.
fn committed(consumer: &BaseConsumer, topic: &str) -> Result<Option<u64>, PipeError> {
    let mut wanted = TopicPartitionList::new();
    wanted.add_partition(topic, 0);
    let found = consumer.committed_offsets(wanted, REQUEST).map_err(kafka)?;
    Ok(found
        .find_partition(topic, 0)
        .and_then(|partition| match partition.offset() {
            Offset::Offset(offset) => u64::try_from(offset).ok(),
            _ => None,
        }))
}

/// Commits `position` as the group's next record, synchronously.
fn commit(consumer: &BaseConsumer, topic: &str, position: u64) -> Result<(), PipeError> {
    let mut positions = TopicPartitionList::new();
    positions
        .add_partition_offset(topic, 0, Offset::Offset(signed(position)))
        .map_err(kafka)?;
    consumer.commit(&positions, CommitMode::Sync).map_err(kafka)
}

fn signed(offset: u64) -> i64 {
    i64::try_from(offset).unwrap_or(i64::MAX)
}

/// Runs a blocking librdkafka call on a thread meant for it.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, PipeError> + Send + 'static,
) -> Result<T, PipeError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| PipeError::Io(format!("blocking Kafka call failed: {error}")))?
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[allow(clippy::needless_pass_by_value)] // Used as `map_err(kafka)`.
fn kafka(error: KafkaError) -> PipeError {
    PipeError::Io(format!("kafka: {error}"))
}
