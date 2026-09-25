//! Where the topics between roles are kept: files in the data directory, for
//! roles in one process, or Kafka, for roles in several.

use std::future::{self, Future};
use std::path::PathBuf;

use goliath_pipe::{DiskOptions, DiskReceiver, DiskSender, DiskTopic, Receiver, Sender};

use crate::RunError;

/// A place to keep topics.
pub(crate) trait Topics: Sync {
    /// An open topic.
    type Topic: Send + Sync;
    /// Sends to a topic.
    type Sender: Sender + Send + Sync + 'static;
    /// Reads a topic as one group.
    type Receiver: Receiver + Send + 'static;

    /// Opens the topic `name`, which the group `reader` reads, wherever that
    /// group runs.
    fn open(
        &self,
        name: &str,
        reader: &str,
    ) -> impl Future<Output = Result<Self::Topic, RunError>> + Send;

    /// A sender to `topic`.
    fn sender(topic: &Self::Topic) -> Self::Sender;

    /// A receiver of `topic` for `group`.
    fn subscribe(
        &self,
        topic: &Self::Topic,
        group: &str,
    ) -> impl Future<Output = Result<Self::Receiver, RunError>> + Send;
}

/// Topics as files in a data directory; every role that uses one must be in
/// this process.
pub(crate) struct Disk {
    data: PathBuf,
}

impl Disk {
    pub(crate) fn new(data: PathBuf) -> Self {
        Self { data }
    }
}

impl Topics for Disk {
    type Topic = DiskTopic;
    type Sender = DiskSender;
    type Receiver = DiskReceiver;

    fn open(
        &self,
        name: &str,
        _reader: &str,
    ) -> impl Future<Output = Result<DiskTopic, RunError>> + Send {
        future::ready(
            DiskTopic::open(self.data.join(name), DiskOptions::default()).map_err(RunError::from),
        )
    }

    fn sender(topic: &DiskTopic) -> DiskSender {
        topic.sender()
    }

    fn subscribe(
        &self,
        topic: &DiskTopic,
        group: &str,
    ) -> impl Future<Output = Result<DiskReceiver, RunError>> + Send {
        future::ready(topic.subscribe(group).map_err(RunError::from))
    }
}

#[cfg(feature = "kafka")]
pub(crate) use kafka::Kafka;

#[cfg(feature = "kafka")]
mod kafka {
    use goliath_pipe::{KafkaOptions, KafkaReceiver, KafkaSender, KafkaTopic};

    use super::Topics;
    use crate::RunError;
    use crate::config::KafkaConfig;

    /// Topics in Kafka. Topic and group names carry the configured prefix.
    pub(crate) struct Kafka {
        options: KafkaOptions,
        prefix: String,
    }

    impl Kafka {
        /// # Errors
        ///
        /// Returns [`RunError::Config`] if the SASL password cannot be read.
        pub(crate) fn new(config: &KafkaConfig) -> Result<Self, RunError> {
            let mut options = KafkaOptions::new(&config.brokers);
            options.replication = config.replication;
            if let Some(capacity) = config.capacity {
                options.capacity = capacity;
            }
            options.client = config.client()?;
            Ok(Self {
                options,
                prefix: config.prefix.clone(),
            })
        }
    }

    impl Topics for Kafka {
        type Topic = KafkaTopic;
        type Sender = KafkaSender;
        type Receiver = KafkaReceiver;

        async fn open(&self, name: &str, reader: &str) -> Result<KafkaTopic, RunError> {
            // The reader may run in another process; senders here wait for
            // it, and it receives what they sent before it started.
            let mut options = self.options.clone();
            options.readers.insert(format!("{}{reader}", self.prefix));
            Ok(KafkaTopic::open(&format!("{}{name}", self.prefix), options).await?)
        }

        fn sender(topic: &KafkaTopic) -> KafkaSender {
            topic.sender()
        }

        async fn subscribe(
            &self,
            topic: &KafkaTopic,
            group: &str,
        ) -> Result<KafkaReceiver, RunError> {
            Ok(topic.subscribe(&format!("{}{group}", self.prefix)).await?)
        }
    }
}
