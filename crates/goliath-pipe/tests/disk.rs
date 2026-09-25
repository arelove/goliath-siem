//! The disk topic: the shared contract, and what it adds, durability and
//! recovery.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::Duration;

use goliath_pipe::{
    Delivery, DiskOptions, DiskReceiver, DiskSender, DiskTopic, PipeError, Receiver, Sender,
};

mod contract;

/// A disk topic in a directory of its own, sized in one-byte records, with
/// small segments so that the contract also crosses segment boundaries.
struct Disk {
    topic: DiskTopic,
    _directory: tempfile::TempDir,
}

// Nothing here waits; the trait is asynchronous for implementations whose
// topics live on a server.
impl contract::Fixture for Disk {
    type Sender = DiskSender;
    type Receiver = DiskReceiver;

    fn create(records: usize) -> impl Future<Output = Self> + Send {
        let directory = tempfile::tempdir().unwrap();
        // A one-byte record takes its 8-byte header plus the byte.
        let bytes = u64::try_from(records).unwrap() * 9;
        let topic = DiskTopic::open(directory.path(), options(bytes, 64)).unwrap();
        std::future::ready(Self {
            topic,
            _directory: directory,
        })
    }

    fn sender(&self) -> DiskSender {
        self.topic.sender()
    }

    fn subscribe(&self, group: &str) -> impl Future<Output = DiskReceiver> + Send {
        std::future::ready(self.topic.subscribe(group).unwrap())
    }

    fn unsubscribe(&self, group: &str) -> impl Future<Output = ()> + Send {
        self.topic.unsubscribe(group).unwrap();
        std::future::ready(())
    }
}

contract!(Disk);

const SHORT: Duration = Duration::from_millis(20);

fn options(capacity: u64, segment: u64) -> DiskOptions {
    DiskOptions {
        capacity: NonZeroU64::new(capacity).unwrap(),
        segment: NonZeroU64::new(segment).unwrap(),
    }
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

fn segments(directory: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect();
    found.sort();
    found
}

#[tokio::test]
async fn records_and_positions_survive_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    {
        let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
        let mut group = topic.subscribe("writer").unwrap();
        topic
            .sender()
            .send(records(&["a", "b", "c"]))
            .await
            .unwrap();
        let batch = group.receive(10, SHORT).await.unwrap();
        group.acknowledge(batch[0].offset).await.unwrap();
    }
    let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
    let mut group = topic.subscribe("writer").unwrap();
    let batch = group.receive(10, SHORT).await.unwrap();
    assert_eq!(payloads(&batch), [b"b", b"c"]);
    assert_eq!(batch[0].offset, 1);
    // New records continue the offsets.
    topic.sender().send(records(&["d"])).await.unwrap();
    assert_eq!(group.receive(10, SHORT).await.unwrap()[0].offset, 3);
}

#[tokio::test]
async fn a_torn_last_record_is_cut_away_on_opening() {
    let directory = tempfile::tempdir().unwrap();
    {
        let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
        let _group = topic.subscribe("writer").unwrap();
        topic.sender().send(records(&["whole"])).await.unwrap();
    }
    // A crash in the middle of the next write: a header and half a payload.
    let segment = segments(directory.path()).pop().unwrap();
    let before = fs::metadata(&segment).unwrap().len();
    let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
    file.write_all(&100u32.to_le_bytes()).unwrap();
    file.write_all(&0u32.to_le_bytes()).unwrap();
    file.write_all(b"only part").unwrap();
    drop(file);

    let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
    assert_eq!(fs::metadata(&segment).unwrap().len(), before);
    assert_eq!(topic.offsets(), 0..1);
    let mut group = topic.subscribe("writer").unwrap();
    assert_eq!(
        payloads(&group.receive(10, SHORT).await.unwrap()),
        [b"whole"]
    );
}

#[tokio::test]
async fn a_record_failing_its_checksum_at_the_end_is_cut_away() {
    let directory = tempfile::tempdir().unwrap();
    {
        let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
        let _group = topic.subscribe("writer").unwrap();
        topic
            .sender()
            .send(records(&["first", "second"]))
            .await
            .unwrap();
    }
    let segment = segments(directory.path()).pop().unwrap();
    let mut bytes = fs::read(&segment).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&segment, bytes).unwrap();

    let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
    assert_eq!(topic.offsets(), 0..1);
}

#[tokio::test]
async fn damage_before_the_last_segment_is_an_error_not_a_truncation() {
    let directory = tempfile::tempdir().unwrap();
    {
        // Segments of one record each.
        let topic = DiskTopic::open(directory.path(), options(1 << 20, 1)).unwrap();
        let _group = topic.subscribe("writer").unwrap();
        for text in ["a", "b", "c"] {
            topic.sender().send(records(&[text])).await.unwrap();
        }
    }
    let first = segments(directory.path()).remove(0);
    let mut bytes = fs::read(&first).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&first, bytes).unwrap();

    let error = DiskTopic::open(directory.path(), options(1 << 20, 1)).unwrap_err();
    assert!(
        matches!(error, PipeError::Io(ref text) if text.contains("checksum")),
        "{error}"
    );
}

#[tokio::test]
async fn acknowledged_segments_are_deleted_whole() {
    let directory = tempfile::tempdir().unwrap();
    let topic = DiskTopic::open(directory.path(), options(1 << 20, 1)).unwrap();
    let mut writer = topic.subscribe("writer").unwrap();
    let mut detector = topic.subscribe("detector").unwrap();
    for text in ["a", "b", "c"] {
        topic.sender().send(records(&[text])).await.unwrap();
    }
    // Three full segments and the empty active one.
    assert_eq!(segments(directory.path()).len(), 4);

    let batch = writer.receive(10, SHORT).await.unwrap();
    writer.acknowledge(batch[2].offset).await.unwrap();
    assert_eq!(
        segments(directory.path()).len(),
        4,
        "the detector still needs them"
    );

    let batch = detector.receive(2, SHORT).await.unwrap();
    detector.acknowledge(batch[1].offset).await.unwrap();
    assert_eq!(segments(directory.path()).len(), 2);
    assert_eq!(topic.offsets(), 2..3);
}

#[tokio::test]
async fn group_names_must_be_safe_file_names() {
    let directory = tempfile::tempdir().unwrap();
    let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
    for name in ["", "../escape", "a/b", "a b"] {
        assert!(
            matches!(topic.subscribe(name), Err(PipeError::GroupName(_))),
            "{name}"
        );
    }
    topic.subscribe("writer-1_a").unwrap();
}

#[tokio::test]
async fn an_unsubscribed_group_is_forgotten_across_restarts() {
    let directory = tempfile::tempdir().unwrap();
    {
        let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
        let _group = topic.subscribe("gone").unwrap();
        topic.sender().send(records(&["a"])).await.unwrap();
        topic.unsubscribe("gone").unwrap();
    }
    let topic = DiskTopic::open(directory.path(), DiskOptions::default()).unwrap();
    // It comes back as a new group, at the end.
    let mut group = topic.subscribe("gone").unwrap();
    assert!(group.receive(10, SHORT).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_senders_lose_nothing_across_segments() {
    let directory = tempfile::tempdir().unwrap();
    let topic = DiskTopic::open(directory.path(), options(4096, 512)).unwrap();
    let mut group = topic.subscribe("writer").unwrap();
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
    let mut seen = std::collections::HashSet::new();
    let mut last: Option<u64> = None;
    while seen.len() < 1000 {
        let batch = group.receive(64, Duration::from_secs(5)).await.unwrap();
        assert!(!batch.is_empty(), "stalled at {} records", seen.len());
        for delivery in &batch {
            assert_eq!(delivery.offset, last.map_or(0, |last| last + 1));
            last = Some(delivery.offset);
            assert!(seen.insert(delivery.payload.clone()), "delivered twice");
        }
        group.acknowledge(last.unwrap()).await.unwrap();
    }
    for sender in senders {
        sender.await.unwrap();
    }
    assert!(segments(directory.path()).len() <= 2);
}
