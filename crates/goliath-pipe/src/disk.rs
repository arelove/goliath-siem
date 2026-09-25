//! A durable topic in a directory, for single-binary mode.
//!
//! Records are appended to segment files, each named after the offset of its
//! first record. A record is framed as its length, the CRC32C of its bytes,
//! and the bytes, all little-endian:
//!
//! ```text
//! u32 length | u32 crc32c | length bytes
//! ```
//!
//! Every batch is flushed to disk before `send` returns, and every group's
//! position is replaced atomically before `acknowledge` returns, so after a
//! crash a group receives again at most what it had not acknowledged.
//!
//! On opening, the last segment is scanned, and a torn record at its end, cut
//! off by a crash in the middle of a write, is truncated away. Damage anywhere
//! else is an error: that is not a crash, and cutting the history there would
//! drop records every group still needs.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::{Delivery, PipeError, Receiver, Sender};

/// Bytes before a record: its length and its checksum.
const HEADER: u64 = 8;

/// The largest record accepted. A length above it in a segment is damage,
/// not a record.
const MAX_RECORD: u64 = 64 << 20;

/// How a disk topic is sized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskOptions {
    /// Bytes of records not yet acknowledged by every group that the topic
    /// holds before sending waits.
    pub capacity: NonZeroU64,
    /// Bytes after which a new segment is started. Acknowledged records are
    /// deleted a whole segment at a time, so the directory holds up to
    /// `capacity` plus one segment.
    pub segment: NonZeroU64,
}

impl Default for DiskOptions {
    /// One GiB of unacknowledged records, in segments of 64 MiB.
    fn default() -> Self {
        Self {
            capacity: NonZeroU64::new(1 << 30).unwrap_or(NonZeroU64::MIN),
            segment: NonZeroU64::new(64 << 20).unwrap_or(NonZeroU64::MIN),
        }
    }
}

/// A topic stored in a directory.
///
/// One process owns a directory at a time. Cheap to clone; clones are the
/// same topic.
#[derive(Debug, Clone)]
pub struct DiskTopic {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    log: Mutex<Log>,
    arrived: Notify,
    released: Notify,
}

#[derive(Debug)]
struct Log {
    directory: PathBuf,
    options: DiskOptions,
    /// Oldest first; the last one is written to.
    segments: Vec<Segment>,
    /// The file of the last segment, open for appending.
    active: File,
    /// Each group's first unacknowledged offset.
    groups: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct Segment {
    path: PathBuf,
    base: u64,
    /// Where each record of the segment starts, in its file.
    positions: Vec<u64>,
    /// The file's length.
    bytes: u64,
}

impl Segment {
    fn end(&self) -> u64 {
        self.base + self.positions.len() as u64
    }
}

impl Log {
    fn end(&self) -> u64 {
        self.segments.last().map_or(0, Segment::end)
    }

    fn base(&self) -> u64 {
        self.segments.first().map_or(0, |segment| segment.base)
    }

    /// The first offset some group has not acknowledged, or the end.
    fn floor(&self) -> u64 {
        self.groups
            .values()
            .copied()
            .min()
            .unwrap_or_else(|| self.base())
    }

    /// Bytes from `offset` to the end.
    fn bytes_from(&self, offset: u64) -> u64 {
        self.segments
            .iter()
            .filter(|segment| segment.end() > offset)
            .map(|segment| {
                let skip =
                    usize::try_from(offset.saturating_sub(segment.base)).unwrap_or(usize::MAX);
                segment.bytes - segment.positions.get(skip).copied().unwrap_or(0)
            })
            .sum()
    }

    /// Deletes segments every group has acknowledged, never the active one.
    fn release(&mut self) -> io::Result<bool> {
        let floor = self.floor();
        let mut released = false;
        while self.segments.len() > 1 && self.segments[0].end() <= floor {
            let segment = self.segments.remove(0);
            fs::remove_file(&segment.path)?;
            released = true;
        }
        Ok(released)
    }

    /// Appends a batch and syncs it. A batch that fails part way is removed
    /// again, so no partial batch is ever received.
    fn append(&mut self, payloads: &[Vec<u8>]) -> io::Result<()> {
        let Some(segment) = self.segments.last_mut() else {
            return Err(io::Error::other("a disk topic has no segment"));
        };
        let (bytes, count) = (segment.bytes, segment.positions.len());
        let written =
            write_batch(&self.active, segment, payloads).and_then(|()| self.active.sync_data());
        if let Err(error) = written {
            segment.positions.truncate(count);
            segment.bytes = bytes;
            // Best effort: if even this fails, the torn tail is removed when
            // the topic is next opened.
            let _ = self.active.set_len(bytes);
            return Err(error);
        }
        if segment.bytes >= self.options.segment.get() {
            let next = segment.end();
            self.roll(next)?;
        }
        Ok(())
    }

    /// Starts a new segment at `base`.
    fn roll(&mut self, base: u64) -> io::Result<()> {
        let path = segment_path(&self.directory, base);
        self.active = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)?;
        sync_directory(&self.directory)?;
        self.segments.push(Segment {
            path,
            base,
            positions: Vec::new(),
            bytes: 0,
        });
        Ok(())
    }

    /// Where the records from `offset` on, at most `max`, are: one run per
    /// segment, as the file, its position, and how many records.
    fn locate(&self, offset: u64, max: usize) -> Vec<(PathBuf, u64, usize)> {
        let mut runs = Vec::new();
        let mut left = max;
        for segment in self
            .segments
            .iter()
            .filter(|segment| segment.end() > offset)
        {
            if left == 0 {
                break;
            }
            let skip = usize::try_from(offset.saturating_sub(segment.base)).unwrap_or(usize::MAX);
            // The active segment may hold nothing yet.
            let Some(&position) = segment.positions.get(skip) else {
                continue;
            };
            let count = (segment.positions.len() - skip).min(left);
            runs.push((segment.path.clone(), position, count));
            left -= count;
        }
        runs
    }

    fn write_group(&self, group: &str, position: u64) -> io::Result<()> {
        let path = group_path(&self.directory, group);
        let temporary = path.with_extension("tmp");
        let mut file = File::create(&temporary)?;
        file.write_all(&position.to_le_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        sync_directory(&self.directory.join("groups"))
    }
}

impl DiskTopic {
    /// Opens the topic in `directory`, creating it if needed, and recovers
    /// from a crash during a write.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::Io`] if the directory cannot be read or written,
    /// or holds damage other than a torn last record.
    pub fn open(directory: impl AsRef<Path>, options: DiskOptions) -> Result<Self, PipeError> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(directory.join("groups")).map_err(PipeError::from)?;

        let mut bases = Vec::new();
        for entry in fs::read_dir(&directory).map_err(PipeError::from)? {
            let name = entry.map_err(PipeError::from)?.file_name();
            let name = name.to_string_lossy();
            if let Some(base) = name
                .strip_suffix(".log")
                .and_then(|base| base.parse::<u64>().ok())
            {
                bases.push(base);
            }
        }
        bases.sort_unstable();

        let mut segments = Vec::with_capacity(bases.len());
        for (index, base) in bases.iter().enumerate() {
            let last = index + 1 == bases.len();
            let segment = scan(segment_path(&directory, *base), *base, last)?;
            if let Some(previous) = segments.last().map(Segment::end)
                && previous != *base
            {
                return Err(damage(
                    &segment.path,
                    "does not continue the segment before it",
                ));
            }
            segments.push(segment);
        }

        let mut groups = BTreeMap::new();
        for entry in fs::read_dir(directory.join("groups")).map_err(PipeError::from)? {
            let path = entry.map_err(PipeError::from)?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "offset")
            {
                let bytes = fs::read(&path).map_err(PipeError::from)?;
                let position = <[u8; 8]>::try_from(bytes.as_slice())
                    .map(u64::from_le_bytes)
                    .map_err(|_| damage(&path, "is not an offset"))?;
                let name = path
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_default();
                groups.insert(name, position);
            }
        }

        if segments.is_empty() {
            let path = segment_path(&directory, 0);
            File::create(&path).map_err(PipeError::from)?;
            segments.push(Segment {
                path,
                base: 0,
                positions: Vec::new(),
                bytes: 0,
            });
        }
        let active_path = segments
            .last()
            .map(|segment| segment.path.clone())
            .unwrap_or_default();
        let active = OpenOptions::new()
            .append(true)
            .open(active_path)
            .map_err(PipeError::from)?;
        let end = segments.last().map_or(0, Segment::end);
        for position in groups.values_mut() {
            // A position past the end means records it had acknowledged
            // were in a torn write that never reached disk, so it cannot have
            // received them from here; clamp it.
            *position = (*position).min(end);
        }
        Ok(Self {
            shared: Arc::new(Shared {
                log: Mutex::new(Log {
                    directory,
                    options,
                    segments,
                    active,
                    groups,
                }),
                arrived: Notify::new(),
                released: Notify::new(),
            }),
        })
    }

    /// A sender to this topic.
    pub fn sender(&self) -> DiskSender {
        DiskSender {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A receiver for `group`. A new group starts at the end of the topic; a
    /// known one, including one known before a restart, resumes at its first
    /// unacknowledged record.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::GroupName`] for a name that is not letters,
    /// digits, `-`, and `_`, and [`PipeError::Io`] if the new group's
    /// position cannot be written.
    pub fn subscribe(&self, group: &str) -> Result<DiskReceiver, PipeError> {
        if group.is_empty()
            || !group
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(PipeError::GroupName(group.to_owned()));
        }
        let mut log = lock(&self.shared.log);
        let position = if let Some(position) = log.groups.get(group) {
            *position
        } else {
            let end = log.end();
            log.write_group(group, end).map_err(PipeError::from)?;
            log.groups.insert(group.to_owned(), end);
            end
        };
        Ok(DiskReceiver {
            shared: Arc::clone(&self.shared),
            group: group.to_owned(),
            next: position,
        })
    }

    /// Removes `group` and its position, releasing what only it held.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::Io`] if the position or a segment cannot be
    /// deleted.
    pub fn unsubscribe(&self, group: &str) -> Result<(), PipeError> {
        let mut log = lock(&self.shared.log);
        if log.groups.remove(group).is_some() {
            fs::remove_file(group_path(&log.directory, group)).map_err(PipeError::from)?;
        }
        if log.release().map_err(PipeError::from)? {
            drop(log);
            self.shared.released.notify_waiters();
        }
        Ok(())
    }

    /// The offsets the topic holds, from the first still stored to the next
    /// to be written.
    pub fn offsets(&self) -> std::ops::Range<u64> {
        let log = lock(&self.shared.log);
        log.base()..log.end()
    }
}

/// Sends to a [`DiskTopic`].
#[derive(Debug, Clone)]
pub struct DiskSender {
    shared: Arc<Shared>,
}

impl Sender for DiskSender {
    async fn send(&self, payloads: Vec<Vec<u8>>) -> Result<(), PipeError> {
        if payloads.is_empty() {
            return Ok(());
        }
        let incoming: u64 = payloads
            .iter()
            .map(|payload| HEADER + payload.len() as u64)
            .sum();
        loop {
            let released = self.shared.released.notified();
            {
                let mut log = lock(&self.shared.log);
                let waiting = log.bytes_from(log.floor());
                if waiting == 0 || waiting + incoming <= log.options.capacity.get() {
                    // Written while holding the lock: appends are ordered,
                    // and a batch is on disk before anyone can receive it.
                    log.append(&payloads).map_err(PipeError::from)?;
                    drop(log);
                    self.shared.arrived.notify_waiters();
                    return Ok(());
                }
            }
            released.await;
        }
    }
}

/// Reads a [`DiskTopic`] as one group.
#[derive(Debug)]
pub struct DiskReceiver {
    shared: Arc<Shared>,
    group: String,
    next: u64,
}

impl Receiver for DiskReceiver {
    async fn receive(&mut self, max: usize, wait: Duration) -> Result<Vec<Delivery>, PipeError> {
        let deadline = Instant::now() + wait;
        loop {
            let arrived = self.shared.arrived.notified();
            let runs = {
                let log = lock(&self.shared.log);
                if !log.groups.contains_key(&self.group) {
                    return Err(PipeError::Unsubscribed(self.group.clone()));
                }
                let from = self.next.max(log.base());
                self.next = from;
                (from < log.end() && max > 0).then(|| log.locate(from, max))
            };
            if let Some(runs) = runs {
                // Read outside the lock: written records never change, and a
                // segment is deleted only once this group acknowledged it.
                let mut batch = Vec::new();
                for (path, position, count) in runs {
                    read_run(&path, position, count, &mut |payload| {
                        batch.push(Delivery {
                            offset: self.next,
                            payload,
                        });
                        self.next += 1;
                    })?;
                }
                return Ok(batch);
            }
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                return Ok(Vec::new());
            }
        }
    }

    fn acknowledge(&mut self, offset: u64) -> impl Future<Output = Result<(), PipeError>> + Send {
        std::future::ready(self.acknowledge_now(offset))
    }
}

impl DiskReceiver {
    /// Writes the position synchronously: it is a few bytes and one sync,
    /// and must be on disk before the caller treats the records as handled.
    fn acknowledge_now(&mut self, offset: u64) -> Result<(), PipeError> {
        if offset >= self.next {
            return Err(PipeError::NotReceived {
                offset,
                received: self.next,
            });
        }
        let mut log = lock(&self.shared.log);
        let Some(current) = log.groups.get(&self.group).copied() else {
            return Err(PipeError::Unsubscribed(self.group.clone()));
        };
        let position = current.max(offset + 1);
        if position == current {
            return Ok(());
        }
        log.write_group(&self.group, position)
            .map_err(PipeError::from)?;
        log.groups.insert(self.group.clone(), position);
        log.release().map_err(PipeError::from)?;
        drop(log);
        // Capacity counts unacknowledged bytes, so any acknowledgement makes
        // room, whether or not it completed a segment.
        self.shared.released.notify_waiters();
        Ok(())
    }
}

/// Writes a batch of frames after the segment's last record, indexing them.
fn write_batch(file: &File, segment: &mut Segment, payloads: &[Vec<u8>]) -> io::Result<()> {
    let mut writer = BufWriter::new(file);
    for payload in payloads {
        let length = u32::try_from(payload.len())
            .ok()
            .filter(|length| u64::from(*length) <= MAX_RECORD)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "record larger than 64 MiB")
            })?;
        writer.write_all(&length.to_le_bytes())?;
        writer.write_all(&crc32c::crc32c(payload).to_le_bytes())?;
        writer.write_all(payload)?;
        segment.positions.push(segment.bytes);
        segment.bytes += HEADER + u64::from(length);
    }
    writer.flush()
}

/// Reads a segment, indexing its records. A torn record at the end of the
/// last segment is truncated away; any other damage is an error.
fn scan(path: PathBuf, base: u64, last: bool) -> Result<Segment, PipeError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(last)
        .open(&path)
        .map_err(PipeError::from)?;
    let length = file.metadata().map_err(PipeError::from)?.len();
    let mut reader = io::BufReader::new(&mut file);
    let mut positions = Vec::new();
    let mut position = 0;
    let mut payload = Vec::new();
    while position < length {
        match read_frame(&mut reader, &mut payload) {
            Ok(()) => {
                positions.push(position);
                position += HEADER + payload.len() as u64;
            }
            Err(Frame::Io(error)) => return Err(PipeError::from(error)),
            Err(Frame::Damaged(reason)) if !last => return Err(damage(&path, reason)),
            Err(Frame::Damaged(_)) => {
                drop(reader);
                file.set_len(position).map_err(PipeError::from)?;
                file.sync_all().map_err(PipeError::from)?;
                break;
            }
        }
    }
    Ok(Segment {
        path,
        base,
        positions,
        bytes: position,
    })
}

enum Frame {
    Io(io::Error),
    Damaged(&'static str),
}

/// Reads one record into `payload`.
fn read_frame(reader: &mut impl Read, payload: &mut Vec<u8>) -> Result<(), Frame> {
    let mut length = [0; 4];
    let mut checksum = [0; 4];
    reader
        .read_exact(&mut length)
        .and_then(|()| reader.read_exact(&mut checksum))
        .map_err(eof_is_damage("a record header is cut short"))?;
    let length = u32::from_le_bytes(length);
    let checksum = u32::from_le_bytes(checksum);
    if u64::from(length) > MAX_RECORD {
        return Err(Frame::Damaged("a record length is out of range"));
    }
    payload.clear();
    payload.resize(length as usize, 0);
    reader
        .read_exact(payload)
        .map_err(eof_is_damage("a record is cut short"))?;
    if crc32c::crc32c(payload) != checksum {
        return Err(Frame::Damaged("a record fails its checksum"));
    }
    Ok(())
}

fn eof_is_damage(reason: &'static str) -> impl Fn(io::Error) -> Frame {
    move |error| match error.kind() {
        io::ErrorKind::UnexpectedEof => Frame::Damaged(reason),
        _ => Frame::Io(error),
    }
}

/// Reads `count` records from `position` of the segment at `path`.
fn read_run(
    path: &Path,
    position: u64,
    count: usize,
    each: &mut impl FnMut(Vec<u8>),
) -> Result<(), PipeError> {
    let mut file = File::open(path).map_err(PipeError::from)?;
    file.seek(SeekFrom::Start(position))
        .map_err(PipeError::from)?;
    let mut reader = io::BufReader::new(file);
    for _ in 0..count {
        let mut payload = Vec::new();
        read_frame(&mut reader, &mut payload).map_err(|frame| match frame {
            Frame::Io(error) => PipeError::from(error),
            Frame::Damaged(reason) => damage(path, reason),
        })?;
        each(payload);
    }
    Ok(())
}

fn segment_path(directory: &Path, base: u64) -> PathBuf {
    directory.join(format!("{base:020}.log"))
}

fn group_path(directory: &Path, group: &str) -> PathBuf {
    directory.join("groups").join(format!("{group}.offset"))
}

/// Makes a file's creation, removal, or rename durable. Windows has no way
/// to open a directory for this and orders metadata writes itself.
fn sync_directory(directory: &Path) -> io::Result<()> {
    if cfg!(unix) {
        File::open(directory)?.sync_all()
    } else {
        Ok(())
    }
}

fn lock(log: &Mutex<Log>) -> MutexGuard<'_, Log> {
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

fn damage(path: &Path, reason: &str) -> PipeError {
    PipeError::Io(format!("{}: {reason}", path.display()))
}
