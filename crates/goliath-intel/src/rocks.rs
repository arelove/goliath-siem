//! The store on disk: `RocksDB` in the process, behind a filter in memory.
//!
//! An entry's key is the indicator's key, the feed, and the generation of
//! the feed that wrote it; its value is the assertion. A feed is replaced by
//! writing a new generation beside the old and then naming the new one
//! current in one write, so a reader sees the old feed or the new, never half
//! of each, and a replacement of any size is written in bounded memory.
//! Entries of other generations are skipped by readers and dropped as files
//! are compacted. See `docs/adr/0020-state-beyond-events.md`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, CompactionDecision, DB, DBCompressionType,
    Direction, IteratorMode, Options, ReadOptions, WriteBatch, WriteOptions,
};

use crate::bloom::Bloom;
use crate::key::{Key, PrefixLengths};
use crate::store::{Replaced, Store};
use crate::{Assertion, IntelError};

/// The column family of indicators; the default one holds the feeds.
const INDICATORS: &str = "indicators";
/// The key of the last generation given out.
const GENERATION: &[u8] = b"generation";
/// Before a feed's name, in the key of what is current for it.
const FEED: &[u8] = b"feed\0";
/// Entries written at once while a feed is replaced.
const CHUNK: usize = 10_000;
/// The block cache, unless [`RocksStore::open_with`] says otherwise.
const DEFAULT_CACHE_BYTES: usize = 1 << 30;

/// What is current for a feed.
#[derive(Debug, Clone)]
struct Current {
    generation: u64,
    version: String,
    count: u64,
}

type Feeds = Arc<RwLock<HashMap<String, Current>>>;

/// Indicators in `RocksDB`, for sets too large for memory.
///
/// Lookups of what no feed names are answered by a filter in memory, about
/// 10 bits an indicator. The filter is built by reading every key when the
/// store is opened, and again when replaced feeds have left it stale.
pub struct RocksStore {
    db: DB,
    feeds: Feeds,
    bloom: RwLock<Arc<Bloom>>,
    lengths: RwLock<PrefixLengths>,
    /// Held while a feed is replaced: one replacement at a time.
    writer: Mutex<()>,
}

impl std::fmt::Debug for RocksStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RocksStore")
            .field("path", &self.db.path())
            .finish_non_exhaustive()
    }
}

fn failed(error: impl std::fmt::Display) -> IntelError {
    IntelError::Store(error.to_string())
}

impl RocksStore {
    /// Opens the store in `directory`, creating it if it is not there, with
    /// a block cache of one gibibyte.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Store`] if the directory cannot be opened as a
    /// store, such as when another process holds it.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, IntelError> {
        Self::open_with(directory, DEFAULT_CACHE_BYTES)
    }

    /// The same, with a block cache of `cache_bytes`.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub fn open_with(directory: impl AsRef<Path>, cache_bytes: usize) -> Result<Self, IntelError> {
        let feeds: Feeds = Arc::default();

        let mut table = BlockBasedOptions::default();
        table.set_block_cache(&Cache::new_lru_cache(cache_bytes));
        table.set_bloom_filter(10.0, false);
        let mut indicators = Options::default();
        indicators.set_block_based_table_factory(&table);
        indicators.set_compression_type(DBCompressionType::Lz4);
        let current = Arc::clone(&feeds);
        indicators.set_compaction_filter(
            "superseded-generations",
            move |_, key: &[u8], _: &[u8]| {
                let feeds = current.read().unwrap_or_else(PoisonError::into_inner);
                match split(key) {
                    // Kept while its feed has no generation as new: it may be
                    // the one being written.
                    Some((_, feed, generation))
                        if feeds
                            .get(feed)
                            .is_some_and(|current| generation < current.generation) =>
                    {
                        CompactionDecision::Remove
                    }
                    _ => CompactionDecision::Keep,
                }
            },
        );

        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let db = DB::open_cf_descriptors(
            &options,
            directory,
            [
                ColumnFamilyDescriptor::new("default", Options::default()),
                ColumnFamilyDescriptor::new(INDICATORS, indicators),
            ],
        )
        .map_err(failed)?;

        {
            let mut feeds = feeds.write().unwrap_or_else(PoisonError::into_inner);
            for entry in db.iterator(IteratorMode::From(FEED, Direction::Forward)) {
                let (key, value) = entry.map_err(failed)?;
                let Some(name) = key.strip_prefix(FEED) else {
                    break;
                };
                let (Ok(name), Some(current)) = (std::str::from_utf8(name), current_of(&value))
                else {
                    return Err(failed("a feed's record cannot be read"));
                };
                feeds.insert(name.to_owned(), current);
            }
        }

        let store = Self {
            db,
            feeds,
            bloom: RwLock::new(Arc::new(Bloom::new(0))),
            lengths: RwLock::default(),
            writer: Mutex::new(()),
        };
        store.build_filter(0)?;
        Ok(store)
    }

    /// The feeds held, each with its version and how many indicators it
    /// asserts, by name.
    pub fn feeds(&self) -> Vec<(String, String, u64)> {
        let mut feeds: Vec<_> = self
            .feeds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(name, current)| (name.clone(), current.version.clone(), current.count))
            .collect();
        feeds.sort();
        feeds
    }

    /// The bytes the filter takes in memory.
    pub fn filter_bytes(&self) -> usize {
        self.bloom
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes()
    }

    /// Drops the entries of replaced feeds now, which otherwise happens as
    /// files are compacted. Takes as long as rewriting the store.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Store`] if the store cannot be written.
    pub fn compact(&self) -> Result<(), IntelError> {
        let indicators = self.indicators()?;
        self.db.flush_cf(indicators).map_err(failed)?;
        self.db
            .compact_range_cf(indicators, None::<&[u8]>, None::<&[u8]>);
        Ok(())
    }

    fn indicators(&self) -> Result<&rocksdb::ColumnFamily, IntelError> {
        self.db
            .cf_handle(INDICATORS)
            .ok_or_else(|| failed("the indicators are missing"))
    }

    /// Builds the filter and the prefix lengths from the current entries,
    /// sized for them and `more` to come, and for as many again.
    fn build_filter(&self, more: u64) -> Result<(), IntelError> {
        let expected: u64 = self
            .feeds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|current| current.count)
            .sum();
        let room = expected.saturating_add(more).saturating_mul(2);
        let bloom = Bloom::new(usize::try_from(room).unwrap_or(usize::MAX));
        let mut lengths = PrefixLengths::default();
        {
            let feeds = self.feeds.read().unwrap_or_else(PoisonError::into_inner);
            for entry in self.db.iterator_cf(self.indicators()?, IteratorMode::Start) {
                let (key, _) = entry.map_err(failed)?;
                let Some((indicator, feed, generation)) = split(&key) else {
                    continue;
                };
                if feeds
                    .get(feed)
                    .is_some_and(|current| current.generation == generation)
                {
                    bloom.add(indicator);
                    if let Some(key) = Key::from_bytes(indicator) {
                        lengths.add(&key);
                    }
                }
            }
        }
        *self.bloom.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(bloom);
        *self.lengths.write().unwrap_or_else(PoisonError::into_inner) = lengths;
        Ok(())
    }
}

impl Store for RocksStore {
    fn assertions(&self, key: &Key) -> Result<Vec<Assertion>, IntelError> {
        let indicator = key.to_bytes();
        let bloom = Arc::clone(&self.bloom.read().unwrap_or_else(PoisonError::into_inner));
        if !bloom.may_contain(&indicator) {
            return Ok(Vec::new());
        }

        // Every entry of the indicator: its bytes, the separator, a feed.
        let mut from = indicator;
        from.push(0);
        let mut until = from.clone();
        until.pop();
        until.push(1);
        let mut options = ReadOptions::default();
        options.set_iterate_upper_bound(until);
        let entries = self.db.iterator_cf_opt(
            self.indicators()?,
            options,
            IteratorMode::From(&from, Direction::Forward),
        );

        let feeds = self.feeds.read().unwrap_or_else(PoisonError::into_inner);
        let mut assertions = Vec::new();
        for entry in entries {
            let (key, value) = entry.map_err(failed)?;
            let Some((_, feed, generation)) = split(&key) else {
                continue;
            };
            let Some(current) = feeds
                .get(feed)
                .filter(|current| current.generation == generation)
            else {
                continue;
            };
            let mut assertion =
                decode(&value).ok_or_else(|| failed("an assertion cannot be read"))?;
            feed.clone_into(&mut assertion.feed);
            current.version.clone_into(&mut assertion.version);
            assertions.push(assertion);
        }
        Ok(assertions)
    }

    fn prefix_lengths(&self) -> PrefixLengths {
        *self.lengths.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn replace_feed(
        &self,
        feed: &str,
        version: &str,
        indicators: impl IntoIterator<Item = (Key, Assertion)>,
    ) -> Result<Replaced, IntelError> {
        if feed.is_empty() || feed.contains('\0') {
            return Err(failed("a feed needs a name without a NUL"));
        }
        let _writing = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut durable = WriteOptions::default();
        durable.set_sync(true);

        // A generation is given out once, and recorded before it is used:
        // entries left by a replacement that did not finish are of a
        // generation that is never current.
        let generation = match self.db.get(GENERATION).map_err(failed)? {
            Some(last) => number(&last).ok_or_else(|| failed("the generation cannot be read"))? + 1,
            None => 1,
        };
        let mut batch = WriteBatch::default();
        batch.put(GENERATION, generation.to_be_bytes());
        self.db.write_opt(batch, &durable).map_err(failed)?;

        // The filter must hold the new generation before it is current. If
        // it has no room, it is built again with room, away from readers,
        // who keep the one they have.
        let indicators = indicators.into_iter();
        let expected = indicators.size_hint().0 as u64;
        if self
            .bloom
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .room()
            < expected
        {
            self.build_filter(expected)?;
        }
        let bloom = Arc::clone(&self.bloom.read().unwrap_or_else(PoisonError::into_inner));

        // The new generation, beside the old. An indicator named twice
        // overwrites itself, so the later assertion is kept.
        let before = self
            .feeds
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(feed)
            .map(|current| current.generation);
        let mut lengths = self.prefix_lengths();
        let mut chunk = Vec::with_capacity(CHUNK);
        let (mut count, mut added) = (0usize, 0usize);
        for (key, assertion) in indicators {
            let indicator = key.to_bytes();
            lengths.add(&key);
            chunk.push((indicator, assertion));
            count += 1;
            if chunk.len() >= CHUNK {
                added += self.write_chunk(&mut chunk, feed, before, generation, &bloom)?;
            }
        }
        added += self.write_chunk(&mut chunk, feed, before, generation, &bloom)?;
        // Networks of the new generation are probed from now; a length no
        // feed uses any longer costs a lookup that finds nothing.
        *self.lengths.write().unwrap_or_else(PoisonError::into_inner) = lengths;

        // The one write that replaces the feed.
        let current = Current {
            generation,
            version: version.to_owned(),
            count: count as u64,
        };
        let mut batch = WriteBatch::default();
        batch.put([FEED, feed.as_bytes()].concat(), record_of(&current));
        self.db.write_opt(batch, &durable).map_err(failed)?;
        self.feeds
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(feed.to_owned(), current);

        // Replaced generations stay in the filter until it is built again.
        if bloom.is_full() {
            self.build_filter(0)?;
        }
        Ok(Replaced {
            indicators: count,
            added,
        })
    }
}

impl RocksStore {
    /// Writes the indicators of `chunk` as entries of `generation`, emptying
    /// it, and returns how many the feed did not assert in the generation
    /// `before`. One it did keeps when it was added.
    fn write_chunk(
        &self,
        chunk: &mut Vec<(Vec<u8>, Assertion)>,
        feed: &str,
        before: Option<u64>,
        generation: u64,
        bloom: &Bloom,
    ) -> Result<usize, IntelError> {
        let column = self.indicators()?;
        let mut added = chunk.len();
        if let Some(before) = before {
            // An indicator the filter does not hold was in no generation:
            // only the others are read. Read before any is added to it.
            let held: Vec<usize> = (0..chunk.len())
                .filter(|&index| bloom.may_contain(&chunk[index].0))
                .collect();
            let earlier = self.db.multi_get_cf(
                held.iter()
                    .map(|&index| (column, entry_key(&chunk[index].0, feed, before))),
            );
            for (index, earlier) in held.into_iter().zip(earlier) {
                if let Some(value) = earlier.map_err(failed)? {
                    let earlier =
                        decode(&value).ok_or_else(|| failed("an assertion cannot be read"))?;
                    chunk[index].1.added = earlier.added;
                    added -= 1;
                }
            }
        }
        let mut batch = WriteBatch::default();
        for (indicator, assertion) in chunk.drain(..) {
            bloom.add(&indicator);
            batch.put_cf(
                column,
                entry_key(&indicator, feed, generation),
                encode(&assertion),
            );
        }
        self.db.write(batch).map_err(failed)?;
        Ok(added)
    }
}

/// The key of an entry: the indicator, the feed, and the generation.
fn entry_key(indicator: &[u8], feed: &str, generation: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(indicator.len() + feed.len() + 10);
    key.extend_from_slice(indicator);
    key.push(0);
    key.extend_from_slice(feed.as_bytes());
    key.push(0);
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

/// An entry's key as its indicator, feed, and generation. Neither an
/// indicator nor a feed holds a NUL, so the first one ends the indicator.
fn split(key: &[u8]) -> Option<(&[u8], &str, u64)> {
    let (rest, generation) = key.split_last_chunk::<8>()?;
    let rest = rest.strip_suffix(&[0])?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    let (indicator, feed) = (rest.get(..end)?, rest.get(end + 1..)?);
    Some((
        indicator,
        std::str::from_utf8(feed).ok()?,
        u64::from_be_bytes(*generation),
    ))
}

fn number(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

/// What is current for a feed, as stored: the generation, the count, and
/// the version.
fn record_of(current: &Current) -> Vec<u8> {
    let mut record = Vec::with_capacity(16 + current.version.len());
    record.extend_from_slice(&current.generation.to_be_bytes());
    record.extend_from_slice(&current.count.to_be_bytes());
    record.extend_from_slice(current.version.as_bytes());
    record
}

fn current_of(record: &[u8]) -> Option<Current> {
    let (generation, rest) = record.split_first_chunk::<8>()?;
    let (count, version) = rest.split_first_chunk::<8>()?;
    Some(Current {
        generation: u64::from_be_bytes(*generation),
        version: std::str::from_utf8(version).ok()?.to_owned(),
        count: u64::from_be_bytes(*count),
    })
}

/// An assertion as stored: the confidence, which times are present, and
/// those times. The feed and its version are not repeated in every entry.
/// An entry written before `added` was kept has none, and reads so.
fn encode(assertion: &Assertion) -> Vec<u8> {
    let times = [
        assertion.valid_from,
        assertion.valid_until,
        assertion.first_seen,
        assertion.last_seen,
        assertion.added,
    ];
    let mut present = 0u8;
    let mut value = vec![assertion.confidence, 0];
    for (index, time) in times.iter().enumerate() {
        if let Some(time) = time {
            present |= 1 << index;
            value.extend_from_slice(&time.to_be_bytes());
        }
    }
    value[1] = present;
    value
}

fn decode(value: &[u8]) -> Option<Assertion> {
    let (&[confidence, present], mut rest) = value.split_first_chunk::<2>()?;
    let mut times = [None; 5];
    for (index, time) in times.iter_mut().enumerate() {
        if present & (1 << index) != 0 {
            let (bytes, after) = rest.split_first_chunk::<8>()?;
            *time = Some(i64::from_be_bytes(*bytes));
            rest = after;
        }
    }
    let mut assertion = Assertion::new(confidence)
        .valid(times[0], times[1])
        .seen(times[2], times[3]);
    assertion.added = times[4];
    Some(assertion)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use rocksdb::IteratorMode;

    use super::{RocksStore, decode, encode, entry_key, split};
    use crate::{Assertion, Key, Kind, Store};

    #[test]
    fn an_entry_key_splits_into_what_made_it() {
        let indicator = Key::new(Kind::Domain, "bad.example.com")
            .expect("a key")
            .to_bytes();
        // A generation whose bytes hold NULs, as most do.
        let key = entry_key(&indicator, "feed-a", 256);
        assert_eq!(split(&key), Some((&indicator[..], "feed-a", 256)));
        assert_eq!(split(b"short"), None);
    }

    #[test]
    fn an_assertion_is_stored_with_the_times_it_has() {
        for assertion in [
            Assertion::new(70),
            Assertion::new(0).valid(Some(-5), None),
            Assertion::new(100)
                .valid(Some(1), Some(2))
                .seen(Some(i64::MIN), Some(i64::MAX)),
            Assertion::new(1).seen(None, Some(9)),
            Assertion::new(1).seen(None, Some(9)).added_at(7),
        ] {
            assert_eq!(decode(&encode(&assertion)), Some(assertion));
        }
        assert_eq!(encode(&Assertion::new(70)).len(), 2);
        // An entry written before `added` was kept reads as having none.
        assert_eq!(
            decode(&[70, 0b1000, 0, 0, 0, 0, 0, 0, 0, 9]),
            Some(Assertion::new(70).seen(None, Some(9)))
        );
        assert_eq!(decode(&[70, 1, 0]), None);
    }

    #[test]
    fn compaction_drops_the_generations_a_feed_replaced() {
        let directory = tempfile::tempdir().expect("a directory");
        let store = RocksStore::open_with(directory.path(), 1 << 20).expect("opened");
        let entries = |store: &RocksStore| {
            store
                .db
                .iterator_cf(store.indicators().expect("a column"), IteratorMode::Start)
                .count()
        };
        let feed = |version: &str, range: std::ops::Range<u32>| {
            store
                .replace_feed(
                    "feed-a",
                    version,
                    range.map(|index| {
                        (
                            Key::new(Kind::Domain, &format!("host-{index}.example.com"))
                                .expect("a key"),
                            Assertion::new(50),
                        )
                    }),
                )
                .expect("replaced");
        };
        feed("1", 0..100);
        store
            .replace_feed(
                "feed-b",
                "1",
                [(
                    Key::new(Kind::Ip, "203.0.113.7").expect("a key"),
                    Assertion::new(50),
                )],
            )
            .expect("replaced");
        feed("2", 50..120);
        // Both generations are on disk until files are compacted.
        assert_eq!(entries(&store), 171);
        store.compact().expect("compacted");
        assert_eq!(entries(&store), 71);
        assert_eq!(
            store.feeds(),
            [
                ("feed-a".to_owned(), "2".to_owned(), 70),
                ("feed-b".to_owned(), "1".to_owned(), 1)
            ]
        );
    }
}
