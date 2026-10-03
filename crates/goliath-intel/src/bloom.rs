//! The filter in front of the store on disk: it answers "certainly not an
//! indicator" from memory, which is the answer for nearly every observable.

use std::hash::{BuildHasher, BuildHasherDefault, DefaultHasher};
use std::sync::atomic::{AtomicU64, Ordering};

/// Bits for each expected key. At eight bits set in one 512-bit block this
/// gives about one false positive in a hundred lookups; a false positive
/// costs one read of the store and never a hit.
const BITS_PER_KEY: usize = 10;
/// Bits a key sets, all in one block.
const PROBES: u32 = 8;
/// Words in a block: 512 bits, one cache line.
const BLOCK: usize = 8;

/// A blocked bloom filter that is added to while it is read. Keys are never
/// removed; a filter grown stale or full is built again.
#[derive(Debug)]
pub(crate) struct Bloom {
    words: Vec<AtomicU64>,
    blocks: usize,
    capacity: usize,
    added: AtomicU64,
}

impl Bloom {
    /// A filter sized for `capacity` keys.
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1024);
        let blocks = (capacity * BITS_PER_KEY).div_ceil(BLOCK * 64);
        Self {
            words: (0..blocks * BLOCK).map(|_| AtomicU64::new(0)).collect(),
            blocks,
            capacity,
            added: AtomicU64::new(0),
        }
    }

    /// Whether more keys were added than it was sized for, so that false
    /// positives pass its budget.
    pub(crate) fn is_full(&self) -> bool {
        usize::try_from(self.added.load(Ordering::Relaxed)).unwrap_or(usize::MAX) > self.capacity
    }

    /// How many more keys it was sized for.
    pub(crate) fn room(&self) -> u64 {
        (self.capacity as u64).saturating_sub(self.added.load(Ordering::Relaxed))
    }

    /// The bytes it takes in memory.
    pub(crate) fn bytes(&self) -> usize {
        self.words.len() * 8
    }

    pub(crate) fn add(&self, key: &[u8]) {
        self.added.fetch_add(1, Ordering::Relaxed);
        self.each(key, |word, bit| {
            word.fetch_or(bit, Ordering::Relaxed);
            true
        });
    }

    /// False if `key` was never added; true if it was, or by chance.
    pub(crate) fn may_contain(&self, key: &[u8]) -> bool {
        self.each(key, |word, bit| word.load(Ordering::Relaxed) & bit != 0)
    }

    /// Visits the bits of `key` until `visit` says to stop, and says whether
    /// it never did.
    fn each(&self, key: &[u8], mut visit: impl FnMut(&AtomicU64, u64) -> bool) -> bool {
        let hash = BuildHasherDefault::<DefaultHasher>::default().hash_one(key);
        // The high bits choose the block; a sequence seeded with the hash,
        // each of its numbers mixed, chooses the bits in it.
        let block = usize::try_from((u128::from(mixed(hash) >> 32) * self.blocks as u128) >> 32)
            .unwrap_or_default();
        let mut state = hash;
        for _ in 0..PROBES {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            // Nine bits: three for the word, six for the bit in it.
            let position = usize::try_from(mixed(state) & 0x1ff).unwrap_or_default();
            let Some(word) = self.words.get(block * BLOCK + position / 64) else {
                return true;
            };
            if !visit(word, 1 << (position % 64)) {
                return false;
            }
        }
        true
    }
}

/// The finalizer of `SplitMix64`: every bit of the result depends on every
/// bit of `value`.
fn mixed(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::Bloom;

    #[test]
    fn what_was_added_is_found_and_little_else() {
        let bloom = Bloom::new(100_000);
        for index in 0..100_000u32 {
            bloom.add(format!("indicator-{index}").as_bytes());
        }
        assert!(!bloom.is_full());
        for index in 0..100_000u32 {
            assert!(bloom.may_contain(format!("indicator-{index}").as_bytes()));
        }
        let false_positives = (0..100_000u32)
            .filter(|index| bloom.may_contain(format!("absent-{index}").as_bytes()))
            .count();
        // About 1% expected; 3% leaves room for the blocks' unevenness.
        assert!(false_positives < 3_000, "{false_positives}");
        assert_eq!(bloom.bytes(), 125_056);
        bloom.add(b"one more");
        assert!(bloom.is_full());
    }
}
