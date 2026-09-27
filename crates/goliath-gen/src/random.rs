//! Randomness that is the same on every run, platform, and version.
//!
//! A generated organization must be reproducible from its seed for as long as
//! a published benchmark refers to it, so the generator is part of this crate
//! rather than a dependency whose algorithm may change between releases.

/// `SplitMix64`: small, fast, and good enough for synthetic telemetry.
#[derive(Debug, Clone)]
pub(crate) struct Random(u64);

impl Random {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// An independent stream for one purpose, so that adding draws to one
    /// part of the generator does not change what another part produces.
    pub(crate) fn fork(&self, purpose: &str) -> Self {
        let mut state = self.0;
        for byte in purpose.bytes() {
            state = mix(state ^ u64::from(byte));
        }
        Self(state)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mix(self.0)
    }

    /// A number below `bound`, which must not be zero.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        // Lemire's multiply and shift; the bias is below 2^-32 for the
        // bounds used here.
        let product = u128::from(self.next()) * bound as u128;
        usize::try_from(product >> 64).unwrap_or(0)
    }

    /// A number in `0.0..1.0`.
    pub(crate) fn unit(&mut self) -> f64 {
        // The top 53 bits, exactly representable.
        #[allow(clippy::cast_precision_loss)]
        let bits = (self.next() >> 11) as f64;
        bits / (1_u64 << 53) as f64
    }

    pub(crate) fn chance(&mut self, probability: f64) -> bool {
        self.unit() < probability
    }

    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Sixteen random bytes as a lowercase GUID, as Entra ID writes ids.
    pub(crate) fn guid(&mut self) -> String {
        let (high, low) = (self.next(), self.next());
        format!(
            "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            high >> 32,
            (high >> 16) & 0xffff,
            high & 0x0fff,
            0x8000 | (low >> 48) & 0x3fff,
            low & 0xffff_ffff_ffff
        )
    }
}

fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Draws items in proportion to their weights, by binary search over the
/// running totals.
#[derive(Debug, Clone)]
pub(crate) struct Weighted {
    totals: Vec<f64>,
}

impl Weighted {
    pub(crate) fn new(weights: impl IntoIterator<Item = f64>) -> Self {
        let mut total = 0.0;
        let totals = weights
            .into_iter()
            .map(|weight| {
                total += weight.max(0.0);
                total
            })
            .collect();
        Self { totals }
    }

    /// The index of a drawn item. There must be at least one item with a
    /// positive weight.
    pub(crate) fn draw(&self, random: &mut Random) -> usize {
        let total = self.totals.last().copied().unwrap_or(0.0);
        let target = random.unit() * total;
        self.totals
            .partition_point(|&running| running <= target)
            .min(self.totals.len() - 1)
    }
}

/// Weights of a Zipf distribution over `count` ranks with exponent `s`:
/// the first rank is the most frequent, and the tail is long.
pub(crate) fn zipf(count: usize, s: f64) -> Vec<f64> {
    (1..=count)
        .map(|rank| {
            #[allow(clippy::cast_precision_loss)]
            let rank = rank as f64;
            rank.powf(-s)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_values() {
        let (mut first, mut second) = (Random::new(7), Random::new(7));
        for _ in 0..100 {
            assert_eq!(first.next(), second.next());
        }
    }

    #[test]
    fn forks_are_independent_and_reproducible() {
        let root = Random::new(1);
        let (mut people, mut machines) = (root.fork("people"), root.fork("machines"));
        assert_ne!(people.next(), machines.next());
        assert_eq!(root.fork("people").next(), Random::new(1).fork("people").next());
    }

    #[test]
    fn draws_follow_the_weights() {
        let weighted = Weighted::new([1.0, 0.0, 3.0]);
        let mut random = Random::new(3);
        let mut counts = [0; 3];
        for _ in 0..40_000 {
            counts[weighted.draw(&mut random)] += 1;
        }
        assert_eq!(counts[1], 0);
        assert!((9_000..11_000).contains(&counts[0]), "{counts:?}");
        assert!((29_000..31_000).contains(&counts[2]), "{counts:?}");
    }

    #[test]
    fn guids_have_the_version_and_variant_bits() {
        let guid = Random::new(9).guid();
        assert_eq!(guid.len(), 36);
        assert_eq!(&guid[14..15], "4");
        assert!(matches!(&guid[19..20], "8" | "9" | "a" | "b"), "{guid}");
    }
}
