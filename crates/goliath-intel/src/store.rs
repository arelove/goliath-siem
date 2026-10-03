//! Where indicators are kept, and one such place in memory.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use crate::key::{Key, PrefixLengths};
use crate::{Assertion, IntelError};

/// A set of indicators, each with what every feed asserts of it.
///
/// A feed is replaced whole and never edited: a reader sees a feed as it was
/// or as it is, never half of each. Indicators are not merged into one flat
/// set; an indicator keeps the assertion of every feed that names it. See
/// `docs/adr/0020-state-beyond-events.md`.
pub trait Store {
    /// What each feed asserts of `key`; empty if none names it.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Store`] if the store cannot be read.
    fn assertions(&self, key: &Key) -> Result<Vec<Assertion>, IntelError>;

    /// The prefix lengths of the networks held.
    fn prefix_lengths(&self) -> PrefixLengths;

    /// Replaces everything `feed` asserted with `indicators`, each asserted
    /// at the feed's `version`, and returns how many it now asserts. An
    /// indicator named twice keeps the later assertion.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Store`] if the store cannot be written; the
    /// feed is then as it was.
    fn replace_feed(
        &self,
        feed: &str,
        version: &str,
        indicators: impl IntoIterator<Item = (Key, Assertion)>,
    ) -> Result<usize, IntelError>;
}

/// A store in memory, for tests and for sets small enough to hold there.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    indicators: HashMap<Key, Vec<Assertion>>,
    lengths: PrefixLengths,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many indicators it holds, whatever the number of feeds that
    /// assert each.
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .indicators
            .len()
    }

    /// Whether it holds no indicator.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Store for MemoryStore {
    fn assertions(&self, key: &Key) -> Result<Vec<Assertion>, IntelError> {
        Ok(self
            .inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .indicators
            .get(key)
            .cloned()
            .unwrap_or_default())
    }

    fn prefix_lengths(&self) -> PrefixLengths {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .lengths
    }

    fn replace_feed(
        &self,
        feed: &str,
        version: &str,
        indicators: impl IntoIterator<Item = (Key, Assertion)>,
    ) -> Result<usize, IntelError> {
        // Gathered before the lock is taken, so readers wait for the swap
        // alone and not for the feed to be read.
        let mut incoming: HashMap<Key, Assertion> = HashMap::new();
        for (key, mut assertion) in indicators {
            feed.clone_into(&mut assertion.feed);
            version.clone_into(&mut assertion.version);
            incoming.insert(key, assertion);
        }
        let count = incoming.len();

        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.indicators.retain(|_, assertions| {
            assertions.retain(|assertion| assertion.feed != feed);
            !assertions.is_empty()
        });
        for (key, assertion) in incoming {
            inner.indicators.entry(key).or_default().push(assertion);
        }
        let mut lengths = PrefixLengths::default();
        for (key, assertions) in &mut inner.indicators {
            lengths.add(key);
            assertions.sort_by(|a, b| a.feed.cmp(&b.feed));
        }
        inner.lengths = lengths;
        Ok(count)
    }
}
