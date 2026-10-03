//! Looking an observable up: canonical form, the store, validity, and the
//! allowlists.

use crate::allow::{Allowed, Allowlists};
use crate::key::{Key, Kind};
use crate::store::Store;
use crate::{Assertion, IntelError};

/// An observable that an indicator names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The indicator: the observable itself, or a network that holds it.
    pub indicator: Key,
    /// What each feed asserts of it, of those valid at the time asked,
    /// ordered by feed.
    pub assertions: Vec<Assertion>,
    /// The allowlist entry that suppresses it, if one does. A suppressed
    /// hit is still returned, so that it is recorded and not reported.
    pub suppressed: Option<Allowed>,
}

impl Hit {
    /// The highest confidence any feed gives it.
    pub fn confidence(&self) -> u8 {
        self.assertions
            .iter()
            .map(|assertion| assertion.confidence)
            .max()
            .unwrap_or_default()
    }
}

/// Indicators and allowlists, asked together.
#[derive(Debug)]
pub struct Matcher<S> {
    store: S,
    allowlists: Allowlists,
}

impl<S: Store> Matcher<S> {
    /// A matcher over `store`, with `allowlists` taking precedence.
    pub fn new(store: S, allowlists: Allowlists) -> Self {
        Self { store, allowlists }
    }

    /// The store, such as to replace a feed.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The indicators that name `value` as a `kind` and are valid at `at`,
    /// in seconds since the epoch: the value itself, then for an address
    /// the networks that hold it, longest prefix first. Usually none.
    ///
    /// A value that cannot be of its kind, as events hold, matches nothing.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Store`] if the store cannot be read.
    pub fn lookup(&self, kind: Kind, value: &str, at: i64) -> Result<Vec<Hit>, IntelError> {
        let Ok(key) = Key::new(kind, value) else {
            return Ok(Vec::new());
        };
        let mut hits = Vec::new();
        self.hit(&key, &key, at, &mut hits)?;
        if let Some(address) = key.address() {
            for network in self.store.prefix_lengths().networks(address) {
                self.hit(network, &key, at, &mut hits)?;
            }
        }
        Ok(hits)
    }

    /// Adds the hit of `indicator`, if feeds assert it at `at`. Allowlists
    /// are asked of the `observed` value, so that an allowed address is
    /// allowed in every network that holds it.
    fn hit(
        &self,
        indicator: impl std::borrow::Borrow<Key>,
        observed: &Key,
        at: i64,
        hits: &mut Vec<Hit>,
    ) -> Result<(), IntelError> {
        let indicator = indicator.borrow();
        let mut assertions = self.store.assertions(indicator)?;
        assertions.retain(|assertion| assertion.valid_at(at));
        if !assertions.is_empty() {
            hits.push(Hit {
                indicator: indicator.clone(),
                assertions,
                suppressed: self.allowlists.allows(observed).cloned(),
            });
        }
        Ok(())
    }
}
