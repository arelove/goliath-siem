//! Threat intelligence: indicators in one canonical spelling, what every
//! feed asserts of each, allowlists that take precedence, and the lookup an
//! event's observables go through.
//!
//! An indicator is never merged into a flat set: it keeps the assertion of
//! every feed that names it, so a hit says which feed, at which version, with
//! what confidence, and for how long. An allowlist entry suppresses a hit
//! whatever the feeds say, and the suppressed hit is still returned, to be
//! recorded. See `docs/adr/0008-threat-intelligence-model.md` and
//! `docs/adr/0021-enrichment-placement.md`.
//!
//! ```
//! use goliath_intel::{Allowlist, Allowlists, Assertion, Key, Kind, Matcher, MemoryStore, Store};
//!
//! let store = MemoryStore::new();
//! store.replace_feed(
//!     "example-feed",
//!     "2026-10-03",
//!     [(Key::new(Kind::Domain, "Bad.Example[.]com")?, Assertion::new(80))],
//! )?;
//! let allowlists = Allowlists::new(&[Allowlist::from_yaml(
//!     "name: infrastructure\nversion: 1\nentries:\n  - { kind: ip, value: 8.8.8.8, reason: Public DNS resolver }\n",
//! )?])?;
//! let matcher = Matcher::new(store, allowlists);
//!
//! let hits = matcher.lookup(Kind::Domain, "bad.example.com.", 1_780_000_000)?;
//! assert_eq!(hits[0].assertions[0].feed, "example-feed");
//! assert!(hits[0].suppressed.is_none());
//! # Ok::<(), goliath_intel::IntelError>(())
//! ```

mod allow;
#[cfg(feature = "rocksdb")]
mod bloom;
mod feed;
mod finding;
mod key;
mod matcher;
mod observe;
#[cfg(feature = "rocksdb")]
mod rocks;
mod stix;
mod store;

pub use allow::{Allowed, Allowlist, Allowlists, Entry};
pub use feed::{Csv, Feed, Format, Loaded, Parsed};
pub use finding::{finding, finding_uid};
pub use key::{Key, Kind, PrefixLengths};
pub use matcher::{Hit, Matcher};
pub use observe::{Observed, observables};
#[cfg(feature = "rocksdb")]
pub use rocks::RocksStore;
pub use store::{MemoryStore, Store};

/// The definition of abuse.ch Feodo Tracker shipped with this crate, ready
/// for [`Feed::from_yaml`].
pub const FEODO_TRACKER: &str = include_str!("../feeds/feodo-tracker.yaml");
/// The definition of abuse.ch SSLBL shipped with this crate.
pub const SSLBL: &str = include_str!("../feeds/sslbl.yaml");
/// The definition of abuse.ch `ThreatFox` shipped with this crate.
pub const THREATFOX: &str = include_str!("../feeds/threatfox.yaml");
/// The definition of abuse.ch `URLhaus` shipped with this crate.
pub const URLHAUS: &str = include_str!("../feeds/urlhaus.yaml");

/// Every feed definition shipped with this crate, by name.
pub const FEEDS: &[(&str, &str)] = &[
    ("feodo-tracker", FEODO_TRACKER),
    ("sslbl", SSLBL),
    ("threatfox", THREATFOX),
    ("urlhaus", URLHAUS),
];

/// What one feed asserts of an indicator: the provenance a hit is reported
/// with. Times are seconds since the epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The feed. Set by [`Store::replace_feed`].
    pub feed: String,
    /// The feed's version when it asserted this. Set by
    /// [`Store::replace_feed`].
    pub version: String,
    /// The confidence, 0 to 100.
    pub confidence: u8,
    /// From when the indicator holds; always, if the feed does not say.
    pub valid_from: Option<i64>,
    /// Until when the indicator holds, exclusive; without end, if the feed
    /// does not say.
    pub valid_until: Option<i64>,
    /// When the feed first saw it.
    pub first_seen: Option<i64>,
    /// When the feed last saw it.
    pub last_seen: Option<i64>,
}

impl Assertion {
    /// An assertion with `confidence`, capped at 100, and no times.
    pub fn new(confidence: u8) -> Self {
        Self {
            feed: String::new(),
            version: String::new(),
            confidence: confidence.min(100),
            valid_from: None,
            valid_until: None,
            first_seen: None,
            last_seen: None,
        }
    }

    /// The same, holding from `from` until `until`.
    #[must_use]
    pub fn valid(mut self, from: Option<i64>, until: Option<i64>) -> Self {
        self.valid_from = from;
        self.valid_until = until;
        self
    }

    /// The same, seen by the feed first at `first` and last at `last`.
    #[must_use]
    pub fn seen(mut self, first: Option<i64>, last: Option<i64>) -> Self {
        self.first_seen = first;
        self.last_seen = last;
        self
    }

    /// Whether the indicator holds at `at`. An expired indicator stops
    /// matching; what it matched before stays matched.
    pub fn valid_at(&self, at: i64) -> bool {
        self.valid_from.is_none_or(|from| from <= at)
            && self.valid_until.is_none_or(|until| at < until)
    }
}

/// Why intelligence could not be loaded or looked up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntelError {
    /// A value that cannot be of its kind.
    #[error("`{value}` is not a {kind}: {why}")]
    Value {
        /// The kind asked for.
        kind: Kind,
        /// The value as given.
        value: String,
        /// What is wrong with it.
        why: &'static str,
    },
    /// YAML that is malformed or does not fit.
    #[error(transparent)]
    Yaml(#[from] goliath_sigma::YamlError),
    /// An allowlist that cannot be used.
    #[error("allowlist `{list}`: {why}")]
    Allowlist {
        /// The list's name.
        list: String,
        /// What is wrong with it.
        why: String,
    },
    /// A feed whose definition or publication cannot be used.
    #[error("feed `{feed}`: {why}")]
    Feed {
        /// The feed's name.
        feed: String,
        /// What is wrong with it.
        why: String,
    },
    /// A store that could not be read or written.
    #[error("the indicator store: {0}")]
    Store(String),
}
