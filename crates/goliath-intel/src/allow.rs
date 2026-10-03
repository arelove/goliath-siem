//! Allowlists: what is never reported, whatever a feed says.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::IntelError;
use crate::key::{Key, Kind, PrefixLengths};

/// An allowlist as a file: versioned, reviewed content beside rules.
///
/// ```yaml
/// name: infrastructure
/// version: 3
/// entries:
///   - { kind: ip, value: 8.8.8.8, reason: Public DNS resolver }
///   - { kind: cidr, value: 10.0.0.0/8, reason: Internal network }
///   - { kind: domain, value: "*.windowsupdate.com", reason: Windows Update }
/// ```
///
/// A network allows every address in it. A domain written `*.name` allows
/// `name` and every name under it. A domain or an address allows the URLs on
/// that host.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    /// The list's name, which a suppression is reported with.
    pub name: String,
    /// The list's version.
    pub version: u32,
    /// What it allows.
    pub entries: Vec<Entry>,
}

/// One allowed value, and why.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// What the value is.
    pub kind: Kind,
    /// The value, in any spelling [`Key::new`] reads; a domain may begin
    /// with `*.`.
    pub value: String,
    /// Why it is allowed. Required: an entry nobody can explain is removed
    /// by nobody.
    pub reason: String,
}

impl Allowlist {
    /// Reads a list from YAML, as untrusted input.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Yaml`] if the YAML is malformed or is not a
    /// list.
    pub fn from_yaml(source: &str) -> Result<Self, IntelError> {
        Ok(goliath_sigma::yaml::from_str(source)?)
    }
}

/// The entry that suppressed a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    /// The list's name.
    pub list: String,
    /// The list's version.
    pub version: u32,
    /// The entry's value as the list writes it.
    pub entry: String,
    /// The entry's reason.
    pub reason: String,
}

/// Every allowlist in force, ready to be asked.
#[derive(Debug, Clone, Default)]
pub struct Allowlists {
    exact: HashMap<Key, usize>,
    /// Domains written `*.name`, by `name`.
    under: HashMap<String, usize>,
    lengths: PrefixLengths,
    allowed: Vec<Allowed>,
}

impl Allowlists {
    /// The lists together. Of two entries for one value, the first list's
    /// is reported.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Allowlist`] if two lists share a name, a
    /// reason is empty, or a value cannot be of its kind.
    pub fn new(lists: &[Allowlist]) -> Result<Self, IntelError> {
        let mut all = Self::default();
        let mut names = HashSet::new();
        for list in lists {
            let refuse = |why: String| IntelError::Allowlist {
                list: list.name.clone(),
                why,
            };
            if !names.insert(list.name.as_str()) {
                return Err(refuse("another list has this name".to_owned()));
            }
            for entry in &list.entries {
                if entry.reason.trim().is_empty() {
                    return Err(refuse(format!("`{}` has no reason", entry.value)));
                }
                let (wildcard, value) = match entry.value.strip_prefix("*.") {
                    Some(name) if entry.kind == Kind::Domain => (true, name),
                    _ => (false, entry.value.as_str()),
                };
                let key = Key::new(entry.kind, value).map_err(|error| refuse(error.to_string()))?;
                let index = all.allowed.len();
                all.allowed.push(Allowed {
                    list: list.name.clone(),
                    version: list.version,
                    entry: entry.value.clone(),
                    reason: entry.reason.clone(),
                });
                all.lengths.add(&key);
                if wildcard {
                    all.under.entry(key.value().to_owned()).or_insert(index);
                }
                all.exact.entry(key).or_insert(index);
            }
        }
        Ok(all)
    }

    /// How many entries are in force.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Whether no entry is in force.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// The entry that allows `key`, if one does.
    pub fn allows(&self, key: &Key) -> Option<&Allowed> {
        self.entry(key)
            .or_else(|| key.host().and_then(|host| self.entry(&host)))
            .and_then(|index| self.allowed.get(index))
    }

    fn entry(&self, key: &Key) -> Option<usize> {
        if let Some(index) = self.exact.get(key) {
            return Some(*index);
        }
        if let Some(address) = key.address() {
            return self
                .lengths
                .networks(address)
                .find_map(|network| self.exact.get(&network).copied());
        }
        if key.kind() == Kind::Domain && !self.under.is_empty() {
            let mut name = key.value();
            while let Some((_, parent)) = name.split_once('.') {
                if let Some(index) = self.under.get(parent) {
                    return Some(*index);
                }
                name = parent;
            }
        }
        None
    }
}
