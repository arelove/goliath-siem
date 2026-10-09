//! The snapshot: every source's records, and how one is found.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use crate::record::{Id, IdKind, Kind, Range, Record};

/// A record found, and the source that holds it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Found<'a> {
    /// The source's name.
    pub source: &'a str,
    /// The source's version when it was loaded.
    pub version: &'a str,
    /// The record.
    pub record: &'a Record,
    /// The record stopped holding before the time asked for, and nothing
    /// of its source holds in its place: an account that was closed, a
    /// machine that was retired.
    pub ended: bool,
    /// The range that held the address, if the record was found by one.
    pub range: Option<Range>,
}

struct Source {
    version: String,
    records: Vec<Record>,
}

/// The records of every source, in memory.
///
/// A source is replaced whole: its records are those of its last load and
/// no other. Sources are never merged, so a lookup gives what each one
/// says, under its name.
#[derive(Default)]
pub struct Snapshot {
    sources: BTreeMap<String, Source>,
    /// Where each identifier's records are: the source and the place in it.
    by_id: HashMap<Id, Vec<(String, usize)>>,
    /// The same for each range.
    by_range: HashMap<Range, Vec<(String, usize)>>,
    /// The prefix lengths that some range has, for each family, so that a
    /// lookup asks only for those.
    lengths: BTreeSet<(bool, u8)>,
}

impl Snapshot {
    /// A snapshot that holds nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts `records` in the place of everything `source` held, as its
    /// `version`. Returns how many it holds now.
    pub fn replace(&mut self, source: &str, version: &str, records: Vec<Record>) -> usize {
        let count = records.len();
        self.sources.insert(
            source.to_owned(),
            Source {
                version: version.to_owned(),
                records,
            },
        );
        self.index();
        count
    }

    /// Removes `source` and its records. Returns whether it was held.
    pub fn remove(&mut self, source: &str) -> bool {
        let held = self.sources.remove(source).is_some();
        if held {
            self.index();
        }
        held
    }

    /// The sources held: each one's name, version, and number of records.
    pub fn sources(&self) -> Vec<(&str, &str, usize)> {
        self.sources
            .iter()
            .map(|(name, source)| (name.as_str(), source.version.as_str(), source.records.len()))
            .collect()
    }

    // The whole index is made again: a replacement is rare beside lookups,
    // and what is left of a replaced source cannot then be found.
    fn index(&mut self) {
        self.by_id.clear();
        self.by_range.clear();
        self.lengths.clear();
        for (name, source) in &self.sources {
            for (place, record) in source.records.iter().enumerate() {
                for id in &record.ids {
                    self.by_id
                        .entry(id.clone())
                        .or_default()
                        .push((name.clone(), place));
                }
                for range in &record.ranges {
                    self.by_range
                        .entry(*range)
                        .or_default()
                        .push((name.clone(), place));
                    self.lengths.insert((range.network.is_ipv4(), range.length));
                }
            }
        }
    }

    fn record(&self, source: &str, place: usize) -> Option<(&str, &Source, &Record)> {
        let (name, held) = self.sources.get_key_value(source)?;
        Some((name.as_str(), held, held.records.get(place)?))
    }

    /// What every source says of `id`, for an event of `scope` at `at`, in
    /// seconds since the epoch.
    ///
    /// - A record is found if it lists `id`, is of that scope or of none,
    ///   and holds at `at`.
    /// - If a source lists `id` only in records that ended before `at`, the
    ///   last of them is found, marked as ended.
    /// - An address is also found by the ranges that hold it: of each
    ///   source and kind of record, the narrowest.
    pub fn lookup(&self, id: &Id, scope: Option<&str>, at: i64) -> Vec<Found<'_>> {
        let mut found = Vec::new();
        // By the identifier itself, source by source.
        let mut ended: BTreeMap<&str, Found<'_>> = BTreeMap::new();
        let mut holding: BTreeSet<&str> = BTreeSet::new();
        for (source, place) in self.by_id.get(id).into_iter().flatten() {
            let Some((name, held, record)) = self.record(source, *place) else {
                continue;
            };
            let entry = Found {
                source: name,
                version: &held.version,
                record,
                ended: false,
                range: None,
            };
            if record.holds(scope, at) {
                holding.insert(name);
                found.push(entry);
            } else if record.scope.as_deref().is_none_or(|own| Some(own) == scope)
                && record.valid_until.is_some_and(|until| until <= at)
            {
                let later = ended
                    .get(name)
                    .is_none_or(|kept| kept.record.valid_until < record.valid_until);
                if later {
                    ended.insert(
                        name,
                        Found {
                            ended: true,
                            ..entry
                        },
                    );
                }
            }
        }
        found.extend(
            ended
                .into_iter()
                .filter(|(name, _)| !holding.contains(name))
                .map(|(_, entry)| entry),
        );
        if let Some(address) = id.address() {
            self.ranges(address, scope, at, &mut found);
        }
        if id.kind() == IdKind::Host {
            self.domains(id, scope, at, &mut found);
        }
        found
    }

    /// The rows of context lists that name a domain `host` is under: a
    /// list of dynamic DNS domains describes every name registered in one.
    /// Of each source the nearest domain is taken. Assets are found by
    /// their own name alone.
    fn domains<'a>(&'a self, host: &Id, scope: Option<&str>, at: i64, found: &mut Vec<Found<'a>>) {
        let mut taken: BTreeSet<&str> = found
            .iter()
            .filter(|entry| entry.record.kind == Kind::List)
            .map(|entry| entry.source)
            .collect();
        let mut name = host.value();
        while let Some((_, parent)) = name.split_once('.') {
            name = parent;
            let Ok(parent) = Id::new(IdKind::Host, parent) else {
                break;
            };
            for (source, place) in self.by_id.get(&parent).into_iter().flatten() {
                let Some((source, held, record)) = self.record(source, *place) else {
                    continue;
                };
                if record.kind == Kind::List && record.holds(scope, at) && taken.insert(source) {
                    found.push(Found {
                        source,
                        version: &held.version,
                        record,
                        ended: false,
                        range: None,
                    });
                }
            }
        }
    }

    /// The narrowest range of each source and kind that holds `address`.
    fn ranges<'a>(
        &'a self,
        address: IpAddr,
        scope: Option<&str>,
        at: i64,
        found: &mut Vec<Found<'a>>,
    ) {
        let mut taken = BTreeSet::new();
        // The longest prefix first, so that the first of a source is the
        // narrowest.
        for (_, length) in self
            .lengths
            .iter()
            .rev()
            .filter(|(is_v4, _)| *is_v4 == address.is_ipv4())
        {
            let range = Range::holding(address, *length);
            for (source, place) in self.by_range.get(&range).into_iter().flatten() {
                let Some((name, held, record)) = self.record(source, *place) else {
                    continue;
                };
                if record.holds(scope, at) && taken.insert((name, record.kind)) {
                    found.push(Found {
                        source: name,
                        version: &held.version,
                        record,
                        ended: false,
                        range: Some(range),
                    });
                }
            }
        }
    }
}
