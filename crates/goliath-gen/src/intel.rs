//! Indicators for measuring the detector, and what it takes to plant one in
//! an event.
//!
//! The indicators are numbered. Indicator `n` is the same on every run, and
//! no two are equal, so a set of any size is `0..n` and needs no file to be
//! told apart from another. Of every twenty, nine are IPv4 addresses, six
//! domains, three URLs, and two SHA-256 hashes: the mix the exit criterion
//! of M4 measures with (`docs/adr/0021-enrichment-placement.md`).
//!
//! None of them can occur in the organization's ordinary telemetry. The
//! addresses are in 240.0.0.0/4, which is reserved and routes nowhere; the
//! names end in `.example`; the hashes are of nothing. So every match the
//! detector reports was planted, and one that was not is a defect.

use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::ops::Range;

/// What an indicator is a value of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IndicatorKind {
    /// An IPv4 address.
    Ip,
    /// A host name.
    Domain,
    /// A URL.
    Url,
    /// A SHA-256 hash, in lowercase hexadecimal.
    Sha256,
}

impl IndicatorKind {
    /// The kind as feeds and `goliath-intel` name it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Sha256 => "sha256",
        }
    }
}

/// Of every twenty indicators: where each kind's begin, and how many it has.
const MIX: [(IndicatorKind, u64, u64); 4] = [
    (IndicatorKind::Ip, 0, 9),
    (IndicatorKind::Domain, 9, 6),
    (IndicatorKind::Url, 15, 3),
    (IndicatorKind::Sha256, 18, 2),
];

/// The kind of indicator `index`, and which of its kind it is, from 0.
fn place(index: u64) -> (IndicatorKind, u64) {
    let (round, slot) = (index / 20, index % 20);
    let (kind, start, count) = MIX
        .into_iter()
        .rev()
        .find(|(_, start, _)| slot >= *start)
        .unwrap_or(MIX[0]);
    (kind, round * count + (slot - start))
}

/// The host and the path of the `ordinal`th URL.
fn url_parts(ordinal: u64) -> (String, String) {
    (
        format!("d{ordinal:x}.dl.goliath-bench.example"),
        format!("/get/{ordinal:x}.bin"),
    )
}

/// Indicator `index`: its kind and its value.
///
/// 240.0.0.0/4 holds the addresses of about 590 million indicators; beyond
/// that an address repeats an earlier one.
pub fn indicator(index: u64) -> (IndicatorKind, String) {
    let (kind, ordinal) = place(index);
    let value = match kind {
        IndicatorKind::Ip => {
            let offset = u32::try_from(ordinal & 0x0fff_ffff).unwrap_or(0);
            Ipv4Addr::from(0xf000_0000 | offset).to_string()
        }
        IndicatorKind::Domain => format!("c{ordinal:x}.c2.goliath-bench.example"),
        IndicatorKind::Url => {
            let (host, path) = url_parts(ordinal);
            format!("http://{host}{path}")
        }
        IndicatorKind::Sha256 => {
            // Four mixed words: no two ordinals give the same first one.
            let mut state = ordinal;
            (0..4).fold(String::with_capacity(64), |mut hash, _| {
                state = mix(state.wrapping_add(0x9e37_79b9_7f4a_7c15));
                let _ = write!(hash, "{state:016x}");
                hash
            })
        }
    };
    (kind, value)
}

/// A bijection of 64 bits, the finalizer of `SplitMix64`.
fn mix(mut state: u64) -> u64 {
    state = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    state ^ (state >> 31)
}

/// The definition of a feed named `name` whose publication
/// [`write_feed`] writes, as `goliath-intel` reads feed definitions.
pub fn feed_definition(name: &str) -> String {
    format!(
        "name: {name}\n\
         description: Generated indicators for measuring the detector\n\
         confidence: 80\n\
         format: csv\n\
         csv:\n  \
           columns: [kind, value]\n  \
           value: value\n  \
           kind_column: kind\n  \
           kinds: {{ ip: ip, domain: domain, url: url, sha256: sha256 }}\n"
    )
}

/// Writes the indicators of `indexes` as the publication of a feed: one
/// `kind,value` row each, with no header.
///
/// # Errors
///
/// Returns what `out` returns when it cannot be written.
pub fn write_feed(mut out: impl Write, indexes: Range<u64>) -> io::Result<()> {
    for index in indexes {
        let (kind, value) = indicator(index);
        writeln!(out, "{},{value}", kind.name())?;
    }
    Ok(())
}

/// What a planted event must hold for indicator `index` to match it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plant {
    /// A connection to this address.
    Address(String),
    /// A connection to this host name.
    Name(String),
    /// A process whose image has this SHA-256.
    Hash(String),
    /// An HTTP request for this path of this host.
    Request { host: String, path: String },
}

pub(crate) fn plant(index: u64) -> Plant {
    let (kind, ordinal) = place(index);
    let (_, value) = indicator(index);
    match kind {
        IndicatorKind::Ip => Plant::Address(value),
        IndicatorKind::Domain => Plant::Name(value),
        IndicatorKind::Sha256 => Plant::Hash(value),
        IndicatorKind::Url => {
            let (host, path) = url_parts(ordinal);
            Plant::Request { host, path }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    #[test]
    fn the_mix_is_that_of_the_exit_criterion_and_no_two_are_equal() {
        let mut counts = BTreeMap::new();
        let mut values = HashSet::new();
        for index in 0..200_000 {
            let (kind, value) = indicator(index);
            *counts.entry(kind).or_insert(0u32) += 1;
            assert!(values.insert(value), "indicator {index} repeats another");
        }
        assert_eq!(
            counts.into_iter().collect::<Vec<_>>(),
            [
                (IndicatorKind::Ip, 90_000),
                (IndicatorKind::Domain, 60_000),
                (IndicatorKind::Url, 30_000),
                (IndicatorKind::Sha256, 20_000),
            ]
        );
    }

    #[test]
    fn an_indicator_is_the_same_on_every_run() {
        assert_eq!(indicator(0), (IndicatorKind::Ip, "240.0.0.0".to_owned()));
        assert_eq!(indicator(28), (IndicatorKind::Ip, "240.0.0.17".to_owned()));
        assert_eq!(
            indicator(9),
            (
                IndicatorKind::Domain,
                "c0.c2.goliath-bench.example".to_owned()
            )
        );
        assert_eq!(
            indicator(36),
            (
                IndicatorKind::Url,
                "http://d4.dl.goliath-bench.example/get/4.bin".to_owned()
            )
        );
        let (kind, hash) = indicator(19);
        assert_eq!((kind, hash.len()), (IndicatorKind::Sha256, 64));
        assert_eq!(indicator(19), indicator(19));
        // A hundred million fit, the largest set the criterion names.
        assert_eq!(indicator(99_999_988).0, IndicatorKind::Ip);
    }

    #[test]
    fn a_feed_is_one_row_for_each_indicator() {
        let mut out = Vec::new();
        write_feed(&mut out, 18..21).unwrap();
        let text = String::from_utf8(out).unwrap();
        let rows: Vec<_> = text.lines().collect();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].starts_with("sha256,"));
        assert_eq!(rows[2], "ip,240.0.0.9");
    }
}
