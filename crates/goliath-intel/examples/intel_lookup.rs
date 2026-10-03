//! Loads a feed of generated indicators into the store on disk and times
//! lookups of what it holds and of what it does not.
//!
//! ```text
//! cargo run --release -p goliath-intel --features rocksdb --example intel_lookup -- \
//!     <directory> [indicators]
//! ```
//!
//! The directory is made if it is not there, and left for a second run,
//! which then also times opening a store that is full. One thread; the
//! figures are of the lookup alone, not of a detector.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use std::time::Instant;

use goliath_intel::{Allowlists, Assertion, Key, Kind, Matcher, RocksStore, Store};

/// The kinds mixed as the exit criterion of M4 mixes them: 45% addresses,
/// 30% domains, 15% URLs, 10% SHA-256.
fn indicator(index: u64, absent: bool) -> (Kind, String) {
    // Absent values differ from every present one in their first label or
    // octet, and have the same shape.
    let salt = u32::from(absent);
    match index % 20 {
        0..9 => {
            let bytes = (index as u32).to_be_bytes();
            (
                Kind::Ip,
                format!(
                    "{}.{}.{}.{}",
                    11 + salt + u32::from(bytes[0]) * 2,
                    bytes[1],
                    bytes[2],
                    bytes[3]
                ),
            )
        }
        9..15 => (Kind::Domain, format!("h{index}-{salt}.bad.example.com")),
        15..18 => (
            Kind::Url,
            format!("https://h{index}-{salt}.bad.example.com/payload/{index}.bin"),
        ),
        _ => (Kind::Sha256, format!("{index:063x}{salt}")),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(directory) = args.next() else {
        eprintln!("usage: intel_lookup <directory> [indicators]");
        std::process::exit(2);
    };
    let count: u64 = args
        .next()
        .map_or(1_000_000, |count| count.parse().expect("a number"));

    let started = Instant::now();
    let store = RocksStore::open(&directory).expect("the store opens");
    println!(
        "opened with {} feeds in {:.2} s",
        store.feeds().len(),
        started.elapsed().as_secs_f64()
    );

    let started = Instant::now();
    store
        .replace_feed(
            "generated",
            "1",
            (0..count).map(|index| {
                let (kind, value) = indicator(index, false);
                (Key::new(kind, &value).expect("a key"), Assertion::new(50))
            }),
        )
        .expect("the feed loads");
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "loaded {count} indicators in {seconds:.1} s, {:.0} a second; filter {:.1} MiB",
        count as f64 / seconds,
        store.filter_bytes() as f64 / f64::from(1 << 20)
    );

    let matcher = Matcher::new(store, Allowlists::default());
    let lookups = count.min(2_000_000);
    let step = (count / lookups).max(1);
    for (name, absent) in [
        ("absent", true),
        ("present", false),
        ("present again", false),
    ] {
        let started = Instant::now();
        let mut hits = 0u64;
        for index in (0..count).step_by(step as usize) {
            let (kind, value) = indicator(index, absent);
            hits += matcher
                .lookup(kind, &value, 1_780_000_000)
                .expect("looked up")
                .len() as u64;
        }
        let nanoseconds = started.elapsed().as_nanos() as f64 / lookups as f64;
        println!("{name}: {lookups} lookups, {hits} hits, {nanoseconds:.0} ns each");
    }
}
