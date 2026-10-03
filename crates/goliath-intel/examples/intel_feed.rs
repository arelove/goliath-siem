//! Reads a feed's publication from a file with a feed definition, and says
//! what it became: a check of a definition against what the feed publishes
//! today.
//!
//! ```text
//! curl -sO https://feodotracker.abuse.ch/downloads/ipblocklist.csv
//! cargo run -p goliath-intel --example intel_feed -- feodo-tracker ipblocklist.csv
//! ```
//!
//! The definition is the name of a shipped one or the path of a YAML file.

#![allow(clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use goliath_intel::{FEEDS, Feed};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(definition), Some(file)) = (args.next(), args.next()) else {
        eprintln!("usage: intel_feed <definition> <file>");
        std::process::exit(2);
    };
    let yaml = FEEDS
        .iter()
        .find(|(name, _)| *name == definition)
        .map_or_else(
            || std::fs::read_to_string(&definition).expect("the definition reads"),
            |(_, yaml)| (*yaml).to_owned(),
        );
    let feed = Feed::from_yaml(&yaml).expect("the definition loads");
    let bytes = std::fs::read(&file).expect("the file reads");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });

    match feed.parse(&bytes, now) {
        Ok(parsed) => {
            let mut kinds: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
            for (key, assertion) in &parsed.indicators {
                let counted = kinds.entry(key.kind().as_str()).or_default();
                counted.0 += 1;
                counted.1 += usize::from(assertion.valid_at(now));
            }
            println!(
                "{}: {} indicators, {} ignored, {} rejected",
                feed.name,
                parsed.indicators.len(),
                parsed.ignored,
                parsed.rejected
            );
            for (kind, (count, valid)) in kinds {
                println!("  {kind}: {count}, {valid} holding now");
            }
            for reason in parsed.reasons {
                println!("  rejected: {reason}");
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
