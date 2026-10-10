//! What the events of every shipped source show.
//!
//! `goliath-normalize` keeps, for each source, the events its definition
//! makes of the source's fixtures. Each is read here, and what all of a
//! source's events show must equal `tests/sources/<name>.json` exactly. A
//! change to how events are read therefore shows in review as a change to
//! the claims and links they give.
//!
//! After an intended change, regenerate the files with
//! `GOLIATH_BLESS=1 cargo test -p goliath-graph --test sources`, and read
//! the diff before committing it.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use goliath_graph::observe;
use serde_json::{Value, json};

fn sources() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../goliath-normalize/sources")
}

#[test]
fn every_source_shows_what_its_file_says() {
    let bless = std::env::var_os("GOLIATH_BLESS").is_some();
    let expected_in = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sources");
    let mut names: Vec<String> = fs::read_dir(sources())
        .expect("the sources of goliath-normalize")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(names.len() >= 10, "sources found: {names:?}");

    let mut differing = Vec::new();
    for name in &names {
        // Every case of the source: the kinds it has, and what it makes
        // of records that are malformed.
        let mut cases: Vec<PathBuf> = fs::read_dir(sources().join(name))
            .expect("a source's fixtures")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.to_string_lossy().ends_with(".expected.json"))
            .collect();
        cases.sort();
        let outcomes: Vec<Value> = cases
            .iter()
            .flat_map(|case| {
                let text = fs::read_to_string(case).expect("a source's expected events");
                serde_json::from_str::<Vec<Value>>(&text).expect("JSON")
            })
            .collect();
        let mut claims = BTreeSet::new();
        let mut links = BTreeSet::new();
        for outcome in &outcomes {
            let Some(event) = outcome.get("event") else {
                continue;
            };
            let seen = observe(event);
            for claim in seen.claims {
                claims.insert(format!("{} = {}", claim.one, claim.other));
            }
            for link in seen.links {
                links.insert(format!("{} {} {}", link.from, link.kind.as_str(), link.to));
            }
        }
        let shown = json!({ "claims": claims, "links": links });
        let mut written = serde_json::to_string_pretty(&shown).expect("JSON");
        written.push('\n');
        let file = expected_in.join(format!("{name}.json"));
        if bless {
            fs::create_dir_all(&expected_in).expect("the directory of expected files");
            fs::write(&file, written).expect("an expected file");
        } else if fs::read_to_string(&file)
            .ok()
            .map(|text| text.replace("\r\n", "\n"))
            != Some(written)
        {
            differing.push(name.clone());
        }
    }
    assert!(
        differing.is_empty(),
        "what these sources show changed: {differing:?}; see this file's head"
    );
}
