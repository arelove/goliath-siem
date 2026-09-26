//! Every shipped source definition against its fixtures.
//!
//! A definition `sources/<name>.yaml` has fixtures in `sources/<name>/`: each
//! `<case>.input.json` is fed to the definition, and the outcomes must equal
//! `<case>.expected.json` exactly. A change to a definition therefore shows
//! in review as a change to the events it produces.
//!
//! After an intended change, regenerate the expected files with
//! `GOLIATH_BLESS=1 cargo test -p goliath-normalize --test sources`, and read
//! the diff before committing it.

#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use goliath_normalize::{Normalizer, Outcome};
use serde_json::{Value, json};

fn render(outcome: &Outcome) -> Value {
    match outcome {
        Outcome::Event(normalized) => json!({
            "id": normalized.id.to_string(),
            "kind": normalized.kind,
            "event": normalized.event,
            "issues": normalized
                .issues
                .iter()
                .map(|issue| json!({
                    "target": issue.target,
                    "source": issue.source,
                    "reason": issue.reason,
                }))
                .collect::<Vec<_>>(),
        }),
        Outcome::DeadLetter(dead) => json!({
            "dead_letter": {
                "stage": dead.stage.as_str(),
                "error": dead.error,
                "raw": String::from_utf8_lossy(&dead.raw),
            }
        }),
        other => panic!("an outcome this test does not know: {other:?}"),
    }
}

fn definitions() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("sources");
    let mut found: Vec<PathBuf> = fs::read_dir(&root)
        .expect("sources directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect();
    found.sort();
    found
}

#[test]
fn every_definition_produces_its_fixtures() {
    let bless = std::env::var_os("GOLIATH_BLESS").is_some();
    let definitions = definitions();
    assert!(!definitions.is_empty(), "no source definitions found");

    for definition in definitions {
        let text = fs::read_to_string(&definition).expect("definition readable");
        let normalizer = Normalizer::from_yaml(&text)
            .unwrap_or_else(|error| panic!("{}: {error}", definition.display()));
        let fixtures = definition.with_extension("");
        let mut inputs: Vec<PathBuf> = fs::read_dir(&fixtures)
            .unwrap_or_else(|_| panic!("{} has no fixtures directory", definition.display()))
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.to_string_lossy().ends_with(".input.json"))
            .collect();
        inputs.sort();
        assert!(
            !inputs.is_empty(),
            "{} has no fixtures; a definition without fixtures does not merge",
            definition.display()
        );

        for input in inputs {
            let raw = fs::read(&input).expect("fixture readable");
            let mut outcomes = Vec::new();
            normalizer.normalize(&raw, |outcome| {
                // An event that converted cleanly must be valid OCSF.
                if let Outcome::Event(normalized) = &outcome
                    && normalized.issues.is_empty()
                {
                    let event: goliath_ocsf::Event =
                        serde_json::from_value(normalized.event.clone()).unwrap_or_else(|error| {
                            panic!("{}: not an OCSF event: {error}", input.display())
                        });
                    event
                        .validate()
                        .unwrap_or_else(|error| panic!("{}: {error}", input.display()));
                }
                outcomes.push(render(&outcome));
            });
            let actual = serde_json::to_string_pretty(&outcomes).expect("serializes") + "\n";

            let expected_path = PathBuf::from(
                input
                    .to_string_lossy()
                    .replace(".input.json", ".expected.json"),
            );
            if bless {
                fs::write(&expected_path, &actual).expect("expected file writable");
                continue;
            }
            let expected = fs::read_to_string(&expected_path).unwrap_or_else(|_| {
                panic!(
                    "{} is missing; run with GOLIATH_BLESS=1 and review it",
                    expected_path.display()
                )
            });
            assert!(
                actual == expected,
                "{} differs from {}:\n{actual}",
                input.display(),
                expected_path.display()
            );
        }
    }
}

#[test]
fn every_definition_is_shipped_under_its_name() {
    let shipped: Vec<PathBuf> = goliath_normalize::BUILTIN
        .iter()
        .map(|(name, text)| {
            let file = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("sources/{name}.yaml"));
            assert_eq!(&fs::read_to_string(&file).expect("readable"), text);
            let normalizer = Normalizer::from_yaml(text).expect("loads");
            assert_eq!(normalizer.name(), *name);
            file
        })
        .collect();
    assert_eq!(shipped, definitions());
}
