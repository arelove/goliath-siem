//! A replayed recording normalizes as the original does, at its new time.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use goliath_bench::replay::{Clock, Recording};
use goliath_normalize::{AUDITD, ENTRA, FALCO, Normalizer, Outcome, SYSMON};

const SOURCES: [(&str, &str, &str); 4] = [
    (
        "sysmon",
        SYSMON,
        include_str!("../../goliath-normalize/sources/sysmon/kinds.input.json"),
    ),
    (
        "entra",
        ENTRA,
        include_str!("../../goliath-normalize/sources/entra/kinds.input.json"),
    ),
    (
        "falco",
        FALCO,
        include_str!("../../goliath-normalize/sources/falco/kinds.input.json"),
    ),
    (
        "auditd",
        AUDITD,
        include_str!("../../goliath-normalize/sources/auditd/kinds.input.json"),
    ),
];

/// The events a normalizer makes of `bytes`: class and time of each.
fn events(normalizer: &Normalizer, bytes: &[u8]) -> Vec<(u64, i64)> {
    let mut found = Vec::new();
    normalizer.normalize(bytes, |outcome| match outcome {
        Outcome::Event(made) => found.push((
            made.event["class_uid"].as_u64().unwrap(),
            made.event["time"].as_i64().unwrap(),
        )),
        other => panic!("not an event: {other:?}"),
    });
    found
}

#[test]
fn every_source_replays_into_the_same_events_at_the_time_they_are_released() {
    let start = 1_800_000_000_000;
    for (source, definition, sample) in SOURCES {
        let normalizer = Normalizer::from_yaml(definition).unwrap();
        let mut original = events(&normalizer, sample.as_bytes());
        original.sort_by_key(|(_, time)| *time);
        let recording = Recording::read(Clock::of(source).unwrap(), sample.as_bytes()).unwrap();

        let mut classes = Vec::new();
        for (due, bytes) in recording.schedule(start, 1.0) {
            let made = events(&normalizer, &bytes);
            assert!(!made.is_empty(), "{source}: a record made no event");
            for (class, time) in made {
                assert_eq!(time, due, "{source}: the event claims when it was released");
                classes.push(class);
            }
        }
        let expected: Vec<u64> = original.iter().map(|(class, _)| *class).collect();
        assert_eq!(classes, expected, "{source}");
    }
}

/// Labels name each event by the identity its record gets alone; the
/// platform normalizes a whole file of records at once. Both must agree, or
/// ground truth would not find the events it labels.
#[test]
fn a_record_has_the_same_identity_alone_as_in_a_file_of_records() {
    let flat = include_str!("../../goliath-normalize/sources/sysmon-flat/kinds.input.json");
    let sources =
        SOURCES
            .iter()
            .copied()
            .chain([("sysmon-flat", goliath_normalize::SYSMON_FLAT, flat)]);
    for (source, definition, sample) in sources {
        let normalizer = Normalizer::from_yaml(definition).unwrap();
        let recording = Recording::read(Clock::of(source).unwrap(), sample.as_bytes()).unwrap();
        let ids = |bytes: &[u8]| {
            let mut ids = Vec::new();
            normalizer.normalize(bytes, |outcome| {
                if let Outcome::Event(event) = outcome {
                    ids.push(event.id.to_string());
                }
            });
            ids
        };
        let mut file = Vec::new();
        let mut alone = Vec::new();
        for (_, bytes) in recording.schedule(1_800_000_000_000, 1.0) {
            alone.extend(ids(&bytes));
            file.extend_from_slice(&bytes);
        }
        assert!(!alone.is_empty(), "{source}");
        assert_eq!(ids(&file), alone, "{source}");
    }
}
