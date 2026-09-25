//! How a definition is checked, and how records go through it.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_normalize::{DefinitionError, Normalizer, Outcome, Stage};
use serde_json::json;

const MINIMAL: &str = r"
name: test
version: 3
framing: lines
decoding: json
common:
  metadata.product.name: { value: Test }
kinds:
  - name: login
    when: { type: login }
    class: { class_uid: 3002, activity_id: 1 }
    fields:
      user.name: who
      src_endpoint.port: { from: port, as: integer }
    unmapped: [extra]
";

fn outcomes(definition: &str, input: &str) -> Vec<Outcome> {
    let normalizer = Normalizer::from_yaml(definition).expect("definition loads");
    let mut all = Vec::new();
    normalizer.normalize(input.as_bytes(), |outcome| all.push(outcome));
    all
}

fn one(definition: &str, input: &str) -> Outcome {
    let mut all = outcomes(definition, input);
    assert_eq!(all.len(), 1, "{all:?}");
    all.remove(0)
}

fn error(definition: &str) -> DefinitionError {
    Normalizer::from_yaml(definition).expect_err("definition is rejected")
}

#[test]
fn a_record_becomes_an_event_with_its_class() {
    let Outcome::Event(normalized) = one(
        MINIMAL,
        r#"{"type": "login", "who": "adam", "port": "22", "extra": {"tty": "pts/1"}}"#,
    ) else {
        panic!("not an event");
    };
    assert_eq!(normalized.kind, "login");
    assert!(normalized.issues.is_empty());
    assert_eq!(
        normalized.event,
        json!({
            "class_uid": 3002,
            "category_uid": 3,
            "type_uid": 300_201,
            "activity_id": 1,
            "metadata": { "product": { "name": "Test" } },
            "user": { "name": "adam" },
            "src_endpoint": { "port": 22 },
            "unmapped": { "tty": "pts/1" },
        })
    );
}

#[test]
fn lines_framing_skips_blank_lines_and_carriage_returns() {
    let input = "\r\n{\"type\": \"login\"}\r\n   \n{\"type\": \"login\"}";
    let all = outcomes(MINIMAL, input);
    assert_eq!(all.len(), 2);
    assert!(
        all.iter()
            .all(|outcome| matches!(outcome, Outcome::Event(_)))
    );
}

#[test]
fn a_line_that_is_not_json_is_a_dead_letter_with_its_bytes() {
    let all = outcomes(MINIMAL, "{\"type\": \"login\"}\nnot json\n[1, 2]\n");
    let [
        Outcome::Event(_),
        Outcome::DeadLetter(broken),
        Outcome::DeadLetter(array),
    ] = all.as_slice()
    else {
        panic!("unexpected outcomes: {all:?}");
    };
    assert_eq!(broken.stage, Stage::Decoding);
    assert_eq!(broken.raw, b"not json");
    assert_eq!(array.stage, Stage::Decoding);
    assert_eq!(array.raw, b"[1, 2]");
}

#[test]
fn a_record_no_kind_accepts_is_a_dead_letter() {
    let Outcome::DeadLetter(dead) = one(MINIMAL, r#"{"type": "logout"}"#) else {
        panic!("not a dead letter");
    };
    assert_eq!(dead.stage, Stage::Mapping);
    assert_eq!(dead.raw, br#"{"type": "logout"}"#);
}

#[test]
fn conditions_compare_exactly() {
    // `"1"` is not `1`: a source that changes a type must change its
    // definition, not be matched by accident.
    let definition = MINIMAL.replace("when: { type: login }", "when: { code: 1 }");
    let all = outcomes(&definition, "{\"code\": 1}\n{\"code\": \"1\"}");
    assert!(matches!(all[0], Outcome::Event(_)));
    assert!(matches!(all[1], Outcome::DeadLetter(_)));
}

#[test]
fn a_value_that_does_not_convert_is_kept_and_reported() {
    let Outcome::Event(normalized) = one(MINIMAL, r#"{"type": "login", "port": "ssh"}"#) else {
        panic!("not an event");
    };
    assert_eq!(normalized.issues.len(), 1);
    assert_eq!(normalized.issues[0].target, "src_endpoint.port");
    assert_eq!(normalized.event["unmapped"]["port"], "ssh");
    assert!(normalized.event.get("src_endpoint").is_none());
}

#[test]
fn nulls_and_missing_fields_are_left_out() {
    let Outcome::Event(normalized) = one(
        MINIMAL,
        r#"{"type": "login", "who": null, "extra": {"gone": null}}"#,
    ) else {
        panic!("not an event");
    };
    assert!(normalized.event.get("user").is_none());
    assert!(normalized.event.get("unmapped").is_none());
    assert!(normalized.issues.is_empty());
}

#[test]
fn a_broken_json_stream_keeps_its_remainder() {
    let definition = MINIMAL.replace("framing: lines", "framing: json-values");
    let all = outcomes(&definition, "{\"type\": \"login\"}\n  {\"type\": \"log");
    let [Outcome::Event(_), Outcome::DeadLetter(dead)] = all.as_slice() else {
        panic!("unexpected outcomes: {all:?}");
    };
    assert_eq!(dead.stage, Stage::Framing);
    assert_eq!(dead.raw, b"{\"type\": \"log");
}

#[test]
fn overlapping_targets_are_rejected() {
    let definition = MINIMAL.replace(
        "      user.name: who\n",
        "      user.name: who\n      user: who\n",
    );
    assert!(matches!(
        error(&definition),
        DefinitionError::Overlap { .. }
    ));

    // A kind's field also overlaps a common one.
    let definition = MINIMAL.replace("user.name: who", "metadata.product: who");
    assert!(matches!(
        error(&definition),
        DefinitionError::Overlap { .. }
    ));
}

#[test]
fn class_and_unmapped_attributes_cannot_be_set_by_fields() {
    for target in ["class_uid", "type_uid", "unmapped.x"] {
        let definition = MINIMAL.replace("user.name: who", &format!("{target}: who"));
        assert!(
            matches!(error(&definition), DefinitionError::Reserved { .. }),
            "{target}"
        );
    }
}

#[test]
fn a_kind_without_conditions_is_rejected() {
    let definition = MINIMAL.replace("when: { type: login }", "when: {}");
    assert!(matches!(
        error(&definition),
        DefinitionError::Unconditional { .. }
    ));
}

#[test]
fn malformed_definitions_are_rejected() {
    assert!(matches!(
        error(&MINIMAL.replace("user.name: who", "user..name: who")),
        DefinitionError::Target { .. }
    ));
    assert!(matches!(
        error(&MINIMAL.replace("user.name: who", "user.name: a..b")),
        DefinitionError::SourcePath { .. }
    ));
    assert!(matches!(
        error(&MINIMAL.replace("version: 3", "version: 3\nsurprise: 1")),
        DefinitionError::Yaml(_)
    ));
    assert!(matches!(
        error(&MINIMAL.replace("as: integer", "as: float")),
        DefinitionError::Yaml(_)
    ));
}
