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

#[test]
fn classes_and_activities_must_exist_in_the_schema() {
    assert_eq!(
        error(&MINIMAL.replace("class_uid: 3002", "class_uid: 3999")).to_string(),
        "kind `login`: OCSF 1.5.0 has no class 3999"
    );
    assert_eq!(
        error(&MINIMAL.replace("activity_id: 1", "activity_id: 77")).to_string(),
        "kind `login`: class `authentication` has no activity 77"
    );
}

#[test]
fn targets_must_be_attributes_of_the_class() {
    assert_eq!(
        error(&MINIMAL.replace("user.name: who", "user.nmae: who")).to_string(),
        "kind `login`: `user.nmae`: object `user` has no attribute `nmae`"
    );
    // Common fields are checked against every kind's class.
    assert_eq!(
        error(&MINIMAL.replace("metadata.product.name", "metadata.produce.name")).to_string(),
        "kind `login`: `metadata.produce.name`: object `metadata` has no attribute `produce`"
    );
    assert_eq!(
        error(&MINIMAL.replace("user.name: who", "attacks.technique.uid: who")).to_string(),
        "kind `login`: `attacks.technique.uid` is inside an array, which a field cannot write into"
    );
}

#[test]
fn fields_must_write_what_their_attribute_holds() {
    let cases = [
        (
            "user.name: { value: 5 }",
            "`user.name` holds `username_t`, but the field writes an integer",
        ),
        (
            "user.name: { from: who, as: timestamp }",
            "`user.name` holds `username_t`, but the field writes a timestamp",
        ),
        (
            "user: { value: adam }",
            "`user` holds an object `user`, but the field writes text",
        ),
        (
            "metadata.labels: { value: test }",
            "`metadata.labels` holds an array of `string_t`, but the field writes text",
        ),
        ("time: { from: who, as: integer }", ""),
        (
            "user.name: { value: true }",
            "`user.name` holds `username_t`, but the field writes a boolean",
        ),
    ];
    for (field, message) in cases {
        let definition = MINIMAL.replace("user.name: who", field);
        if message.is_empty() {
            Normalizer::from_yaml(&definition).expect("an integer is a valid timestamp");
        } else {
            assert_eq!(
                error(&definition).to_string(),
                format!("kind `login`: {message}")
            );
        }
    }
    // A copy carries whatever the source holds, so it fits anything.
    Normalizer::from_yaml(&MINIMAL.replace("user.name: who", "user: who")).expect("a copy fits");
}

#[test]
fn enumerated_constants_must_be_defined_values() {
    let definition = MINIMAL.replace("user.name: who", "severity_id: { value: 42 }");
    assert_eq!(
        error(&definition).to_string(),
        "kind `login`: 42 is not a defined value of `severity_id`"
    );
    let definition = MINIMAL.replace("user.name: who", "severity_id: { value: 99 }");
    Normalizer::from_yaml(&definition).expect("99 is Other");
}

#[test]
fn members_with_dots_in_their_names_are_found() {
    let definition = MINIMAL.replace("user.name: who", "user.name: extra.user.name");
    let Outcome::Event(normalized) = one(
        &definition,
        r#"{"type": "login", "extra": {"user.name": "adam", "proc.pid": 7}}"#,
    ) else {
        panic!("not an event");
    };
    assert_eq!(normalized.event["user"]["name"], "adam");
    // The member it read is not kept twice; the rest are kept by name.
    assert_eq!(normalized.event["unmapped"], json!({ "proc.pid": 7 }));

    // A member named by the segment alone comes first.
    let Outcome::Event(normalized) = one(
        &definition,
        r#"{"type": "login", "extra": {"user": {"name": "eve"}, "user.name": "adam"}}"#,
    ) else {
        panic!("not an event");
    };
    assert_eq!(normalized.event["user"]["name"], "eve");
}

#[test]
fn a_translation_turns_source_words_into_ocsf_values() {
    let definition = MINIMAL.replace(
        "user.name: who",
        "severity_id: { from: level, map: { warn: 3, crit: 5, \"7\": 6 } }",
    );
    let severity = |input: &str| match one(&definition, input) {
        Outcome::Event(normalized) => normalized,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        severity(r#"{"type": "login", "level": "warn"}"#).event["severity_id"],
        3
    );
    // A number is looked up by its text.
    assert_eq!(
        severity(r#"{"type": "login", "level": 7}"#).event["severity_id"],
        6
    );

    // A word the table does not list is kept and reported, not dropped.
    let unlisted = severity(r#"{"type": "login", "level": "loud"}"#);
    assert!(unlisted.event.get("severity_id").is_none());
    assert_eq!(unlisted.event["unmapped"]["level"], "loud");
    assert_eq!(unlisted.issues[0].target, "severity_id");

    // Unless the table says what it becomes.
    let definition = definition.replace("} }", "}, otherwise: 99 }");
    let Outcome::Event(other) = one(&definition, r#"{"type": "login", "level": "loud"}"#) else {
        panic!("not an event");
    };
    assert_eq!(other.event["severity_id"], 99);
    assert!(other.issues.is_empty());
}

#[test]
fn translations_are_checked_when_they_load() {
    let with = |table: &str| MINIMAL.replace("user.name: who", table);
    assert_eq!(
        error(&with(
            "severity_id: { from: level, map: { warn: 3, crit: 42 } }"
        ))
        .to_string(),
        "kind `login`: 42 is not a defined value of `severity_id`"
    );
    assert_eq!(
        error(&with(
            "severity_id: { from: level, map: { warn: 3 }, otherwise: 42 }"
        ))
        .to_string(),
        "kind `login`: 42 is not a defined value of `severity_id`"
    );
    assert_eq!(
        error(&with(
            "severity_id: { from: level, map: { warn: 3, crit: high } }"
        ))
        .to_string(),
        "kind `login`: the translation for `severity_id` mixes values of different types"
    );
    assert_eq!(
        error(&with("severity_id: { from: level, map: {} }")).to_string(),
        "kind `login`: the translation for `severity_id` is empty"
    );
    assert!(matches!(
        error(&with("severity_id: { from: level, map: { warn: high } }")),
        DefinitionError::Type { .. }
    ));
}

#[test]
fn a_record_has_the_same_identity_every_time_it_arrives() {
    let record = r#"{"type": "login", "who": "adam"}"#;
    let id = |input: &str| match one(MINIMAL, input) {
        Outcome::Event(normalized) => normalized.id,
        other => panic!("{other:?}"),
    };
    assert_eq!(id(record), id(record));
    assert_ne!(id(record), id(r#"{"type": "login", "who": "eve"}"#));
    // Only the bytes count: the same event written differently is another
    // record.
    assert_ne!(id(record), id(r#"{"who": "adam", "type": "login"}"#));
}

#[test]
fn identities_separate_sources_and_print_as_hex() {
    use goliath_normalize::EventId;

    assert_ne!(EventId::of("a", b"bc"), EventId::of("ab", b"c"));
    assert_ne!(EventId::of("sysmon", b"x"), EventId::of("auditd", b"x"));
    let text = EventId::of("sysmon", b"x").to_string();
    assert_eq!(text.len(), 32);
    assert!(
        text.bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

#[test]
fn outcomes_travel_between_roles_unchanged() {
    use goliath_normalize::{Envelope, WireError};

    let input = "{\"type\": \"login\", \"who\": \"adam\", \"port\": \"x\", \"extra\": {\"tty\": 1}}\nnot json\n";
    for outcome in outcomes(MINIMAL, input) {
        let envelope = Envelope::new("test", 3, outcome);
        let bytes = envelope.encode();
        assert_eq!(bytes[0], 1, "the format byte comes first");
        assert_eq!(Envelope::decode(&bytes).expect("decodes"), envelope);
    }
    assert!(matches!(Envelope::decode(b""), Err(WireError { .. })));
    assert!(
        Envelope::decode(b"\x09{}")
            .expect_err("unknown format")
            .to_string()
            .contains("unknown format 9")
    );
    assert!(Envelope::decode(b"\x01{").is_err());
}

#[test]
fn identities_read_back_from_their_text() {
    use goliath_normalize::EventId;

    let id = EventId::of("sysmon", b"x");
    assert_eq!(id.to_string().parse::<EventId>().expect("parses"), id);
    assert_eq!(
        id.to_string()
            .to_uppercase()
            .parse::<EventId>()
            .expect("parses"),
        id
    );
    for bad in ["", "abc", &"g".repeat(32), &"a".repeat(33)] {
        assert!(bad.parse::<EventId>().is_err(), "{bad}");
    }
}
