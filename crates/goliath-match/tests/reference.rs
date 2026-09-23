//! Sigma rules, resolved through the shipped Windows mapping, evaluated
//! against OCSF events by the reference evaluator.

#![allow(clippy::expect_used)]

use goliath_match::{CompileError, ReferenceRule};
use goliath_rule::{MappingSet, sigma};
use serde_json::{Value, json};

const SIGMA_WINDOWS: &str = include_str!("../../goliath-rule/mappings/sigma-windows.yaml");

fn rule(detection: &str) -> ReferenceRule {
    try_rule(detection).expect("rule compiles")
}

fn try_rule(detection: &str) -> Result<ReferenceRule, CompileError> {
    let source = format!(
        "title: t\nlogsource: {{ category: process_creation, product: windows }}\ndetection:\n{detection}"
    );
    let parsed = goliath_sigma::parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(SIGMA_WINDOWS).expect("mapping loads");
    ReferenceRule::new(sigma::resolve(&parsed, &mappings).expect("rule resolves"))
}

/// A Windows process launch, with `process` merged over a default.
fn launch(process: &Value) -> Value {
    let mut event = json!({
        "class_uid": 1007,
        "activity_id": 1,
        "device": { "os": { "type_id": 100, "name": "Windows" } },
        "process": {
            "pid": 4242,
            "file": { "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" },
            "cmd_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            "user": { "name": r"CORP\adam" },
            "parent_process": {
                "file": { "path": r"C:\Windows\explorer.exe" }
            }
        }
    });
    merge(&mut event["process"], process);
    event
}

fn merge(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                merge(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (target, patch) => *target = patch.clone(),
    }
}

const ENCODED_POWERSHELL: &str = r"
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flag:
    CommandLine|windash|contains:
      - ' -e '
      - ' -enc '
      - ' -EncodedCommand '
  filter_sccm:
    ParentImage|endswith: '\ccmexec.exe'
  condition: all of selection_* and not 1 of filter_*
";

#[test]
fn a_real_detection_fires_on_the_event_it_describes() {
    assert!(rule(ENCODED_POWERSHELL).matches(&launch(&json!({}))));
}

#[test]
fn case_does_not_matter_unless_the_rule_says_so() {
    let shouting = launch(&json!({
        "file": { "path": r"C:\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE" },
        "cmd_line": "POWERSHELL.EXE -ENCODEDCOMMAND SQBFAFgA"
    }));
    assert!(rule(ENCODED_POWERSHELL).matches(&shouting));

    let cased =
        rule("  sel:\n    CommandLine|cased|contains: '-EncodedCommand'\n  condition: sel\n");
    assert!(cased.matches(&launch(&json!({}))));
    assert!(!cased.matches(&shouting));
}

#[test]
fn windash_catches_the_slash_spelling() {
    let slash = launch(&json!({ "cmd_line": "powershell.exe /enc SQBFAFgA" }));
    assert!(rule(ENCODED_POWERSHELL).matches(&slash));
}

#[test]
fn the_filter_suppresses_a_known_benign_parent() {
    let sccm = launch(&json!({
        "parent_process": { "file": { "path": r"C:\Windows\CCM\CcmExec.exe" } }
    }));
    assert!(!rule(ENCODED_POWERSHELL).matches(&sccm));
}

#[test]
fn the_filter_also_reads_the_actor_process() {
    // OCSF producers may put the parent under `actor.process` instead.
    let mut event = launch(&json!({}));
    event["process"]
        .as_object_mut()
        .expect("object")
        .remove("parent_process");
    event["actor"] = json!({ "process": { "file": { "path": r"C:\Windows\CCM\CcmExec.exe" } } });
    assert!(!rule(ENCODED_POWERSHELL).matches(&event));
}

#[test]
fn a_filter_on_a_missing_field_filters_nothing() {
    let mut event = launch(&json!({}));
    event["process"]
        .as_object_mut()
        .expect("object")
        .remove("parent_process");
    assert!(rule(ENCODED_POWERSHELL).matches(&event));
}

#[test]
fn an_event_of_another_class_never_matches() {
    let mut linux = launch(&json!({}));
    linux["device"]["os"]["type_id"] = json!(200);
    assert!(!rule(ENCODED_POWERSHELL).matches(&linux));

    let mut terminate = launch(&json!({}));
    terminate["activity_id"] = json!(2);
    assert!(!rule(ENCODED_POWERSHELL).matches(&terminate));
}

#[test]
fn base64offset_finds_an_encoded_command_at_any_alignment() {
    // `IEX` in UTF-16LE base64 is `SQBFAFgA`, present in the default event.
    let detect =
        rule("  sel:\n    CommandLine|wide|base64offset|contains: 'IEX'\n  condition: sel\n");
    assert!(detect.matches(&launch(&json!({}))));
    assert!(
        !detect.matches(&launch(
            &json!({ "cmd_line": "powershell.exe -enc sqbfafga" })
        )),
        "base64 is compared with case"
    );
}

#[test]
fn numbers_match_as_numbers_and_as_text() {
    let exact = rule("  sel:\n    ProcessId: 4242\n  condition: sel\n");
    assert!(exact.matches(&launch(&json!({}))));
    assert!(exact.matches(&launch(&json!({ "pid": "4242" }))));
    assert!(!exact.matches(&launch(&json!({ "pid": 4243 }))));

    let prefix = rule("  sel:\n    ProcessId|startswith: 42\n  condition: sel\n");
    assert!(prefix.matches(&launch(&json!({}))));

    let above = rule("  sel:\n    ProcessId|gt: 4000\n  condition: sel\n");
    assert!(above.matches(&launch(&json!({}))));
    assert!(!above.matches(&launch(&json!({ "pid": 4 }))));
}

#[test]
fn null_and_exists_ask_about_presence() {
    let null = rule("  sel:\n    CurrentDirectory: null\n  condition: sel\n");
    assert!(null.matches(&launch(&json!({}))));
    assert!(!null.matches(&launch(&json!({ "working_directory": r"C:\" }))));

    let exists = rule("  sel:\n    CurrentDirectory|exists: true\n  condition: sel\n");
    assert!(!exists.matches(&launch(&json!({}))));
    assert!(exists.matches(&launch(&json!({ "working_directory": r"C:\" }))));
}

#[test]
fn regular_expressions_run_with_their_flags() {
    let detect = rule(
        "  sel:\n    CommandLine|re|i: '-enc(odedcommand)?\\s+[a-z0-9+/=]{8,}'\n  condition: sel\n",
    );
    assert!(detect.matches(&launch(&json!({}))));
}

#[test]
fn regular_expressions_the_engine_cannot_bound_are_refused() {
    let lookahead = try_rule("  sel:\n    CommandLine|re: 'a(?=b)'\n  condition: sel\n");
    assert!(matches!(lookahead, Err(CompileError::Regex { .. })));
}

#[test]
fn fieldref_compares_two_fields() {
    let same_user = rule("  sel:\n    ParentUser|fieldref: User\n  condition: sel\n");
    let event = launch(&json!({
        "parent_process": { "user": { "name": r"corp\ADAM" } }
    }));
    assert!(same_user.matches(&event));
    assert!(!same_user.matches(&launch(&json!({}))));
}

#[test]
fn keywords_search_every_string() {
    let detect = rule("  keywords:\n    - 'explorer'\n  condition: keywords\n");
    assert!(detect.matches(&launch(&json!({}))));
    let absent = rule("  keywords:\n    - 'mshta'\n  condition: keywords\n");
    assert!(!absent.matches(&launch(&json!({}))));
}
