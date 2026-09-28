//! Sigma rules for the Windows Security log, resolved through the shipped
//! mapping, against events the `windows-security` definition produced from
//! its own fixtures: normalization, mapping, and evaluation together.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_match::ReferenceRule;
use goliath_normalize::{Normalizer, Outcome};
use goliath_rule::{MappingSet, sigma};
use serde_json::Value;

const KINDS: &str =
    include_str!("../../goliath-normalize/sources/windows-security/kinds.input.json");

fn events() -> Vec<Value> {
    let normalizer =
        Normalizer::from_yaml(goliath_normalize::WINDOWS_SECURITY).expect("definition loads");
    let mut events = Vec::new();
    normalizer.normalize(KINDS.as_bytes(), |outcome| match outcome {
        Outcome::Event(event) => events.push(event.event),
        other => panic!("a fixture is not an event: {other:?}"),
    });
    events
}

fn resolve(logsource: &str, detection: &str) -> Result<ReferenceRule, String> {
    let source = format!("title: t\nlogsource: {logsource}\ndetection:\n{detection}");
    let parsed = goliath_sigma::parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(goliath_rule::SIGMA_WINDOWS).expect("mapping loads");
    let resolved = sigma::resolve(&parsed, &mappings).map_err(|error| error.to_string())?;
    Ok(ReferenceRule::new(resolved).expect("rule compiles"))
}

/// The `EventRecordID`s, as `metadata.uid`, of the events `detection` fires on.
fn fired(detection: &str) -> Vec<String> {
    let rule =
        resolve("{ product: windows, service: security }", detection).expect("rule resolves");
    events()
        .iter()
        .filter(|event| rule.matches(event))
        .map(|event| event["metadata"]["uid"].as_str().expect("uid").to_owned())
        .collect()
}

#[test]
fn a_wrong_password_is_found_by_its_sub_status() {
    let rule =
        "  selection:\n    EventID: 4625\n    SubStatus: '0xC000006A'\n  condition: selection";
    assert_eq!(fired(rule), ["3003"]);
}

#[test]
fn a_failed_kerberos_pre_authentication_is_found_by_its_status() {
    let rule = "  selection:\n    EventID: 4768\n    Status: '0x18'\n  condition: selection";
    assert_eq!(fired(rule), ["3007"]);
}

#[test]
fn a_network_logon_with_an_address_passes_a_filter_on_dash() {
    let rule = "  selection:\n    EventID: 4624\n  filter:\n    IpAddress: '-'\n  condition: selection and not filter";
    assert_eq!(fired(rule), ["3001"], "the interactive logon has `-`");
    let rule = "  selection:\n    EventID: 4624\n    LogonType: 2\n    IpAddress: '-'\n  condition: selection";
    assert_eq!(fired(rule), ["3002"]);
}

#[test]
fn a_member_added_to_a_builtin_group_is_found_by_the_group_sid() {
    let rule = "  selection:\n    EventID: 4732\n    TargetSid|startswith: 'S-1-5-32-'\n    SubjectUserName: it-admin\n  condition: selection";
    assert_eq!(fired(rule), ["3018"]);
}

#[test]
fn the_log_being_cleared_and_a_task_created_are_found() {
    assert_eq!(
        fired("  selection:\n    EventID: 1102\n  condition: selection"),
        ["3023"]
    );
    let rule = "  selection:\n    EventID: 4698\n    TaskContent|contains: 'export.exe'\n  condition: selection";
    assert_eq!(fired(rule), ["3022"]);
}

#[test]
fn process_creation_rules_fire_on_4688_as_on_sysmon() {
    let rule = resolve(
        "{ category: process_creation, product: windows }",
        "  selection:\n    Image|endswith: '\\ipconfig.exe'\n    ParentImage|endswith: '\\cmd.exe'\n    User: it-admin\n  condition: selection",
    )
    .expect("rule resolves");
    let fired: Vec<_> = events()
        .into_iter()
        .filter(|event| rule.matches(event))
        .collect();
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0]["metadata"]["event_code"], "4688");
}

#[test]
fn a_field_of_an_event_the_definition_does_not_read_fails_to_load() {
    let error = resolve(
        "{ product: windows, service: security }",
        "  selection:\n    EventID: 5140\n    ShareName: '\\\\*\\C$'\n  condition: selection",
    )
    .map(|_| ())
    .expect_err("ShareName is not mapped");
    assert!(error.contains("ShareName"), "{error}");
}
