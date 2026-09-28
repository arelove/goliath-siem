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
        "  selection:\n    EventID: 4648\n    TargetServerName: localhost\n  condition: selection",
    )
    .map(|_| ())
    .expect_err("TargetServerName is not mapped");
    assert!(error.contains("TargetServerName"), "{error}");
}

#[test]
fn a_service_installed_is_found_by_its_image() {
    let rule = "  selection:\n    EventID: 4697\n    ServiceFileName|contains: '\\FinanceSync\\'\n    ServiceAccount: LocalSystem\n  condition: selection";
    assert_eq!(fired(rule), ["3033"]);
}

#[test]
fn object_access_is_found_by_name_and_access_mask() {
    let rule = "  selection:\n    EventID:\n      - 4656\n      - 4663\n    ObjectType: File\n    ObjectName|endswith: '\\ledger.xlsx'\n    AccessMask: '0x1'\n  condition: selection";
    assert_eq!(fired(rule), ["3034", "3035"]);
}

#[test]
fn a_file_on_a_share_is_found_by_share_and_relative_name() {
    let rule = "  selection:\n    EventID: 5145\n    ShareName: '\\\\*\\Finance'\n    RelativeTargetName|endswith: '.xlsx'\n  condition: selection";
    assert_eq!(fired(rule), ["3037"]);
    let rule = "  selection:\n    EventID: 5140\n    IpAddress: 10.20.4.17\n  condition: selection";
    assert_eq!(fired(rule), ["3036"]);
}

#[test]
fn directory_computer_task_and_right_changes_are_found() {
    let rule = "  selection:\n    EventID: 5136\n    ObjectClass: group\n    AttributeLDAPDisplayName: description\n  condition: selection";
    assert_eq!(fired(rule), ["3038"]);
    let rule =
        "  selection:\n    EventID: 4741\n    TargetUserName|endswith: '$'\n  condition: selection";
    assert_eq!(fired(rule), ["3026"]);
    let rule = "  selection:\n    EventID:\n      - 4699\n      - 4701\n    TaskName|contains: Finance\n  condition: selection";
    assert_eq!(fired(rule), ["3029", "3031"]);
    let rule = "  selection:\n    EventID: 4704\n    PrivilegeList|contains: SeBackupPrivilege\n  condition: selection";
    assert_eq!(fired(rule), ["3028"]);
    let rule = "  selection:\n    EventID: 4771\n    Status: '0x18'\n  condition: selection";
    assert_eq!(fired(rule), ["3025"]);
}

#[test]
fn a_wrong_password_checked_with_ntlm_is_found() {
    let rule = "  selection:\n    EventID: 4776\n    Status: '0xC000006A'\n    Workstation: LAPTOP-GUEST\n  condition: selection";
    assert_eq!(fired(rule), ["3040"]);
}

#[test]
fn directory_sam_and_registry_access_are_found() {
    let rule = "  selection:\n    EventID: 4662\n    AccessMask: '0x20'\n    Properties|contains: 'bf967950-0de6-11d0-a285-00aa003049e2'\n  condition: selection";
    assert_eq!(fired(rule), ["3049"]);
    let rule =
        "  selection:\n    EventID: 4661\n    ObjectType: SAM_DOMAIN\n  condition: selection";
    assert_eq!(fired(rule), ["3050"]);
    let rule = "  selection:\n    EventID: 4657\n    ObjectValueName: SyncInterval\n    NewValue: '30'\n  condition: selection";
    assert_eq!(fired(rule), ["3051"]);
}

#[test]
fn account_and_group_lifecycle_is_found() {
    let rule = "  selection:\n    EventID: 4742\n    AllowedToDelegateTo|contains: 'cifs/'\n  condition: selection";
    assert_eq!(fired(rule), ["3042"]);
    let rule = "  selection:\n    EventID: 4738\n    NewUacValue: '0x210'\n  condition: selection";
    assert_eq!(fired(rule), ["3041"]);
    let rule = "  selection:\n    EventID:\n      - 4727\n      - 4730\n    TargetUserName: Finance Auditors\n  condition: selection";
    assert_eq!(fired(rule), ["3043", "3046"]);
}
