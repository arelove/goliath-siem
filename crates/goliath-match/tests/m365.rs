//! Sigma rules for the Microsoft 365 unified audit log, resolved through the
//! shipped mapping, against events the `m365` definition produced from its
//! own fixtures: normalization, mapping, and evaluation together.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_match::{Engine, ReferenceRule};
use goliath_normalize::{Normalizer, Outcome};
use goliath_rule::{MappingSet, sigma};
use serde_json::Value;

const KINDS: &str = include_str!("../../goliath-normalize/sources/m365/kinds.input.json");
const LINES: &str = include_str!("../../goliath-normalize/sources/m365/lines.input.json");

fn events() -> Vec<Value> {
    let normalizer = Normalizer::from_yaml(goliath_normalize::M365).expect("definition loads");
    let mut events = Vec::new();
    for input in [KINDS, LINES] {
        normalizer.normalize(input.as_bytes(), |outcome| match outcome {
            Outcome::Event(event) => events.push(event.event),
            other => panic!("a fixture is not an event: {other:?}"),
        });
    }
    events
}

/// The operations of the events `detection`, for the `service` log source,
/// fires on.
fn fired(service: &str, detection: &str) -> Vec<String> {
    let source = format!(
        "title: t\nlogsource: {{ product: m365, service: {service} }}\ndetection:\n{detection}"
    );
    let parsed = goliath_sigma::parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(goliath_rule::SIGMA_M365).expect("mapping loads");
    let resolved = sigma::resolve(&parsed, &mappings).expect("rule resolves");
    let rule = ReferenceRule::new(resolved.clone()).expect("rule compiles");
    // The engine must agree with the reference on every event.
    let engine = Engine::new(vec![resolved]).expect("engine compiles");
    let events = events();
    for event in &events {
        assert_eq!(
            engine.matches(event).is_empty(),
            !rule.matches(event),
            "the engine and the reference disagree on {event}"
        );
    }
    events
        .iter()
        .filter(|event| rule.matches(event))
        .map(|event| {
            event["metadata"]["event_code"]
                .as_str()
                .expect("an operation")
                .to_owned()
        })
        .collect()
}

#[test]
fn a_sign_in_is_found_by_its_request_type_among_the_extended_properties() {
    let rule = "  selection:\n    Operation: UserLoggedIn\n    ApplicationId: 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223\n    ResultStatus: Success\n    RequestType: 'Cmsi:Cmsi'\n  filter_main:\n    ObjectId: 0000000a-0000-0000-c000-000000000000\n  condition: selection and not filter_main";
    assert_eq!(fired("audit", rule), ["UserLoggedIn"]);
    let rule = "  selection:\n    Operation: UserLoggedIn\n    RequestType: 'Cmsi:Cmsi'\n  filter_main:\n    ObjectId: 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9\n  condition: selection and not filter_main";
    assert!(fired("audit", rule).is_empty());
}

#[test]
fn a_failed_sign_in_is_found_by_its_result() {
    let rule = "  selection:\n    Operation: UserLoginFailed\n    ResultStatus: Failed\n    LogonError: InvalidUserNameOrPassword\n  condition: selection";
    assert_eq!(fired("audit", rule), ["UserLoginFailed"]);
}

#[test]
fn directory_operations_are_found_by_their_names() {
    let rule = "  selection:\n    Operation|contains: 'Disable Strong Authentication.'\n  condition: selection";
    assert_eq!(fired("audit", rule), ["Disable Strong Authentication."]);
    let rule = "  selection_domain:\n    Operation|contains: domain\n  selection_operation:\n    Operation|contains:\n      - add\n      - new\n  condition: all of selection_*";
    assert_eq!(
        fired("audit", rule),
        ["Add domain to company.", "Add-FederatedDomain"]
    );
}

#[test]
fn cmdlet_parameters_and_mailbox_properties_are_compared_by_name_and_value() {
    let rule = "  selection_updateinbox:\n    Operation|contains: UpdateInboxRules\n    OperationProperties|contains:\n      - Forward\n      - Recipients\n  selection_setmailbox:\n    Operation|contains: Set-Mailbox\n    Parameters|contains:\n      - ForwardingSmtpAddress\n      - ForwardingAddress\n  condition: 1 of selection_*";
    assert_eq!(fired("audit", rule), ["Set-Mailbox", "UpdateInboxRules"]);
    let rule = "  selection:\n    Operation:\n      - New-InboxRule\n      - Set-InboxRule\n    Parameters|contains:\n      - DeleteMessage\n      - MoveToFolder\n  condition: selection";
    assert_eq!(fired("audit", rule), ["New-InboxRule"]);
}

#[test]
fn a_message_is_found_by_its_direction_and_delivery() {
    let rule = "  selection:\n    Workload: ThreatIntelligence\n    Operation: TIMailData\n    Directionality: Inbound\n  filter_main_blocked:\n    DeliveryAction: Blocked\n  condition: selection and not 1 of filter_main_*";
    assert_eq!(fired("audit", rule), ["TIMailData"]);
}

#[test]
fn an_exchange_rule_reads_the_workload_the_operation_and_the_result() {
    let rule = "  selection:\n    eventSource: Exchange\n    eventName: Add-FederatedDomain\n    status: success\n  condition: selection";
    assert_eq!(fired("exchange", rule), ["Add-FederatedDomain"]);
}

#[test]
fn an_alert_rule_reads_the_alert_name() {
    let rule = "  selection:\n    eventSource: SecurityComplianceCenter\n    eventName: 'Impossible travel activity'\n    status: success\n  condition: selection";
    assert_eq!(fired("threat_management", rule), ["AlertTriggered"]);
    assert_eq!(fired("threat_detection", rule), ["AlertTriggered"]);
    // Only alerts: no other record has a name to compare.
    let rule = "  selection:\n    eventSource: Exchange\n    eventName: Set-Mailbox\n  condition: selection";
    assert!(fired("threat_management", rule).is_empty());
}
