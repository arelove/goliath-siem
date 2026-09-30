//! Sigma rules for Zeek logs, resolved through the shipped mapping, against
//! events the `zeek` definition produced from its own fixtures:
//! normalization, mapping, and evaluation together.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_match::{Engine, ReferenceRule};
use goliath_normalize::{Normalizer, Outcome};
use goliath_rule::{MappingSet, sigma};
use serde_json::Value;

const LOGS: &str = include_str!("../../goliath-normalize/sources/zeek/logs.input.json");

fn events() -> Vec<Value> {
    let normalizer = Normalizer::from_yaml(goliath_normalize::ZEEK).expect("definition loads");
    let mut events = Vec::new();
    normalizer.normalize(LOGS.as_bytes(), |outcome| match outcome {
        Outcome::Event(event) => events.push(event.event),
        other => panic!("a fixture is not an event: {other:?}"),
    });
    events
}

/// The logs of the events `detection`, for the `service` log source, fires
/// on, each with its connection, if it has one.
fn fired(service: &str, detection: &str) -> Vec<String> {
    let source = format!(
        "title: t\nlogsource: {{ product: zeek, service: {service} }}\ndetection:\n{detection}"
    );
    let parsed = goliath_sigma::parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(goliath_rule::SIGMA_ZEEK).expect("mapping loads");
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
            let log = event["metadata"]["log_name"].as_str().expect("a log");
            match event["metadata"]["correlation_uid"].as_str() {
                Some(uid) => format!("{log} {uid}"),
                None => log.to_owned(),
            }
        })
        .collect()
}

#[test]
fn a_query_is_found_by_its_name_and_type() {
    let rule = "  selection:\n    query|endswith: .example.com\n  condition: selection";
    assert_eq!(
        fired("dns", rule),
        ["dns CExample0003zeek", "dns CExample0004zeek"]
    );
    let rule = "  selection:\n    query|endswith: .example.com\n    qtype_name: aaaa\n    rcode_name: NXDOMAIN\n  condition: selection";
    assert_eq!(fired("dns", rule), ["dns CExample0004zeek"]);
}

#[test]
fn the_z_flag_rule_passes_over_queries_that_do_not_set_it() {
    let rule = "  z_flag_unset:\n    Z: 0\n  most_probable_valid_domain:\n    query|contains: .\n  exclude_netbios:\n    id.resp_p:\n      - 137\n      - 138\n      - 139\n  condition: not z_flag_unset and most_probable_valid_domain and not exclude_netbios";
    assert!(fired("dns", rule).is_empty());
}

#[test]
fn a_request_is_found_by_method_agent_and_response() {
    let rule = "  selection:\n    c-useragent|contains: WebDAV\n    method: PROPFIND\n  condition: selection";
    assert_eq!(fired("http", rule), ["http CExample0007zeek"]);
    let rule = "  selection:\n    status_code: 200\n    uri|endswith: .pdf?lang=en\n    resp_mime_types|contains: pdf\n  condition: selection";
    assert_eq!(fired("http", rule), ["http CExample0005zeek"]);
    let rule =
        "  selection:\n    user_agent|contains: WebDAV\n    method: PUT\n  condition: selection";
    assert!(fired("http", rule).is_empty());
}

#[test]
fn an_address_is_compared_with_networks() {
    let rule = "  selection:\n    id.orig_h|cidr:\n      - 10.0.0.0/8\n      - 192.168.0.0/16\n  condition: not selection";
    assert!(fired("rdp", rule).is_empty());
    let rule =
        "  selection:\n    id.orig_h|cidr: 10.0.0.0/8\n    id.resp_p: 3389\n  condition: selection";
    assert_eq!(fired("rdp", rule), ["rdp CExample0016zeek"]);
}

#[test]
fn a_file_is_found_by_its_share_and_name() {
    let rule = "  selection:\n    path|contains|all:\n      - '\\\\'\n      - Finance\n    name|endswith: .xlsx\n  condition: selection";
    assert_eq!(
        fired("smb_files", rule),
        ["smb_files CExample0010zeek", "smb_files CExample0011zeek"]
    );
}

#[test]
fn a_call_is_found_by_its_operation_not_its_interface() {
    let rule = "  selection:\n    operation|startswith: Lsar\n  condition: selection";
    assert_eq!(fired("dce_rpc", rule), ["dce_rpc CExample0012zeek"]);
    let rule =
        "  selection:\n    endpoint: lsarpc\n    operation: LsarLookupSids\n  condition: selection";
    assert_eq!(fired("dce_rpc", rule), ["dce_rpc CExample0012zeek"]);
    // Written the other way round, as SigmaHQ's two BZAR rules write their
    // pairs, a rule cannot fire on what Zeek logs.
    let rule =
        "  selection:\n    endpoint: LsarLookupSids\n    operation: lsarpc\n  condition: selection";
    assert!(fired("dce_rpc", rule).is_empty());
}

#[test]
fn a_ticket_request_is_found_by_type_cipher_and_outcome() {
    let rule = "  selection:\n    request_type: TGS\n    cipher: aes256-cts-hmac-sha1-96\n  computer_acct:\n    service|startswith: $\n  condition: selection and not computer_acct";
    assert_eq!(fired("kerberos", rule), ["kerberos CExample0014zeek"]);
    let rule =
        "  selection:\n    success: false\n    error_msg|contains: PREAUTH\n  condition: selection";
    assert_eq!(fired("kerberos", rule), ["kerberos CExample0015zeek"]);
}

#[test]
fn a_certificate_is_found_by_its_serial() {
    let rule = "  selection:\n    certificate.serial: 0A1B2C3D4E5F6071\n  condition: selection";
    assert_eq!(fired("x509", rule), ["x509"]);
}
