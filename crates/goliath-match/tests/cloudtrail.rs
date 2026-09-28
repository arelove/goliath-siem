//! Sigma rules for AWS `CloudTrail`, resolved through the shipped mapping,
//! against events the `cloudtrail` definition produced from its own
//! fixtures: normalization, mapping, and evaluation together.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_match::ReferenceRule;
use goliath_normalize::{Normalizer, Outcome};
use goliath_rule::{MappingSet, sigma};
use serde_json::Value;

const KINDS: &str = include_str!("../../goliath-normalize/sources/cloudtrail/kinds.input.json");

fn events() -> Vec<Value> {
    let normalizer =
        Normalizer::from_yaml(goliath_normalize::CLOUDTRAIL).expect("definition loads");
    let mut events = Vec::new();
    normalizer.normalize(KINDS.as_bytes(), |outcome| match outcome {
        Outcome::Event(event) => events.push(event.event),
        other => panic!("a fixture is not an event: {other:?}"),
    });
    events
}

fn resolve(detection: &str) -> Result<ReferenceRule, String> {
    let source = format!(
        "title: t\nlogsource: {{ product: aws, service: cloudtrail }}\ndetection:\n{detection}"
    );
    let parsed = goliath_sigma::parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(goliath_rule::SIGMA_AWS).expect("mapping loads");
    let resolved = sigma::resolve(&parsed, &mappings).map_err(|error| error.to_string())?;
    Ok(ReferenceRule::new(resolved).expect("rule compiles"))
}

/// The operations, `eventName`, of the events `detection` fires on.
fn fired(detection: &str) -> Vec<String> {
    let rule = resolve(detection).expect("rule resolves");
    events()
        .iter()
        .filter(|event| rule.matches(event))
        .map(|event| {
            event["api"]["operation"]
                .as_str()
                .or_else(|| event["unmapped"]["eventName"].as_str())
                .expect("an operation")
                .to_owned()
        })
        .collect()
}

#[test]
fn a_console_sign_in_without_mfa_is_found() {
    let rule = "  selection:\n    eventSource: signin.amazonaws.com\n    eventName: ConsoleLogin\n    additionalEventData.MFAUsed: 'No'\n  condition: selection";
    assert_eq!(fired(rule), ["ConsoleLogin"]);
    let rule = "  selection:\n    eventName: ConsoleLogin\n    responseElements.ConsoleLogin: Success\n  condition: selection";
    assert_eq!(fired(rule), ["ConsoleLogin"]);
}

#[test]
fn a_user_created_by_an_assumed_role_is_found() {
    let rule = "  selection:\n    eventSource: iam.amazonaws.com\n    eventName: CreateUser\n    userIdentity.type: AssumedRole\n    userIdentity.sessionContext.sessionIssuer.userName: ops\n  condition: selection";
    assert_eq!(fired(rule), ["CreateUser"]);
}

#[test]
fn a_denied_call_is_found_by_its_error_and_request() {
    let rule = "  selection:\n    eventName: DeleteBucket\n    errorCode: AccessDenied\n    requestParameters.bucketName|startswith: finance-\n    userIdentity.arn|endswith: ':user/adam'\n  condition: selection";
    assert_eq!(fired(rule), ["DeleteBucket"]);
}

#[test]
fn calls_by_aws_services_are_found_by_their_source_name() {
    let rule = "  selection:\n    sourceIPAddress: ec2.amazonaws.com\n    eventSource: kms.amazonaws.com\n  condition: selection";
    assert_eq!(fired(rule), ["Decrypt", "CreateGrant"]);
    let rule = "  selection:\n    eventSource: s3.amazonaws.com\n  filter:\n    userAgent|contains: aws-cli\n  condition: selection and not filter";
    assert!(fired(rule).is_empty());
}

#[test]
fn a_field_cloudtrail_does_not_write_fails_to_load() {
    let error = resolve("  selection:\n    status: success\n  condition: selection")
        .map(|_| ())
        .expect_err("status is not mapped");
    assert!(error.contains("status"), "{error}");
}
