//! Sigma rules for the Okta System Log, resolved through the shipped
//! mapping, against events the `okta` definition produced from its own
//! fixtures: normalization, mapping, and evaluation together.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_match::{Engine, ReferenceRule};
use goliath_normalize::{Normalizer, Outcome};
use goliath_rule::{MappingSet, sigma};
use serde_json::Value;

const KINDS: &str = include_str!("../../goliath-normalize/sources/okta/kinds.input.json");
const STREAM: &str = include_str!("../../goliath-normalize/sources/okta/stream.input.json");

fn events() -> Vec<Value> {
    let normalizer = Normalizer::from_yaml(goliath_normalize::OKTA).expect("definition loads");
    let mut events = Vec::new();
    for input in [KINDS, STREAM] {
        normalizer.normalize(input.as_bytes(), |outcome| match outcome {
            Outcome::Event(event) => events.push(event.event),
            other => panic!("a fixture is not an event: {other:?}"),
        });
    }
    events
}

/// The event types of the events `detection` fires on.
fn fired(detection: &str) -> Vec<String> {
    let source =
        format!("title: t\nlogsource: {{ product: okta, service: okta }}\ndetection:\n{detection}");
    let parsed = goliath_sigma::parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(goliath_rule::SIGMA_OKTA).expect("mapping loads");
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
                .expect("an event type")
                .to_owned()
        })
        .collect()
}

#[test]
fn a_failed_sign_in_is_found_by_its_outcome() {
    let rule = "  selection:\n    eventType: user.session.start\n    outcome.result: FAILURE\n  condition: selection";
    assert_eq!(fired(rule), ["user.session.start"]);
}

#[test]
fn a_factor_reset_or_deactivated_is_found_by_event_type() {
    let rule = "  selection:\n    eventType:\n      - user.mfa.factor.deactivate\n      - user.mfa.factor.reset_all\n  condition: selection";
    assert_eq!(
        fired(rule),
        ["user.mfa.factor.deactivate", "user.mfa.factor.reset_all"]
    );
}

#[test]
fn any_target_is_compared_whatever_its_place() {
    let rule = "  selection:\n    eventType: group.user_membership.add\n    target.displayName: Finance\n  condition: selection";
    assert_eq!(fired(rule), ["group.user_membership.add"]);
}

#[test]
fn an_event_type_without_a_kind_of_its_own_still_fires() {
    let rule = "  selection:\n    eventType: system.api_token.create\n    actor.alternateId|endswith: '@contoso.com'\n  condition: selection";
    assert_eq!(fired(rule), ["system.api_token.create"]);
    let rule = "  selection:\n    eventType: policy.lifecycle.update\n    debugContext.debugData.requestUri|startswith: /api/v1/policies/\n  condition: selection";
    assert_eq!(fired(rule), ["policy.lifecycle.update"]);
}

#[test]
fn a_privilege_granted_through_a_proxy_is_not_found_when_none_was() {
    let rule = "  selection:\n    eventType: user.account.privilege.grant\n    securityContext.isProxy: 'true'\n  condition: selection";
    assert!(fired(rule).is_empty());
    let rule = "  selection:\n    eventType: user.account.privilege.grant\n    securityContext.isProxy: 'false'\n  condition: selection";
    assert_eq!(fired(rule), ["user.account.privilege.grant"]);
}
