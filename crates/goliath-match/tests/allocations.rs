//! Once warmed up, the engine evaluates an event without allocating.
//!
//! Allocation was most of an event's cost before the engine reused its
//! working memory, and a change that brings one back slows the engine without
//! failing any other test. Timing in CI is too noisy to notice; a count of
//! allocations is exact.
//!
//! `allocation_counter` counts per thread, so tests running in parallel in
//! this binary do not disturb each other. It installs its own global
//! allocator, which is why it is used from this test binary only.

#![allow(clippy::expect_used)]

use goliath_match::Engine;
use goliath_rule::{MappingSet, ResolvedRule, sigma};
use serde_json::{Value, json};

const SIGMA_WINDOWS: &str = include_str!("../../goliath-rule/mappings/sigma-windows.yaml");

fn rule(category: &str, detection: &str) -> ResolvedRule {
    let source = format!(
        "title: t\nlogsource: {{ category: {category}, product: windows }}\ndetection:\n{detection}"
    );
    let parsed = goliath_sigma::parse_rule(&source).expect("rule parses");
    let mappings = MappingSet::from_yaml(SIGMA_WINDOWS).expect("mapping loads");
    sigma::resolve(&parsed, &mappings).expect("rule resolves")
}

/// One rule for every kind of test the engine evaluates differently.
fn rules() -> Vec<ResolvedRule> {
    let process = |detection| rule("process_creation", detection);
    let network = |detection| rule("network_connection", detection);
    vec![
        process("  s:\n    Image|endswith: '\\powershell.exe'\n  condition: s"),
        process("  s:\n    CommandLine|contains|all: [' -nop ', ' -w hidden ']\n  condition: s"),
        process("  s:\n    ParentImage|startswith: 'C:\\Windows\\'\n  condition: s"),
        process("  s:\n    User: 'CORP\\adam'\n  condition: s"),
        process("  s:\n    CommandLine: '*-enc?*SQB*'\n  condition: s"),
        process("  s:\n    CommandLine|cased|contains: 'IEX'\n  condition: s"),
        process("  s:\n    CommandLine|re: '(?i)-e(nc)?\\s+[a-z0-9+/=]{8,}'\n  condition: s"),
        process("  s:\n    ProcessId: 4242\n  condition: s"),
        process("  s:\n    ProcessId|gt: 1000\n  condition: s"),
        process("  s:\n    ProcessId|re: '^42'\n  condition: s"),
        process("  s:\n    ProcessId|contains: '24'\n  condition: s"),
        process("  s:\n    OriginalFileName|exists: true\n  condition: s"),
        process("  s:\n    CurrentDirectory: null\n  condition: s"),
        process("  keywords:\n    - 'mimikatz'\n  condition: keywords"),
        process(
            "  a:\n    Image|endswith: '.exe'\n  b:\n    CommandLine|contains: 'downloadstring'\n  condition: a and not b",
        ),
        network("  s:\n    DestinationIp|cidr: '10.0.0.0/8'\n  condition: s"),
        network("  s:\n    DestinationPort|lt: 1024\n  condition: s"),
    ]
}

fn launch(pid: u64, cmd_line: &str) -> Value {
    json!({
        "class_uid": 1007,
        "activity_id": 1,
        "device": { "os": { "type_id": 100 } },
        "process": {
            "pid": pid,
            "file": { "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe" },
            "cmd_line": cmd_line,
            "user": { "name": r"CORP\adam" },
            "parent_process": { "file": { "path": r"C:\Windows\explorer.exe" } },
        },
        "unmapped": { "OriginalFileName": "PowerShell.EXE", "Tags": ["ΣΊΣΥΦΟΣ", 7] },
    })
}

fn connection(ip: &str, port: u16) -> Value {
    json!({
        "class_uid": 4001,
        "device": { "os": { "type_id": 100 } },
        "actor": { "process": { "file": { "path": r"C:\Tools\agent.exe" } } },
        "dst_endpoint": { "ip": ip, "port": port },
    })
}

#[test]
fn a_warmed_up_engine_does_not_allocate_per_event() {
    let engine = Engine::new(rules()).expect("rules compile");
    let events = [
        launch(
            4242,
            "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA=",
        ),
        launch(
            17,
            "powershell.exe IEX (downloadstring 'http://x') mimikatz",
        ),
        launch(90_000, "cmd.exe /c whoami"),
        connection("10.1.2.3", 445),
        connection("203.0.113.9", 8443),
        json!({ "class_uid": 3002, "message": "not a class any rule reads" }),
    ];

    let mut scratch = engine.scratch();
    let mut matched = Vec::new();
    let mut expected = Vec::new();
    for event in &events {
        engine.matches_into(event, &mut scratch, &mut matched);
        expected.push(matched.clone());
    }
    // Every rule should match some event, or the test would not exercise
    // the path that rule takes.
    let mut covered = vec![false; engine.rules().len()];
    for index in expected.iter().flatten() {
        covered[*index] = true;
    }
    assert!(
        covered.iter().all(|&hit| hit),
        "rules never matched: {covered:?}"
    );

    for _ in 0..3 {
        for (event, expected) in events.iter().zip(&expected) {
            let allocated = allocation_counter::measure(|| {
                engine.matches_into(event, &mut scratch, &mut matched);
            });
            assert_eq!(allocated.count_total, 0, "allocations for {event}");
            assert_eq!(&matched, expected);
        }
    }
}
