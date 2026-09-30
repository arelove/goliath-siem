//! ATT&CK read from a subset of its published 19.2 bundle, and coverage of
//! rules against collected data assessed on it.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_attack::{
    AttackError, Broken, BrokenReference, Framework, RuleRef, State, Verdict, assess, layer,
    technique_of_tag,
};

const SUBSET: &str = include_str!("data/enterprise-attack-subset.json");

fn framework() -> Framework {
    Framework::from_stix(SUBSET).expect("the subset loads")
}

fn names(framework: &Framework, id: &str) -> Vec<String> {
    framework
        .technique(id)
        .expect("a technique")
        .data_components
        .iter()
        .map(|id| {
            framework
                .data_component(id)
                .expect("a component")
                .name
                .clone()
        })
        .collect()
}

#[test]
fn the_bundle_gives_its_version_tactics_and_techniques() {
    let framework = framework();
    assert_eq!(framework.name(), "Enterprise ATT&CK");
    assert_eq!(framework.domain(), "enterprise-attack");
    assert_eq!(framework.version(), "19.2");
    let tactics: Vec<&str> = framework
        .tactics()
        .iter()
        .map(|tactic| tactic.shortname.as_str())
        .collect();
    assert_eq!(
        tactics,
        [
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "stealth",
            "credential-access",
            "command-and-control"
        ]
    );
    assert_eq!(framework.tactics()[1].id, "TA0002");

    let powershell = framework.technique("t1059.001").expect("PowerShell");
    assert_eq!(powershell.name, "PowerShell");
    assert_eq!(powershell.parent.as_deref(), Some("T1059"));
    assert_eq!(powershell.tactics, ["execution"]);
    assert_eq!(powershell.platforms, ["Windows"]);
    assert_eq!(powershell.state, State::Active);
    // Tactics in the matrix's order, not the bundle's.
    let valid = framework.technique("T1078").expect("Valid Accounts");
    assert_eq!(
        valid.tactics,
        [
            "initial-access",
            "persistence",
            "privilege-escalation",
            "stealth"
        ]
    );
    assert_eq!(valid.parent, None);
}

#[test]
fn data_components_come_through_detection_strategies_and_their_analytics() {
    let framework = framework();
    let mut powershell = names(&framework, "T1059.001");
    powershell.sort();
    assert_eq!(
        powershell,
        [
            "Command Execution",
            "Module Load",
            "Process Creation",
            "Process Metadata"
        ]
    );
    let mut spraying = names(&framework, "T1110.003");
    spraying.sort();
    assert_eq!(spraying, ["User Account Authentication"]);
    let mut dns = names(&framework, "T1071.004");
    dns.sort();
    assert_eq!(
        dns,
        [
            "Network Connection Creation",
            "Network Traffic Content",
            "Network Traffic Flow",
            "Process Creation"
        ]
    );
    assert_eq!(
        framework
            .data_component_named("process creation")
            .map(|component| component.id.as_str()),
        framework
            .data_component_named("Process Creation")
            .map(|component| component.id.as_str())
    );
}

#[test]
fn revoked_and_deprecated_techniques_are_kept_and_marked() {
    let framework = framework();
    assert_eq!(
        framework
            .technique("T1086")
            .expect("the old PowerShell")
            .state,
        State::Revoked {
            by: Some("T1059.001".to_owned())
        }
    );
    assert_eq!(
        framework.technique("T1064").expect("Scripting").state,
        State::Deprecated
    );
}

#[test]
fn sigma_tags_name_techniques_and_nothing_else() {
    assert_eq!(
        technique_of_tag("attack.t1059.001").as_deref(),
        Some("T1059.001")
    );
    assert_eq!(technique_of_tag("attack.T1078").as_deref(), Some("T1078"));
    for other in [
        "attack.execution",
        "attack.g0016",
        "attack.s0002",
        "attack.t1059.1",
        "attack.t10590",
        "cve.2021-44228",
        "t1059",
    ] {
        assert_eq!(technique_of_tag(other), None, "{other}");
    }
}

#[test]
fn coverage_separates_detected_blind_collected_and_uncovered() {
    let framework = framework();
    let tags = |tags: &[&str]| tags.iter().map(|tag| (*tag).to_owned()).collect::<Vec<_>>();
    let rules = [
        RuleRef::from_sigma_tags(
            "Encoded PowerShell",
            &tags(&["attack.execution", "attack.t1059.001"]),
        ),
        RuleRef::from_sigma_tags("Password spraying", &tags(&["attack.t1110.003"])),
        RuleRef::from_sigma_tags("Old PowerShell", &tags(&["attack.t1086"])),
        RuleRef::from_sigma_tags("Scripting", &tags(&["attack.t1064"])),
        RuleRef::from_sigma_tags("Typo", &tags(&["attack.t9999"])),
    ];
    let collected = [
        "Process Creation".to_owned(),
        "Command Execution".to_owned(),
    ];
    let coverage = assess(&framework, &rules, &collected).expect("assessed");
    assert_eq!(coverage.version, "19.2");

    let verdict = |id: &str| coverage.techniques[id].verdict;
    assert_eq!(verdict("T1059.001"), Verdict::Detected);
    // A rule exists and cannot fire: no authentication data is collected.
    assert_eq!(verdict("T1110.003"), Verdict::Blind);
    assert_eq!(verdict("T1071"), Verdict::Collected);
    assert_eq!(verdict("T1110"), Verdict::Uncovered);
    assert_eq!(
        coverage.techniques["T1059.001"].rules,
        ["Encoded PowerShell"]
    );
    // Only current techniques are assessed.
    assert!(!coverage.techniques.contains_key("T1086"));
    assert!(!coverage.techniques.contains_key("T1064"));

    assert_eq!(
        coverage.broken,
        [
            BrokenReference {
                rule: "Old PowerShell".to_owned(),
                technique: "T1086".to_owned(),
                why: Broken::Revoked {
                    by: Some("T1059.001".to_owned())
                },
            },
            BrokenReference {
                rule: "Scripting".to_owned(),
                technique: "T1064".to_owned(),
                why: Broken::Deprecated,
            },
            BrokenReference {
                rule: "Typo".to_owned(),
                technique: "T9999".to_owned(),
                why: Broken::Unknown,
            },
        ]
    );
    assert_eq!(coverage.with(Verdict::Blind).count(), 1);
}

#[test]
fn a_misspelled_data_component_is_refused() {
    let framework = framework();
    match assess(&framework, &[], &["Proces Creation".to_owned()]) {
        Err(AttackError::UnknownDataComponent { name, version }) => {
            assert_eq!(name, "Proces Creation");
            assert_eq!(version, "19.2");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_navigator_layer_colours_each_verdict() {
    let framework = framework();
    let rules = [
        RuleRef::from_sigma_tags("Encoded PowerShell", &["attack.t1059.001".to_owned()]),
        RuleRef::from_sigma_tags("Password spraying", &["attack.t1110.003".to_owned()]),
    ];
    let coverage = assess(&framework, &rules, &["Process Creation".to_owned()]).expect("assessed");
    let layer = layer(&framework, &coverage, "Coverage");
    assert_eq!(layer["versions"]["attack"], "19");
    assert_eq!(layer["versions"]["layer"], "4.5");
    assert_eq!(layer["domain"], "enterprise-attack");
    let entry = |id: &str| {
        layer["techniques"]
            .as_array()
            .expect("techniques")
            .iter()
            .find(|entry| entry["techniqueID"] == id)
            .cloned()
    };
    let powershell = entry("T1059.001").expect("detected");
    assert_eq!(powershell["color"], "#3fb950");
    assert_eq!(
        powershell["comment"],
        "Rules: Encoded PowerShell. Collected: Process Creation"
    );
    let spraying = entry("T1110.003").expect("blind");
    assert_eq!(spraying["color"], "#e0533d");
    assert_eq!(
        spraying["comment"],
        "Rules: Password spraying. Needs one of: User Account Authentication"
    );
    assert_eq!(
        entry("T1059").expect("collected")["showSubtechniques"],
        true
    );
    assert!(
        entry("T1110").is_none(),
        "uncovered techniques are not coloured"
    );
    assert_eq!(layer["legendItems"].as_array().map(Vec::len), Some(3));
}

/// Against a whole published bundle, when `GOLIATH_ATTACK_BUNDLE` names
/// one, such as enterprise-attack-19.2.json from attack-stix-data.
#[test]
fn a_whole_bundle_loads() {
    let Ok(path) = std::env::var("GOLIATH_ATTACK_BUNDLE") else {
        eprintln!("GOLIATH_ATTACK_BUNDLE is not set; skipping");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("the bundle reads");
    let framework = Framework::from_stix(&text).expect("the bundle loads");
    let current: Vec<_> = framework
        .techniques()
        .filter(|technique| technique.state == State::Active)
        .collect();
    assert!(current.len() > 500, "{}", current.len());
    for technique in &current {
        if technique.id.contains('.') {
            assert!(technique.parent.is_some(), "{} has no parent", technique.id);
        }
        assert!(
            !technique.tactics.is_empty(),
            "{} has no tactic",
            technique.id
        );
    }
    let with_data = current
        .iter()
        .filter(|technique| !technique.data_components.is_empty())
        .count();
    eprintln!(
        "ATT&CK {}: {} current techniques, {} with data components",
        framework.version(),
        current.len(),
        with_data
    );
}
