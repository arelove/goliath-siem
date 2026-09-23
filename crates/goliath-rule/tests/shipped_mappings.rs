//! Checks the mapping sets shipped in `mappings/`.

#![allow(clippy::expect_used)]

use goliath_rule::{ClassValue, FieldPath, LogSourceSelector, MappingSet};

const SIGMA_WINDOWS: &str = include_str!("../mappings/sigma-windows.yaml");

fn process_creation() -> LogSourceSelector {
    LogSourceSelector {
        category: Some("process_creation".to_owned()),
        product: Some("windows".to_owned()),
        service: None,
    }
}

#[test]
fn sigma_windows_loads() {
    let set = MappingSet::from_yaml(SIGMA_WINDOWS).expect("shipped mapping set loads");
    assert_eq!(set.name, "sigma-windows");
}

#[test]
fn process_creation_is_restricted_to_windows_process_launches() {
    let set = MappingSet::from_yaml(SIGMA_WINDOWS).expect("loads");
    let entry = set.select(&process_creation()).expect("selected");
    let class = |path: &str| &entry.class[&FieldPath::parse(path).expect("valid path")];

    assert_eq!(class("class_uid"), &ClassValue::Integer(1007));
    assert_eq!(class("activity_id"), &ClassValue::Integer(1));
    assert_eq!(class("device.os.type_id"), &ClassValue::Integer(100));
}

#[test]
fn process_creation_maps_the_whole_sigma_taxonomy() {
    // The fields the Sigma taxonomy defines for Windows process creation. A
    // field missing here makes every rule that uses it fail to load.
    const TAXONOMY: [&str; 21] = [
        "Image",
        "OriginalFileName",
        "CommandLine",
        "CurrentDirectory",
        "IntegrityLevel",
        "User",
        "LogonId",
        "LogonGuid",
        "TerminalSessionId",
        "ProcessId",
        "ProcessGuid",
        "Hashes",
        "Product",
        "Company",
        "Description",
        "FileVersion",
        "ParentImage",
        "ParentCommandLine",
        "ParentProcessId",
        "ParentProcessGuid",
        "ParentUser",
    ];

    let set = MappingSet::from_yaml(SIGMA_WINDOWS).expect("loads");
    let entry = set.select(&process_creation()).expect("selected");
    for field in TAXONOMY {
        assert!(entry.fields.contains_key(field), "{field} is not mapped");
    }
}

#[test]
fn every_sysmon_category_has_its_ocsf_class() {
    let set = MappingSet::from_yaml(SIGMA_WINDOWS).expect("loads");
    let class_uid = FieldPath::parse("class_uid").expect("valid path");
    for (category, expected) in [
        ("process_creation", 1007),
        ("file_event", 1001),
        ("image_load", 1005),
        ("network_connection", 4001),
        ("registry_set", 201_002),
    ] {
        let logsource = LogSourceSelector {
            category: Some(category.to_owned()),
            product: Some("windows".to_owned()),
            service: None,
        };
        let entry = set.select(&logsource).expect("selected");
        assert_eq!(
            entry.class[&class_uid],
            ClassValue::Integer(expected),
            "{category}"
        );
    }
}
