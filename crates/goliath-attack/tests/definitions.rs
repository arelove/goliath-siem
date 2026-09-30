//! The data components shipped source definitions declare are data
//! components of ATT&CK, so that coverage never counts a misspelled one as
//! missing data.

#![allow(clippy::expect_used)]

use goliath_attack::Framework;
use goliath_normalize::{BUILTIN, Normalizer};

const SUBSET: &str = include_str!("data/enterprise-attack-subset.json");

#[test]
fn every_declared_data_component_is_one_of_attack() {
    let framework = Framework::from_stix(SUBSET).expect("the subset loads");
    for (name, yaml) in BUILTIN {
        let normalizer = Normalizer::from_yaml(yaml).expect("the definition loads");
        for component in normalizer.data_components() {
            assert!(
                framework.data_component_named(component).is_some(),
                "`{name}` declares `{component}`, which ATT&CK {} does not have",
                framework.version()
            );
        }
    }
}

#[test]
fn only_sources_attack_has_no_log_source_for_declare_nothing() {
    for (name, yaml) in BUILTIN {
        let normalizer = Normalizer::from_yaml(yaml).expect("the definition loads");
        assert_eq!(
            normalizer.data_components().is_empty(),
            *name == "falco",
            "{name}"
        );
    }
}
