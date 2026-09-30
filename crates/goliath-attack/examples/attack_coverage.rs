//! Coverage of a Sigma rule set against the data the shipped source
//! definitions supply, as a summary and an ATT&CK Navigator layer.
//!
//! ```text
//! cargo run --release -p goliath-attack --example attack_coverage -- \
//!     <enterprise-attack bundle> <rules directory> [sources] [layer file]
//! ```
//!
//! `sources` is a comma-separated list of shipped definitions, such as
//! `sysmon,windows-security`, or `all`, the default. The bundle is one of
//! attack-stix-data's, such as `enterprise-attack-19.2.json`.
//!
//! A rule can fire when it resolves through a shipped mapping set whose log
//! source one of the sources supplies: the Sysmon definitions for Windows
//! categories, `windows-security` for the Security log, and the AWS, Okta,
//! Microsoft 365, and Zeek definitions for their own. Rules for log sources with
//! no mapping yet, such as Linux auditd, count as unable to fire.

#![allow(clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::path::Path;
use std::{env, fs};

use goliath_attack::{Broken, Coverage, Framework, RuleRef, Verdict, assess, layer};
use goliath_normalize::{BUILTIN, Normalizer};
use goliath_rule::{MappingSet, sigma};

/// Each shipped mapping set, and the definitions that supply its log
/// sources; the Security log of the Windows set is `windows-security`'s.
const SETS: [(&str, &[&str]); 5] = [
    (goliath_rule::SIGMA_WINDOWS, &["sysmon", "sysmon-flat"]),
    (goliath_rule::SIGMA_AWS, &["cloudtrail"]),
    (goliath_rule::SIGMA_OKTA, &["okta"]),
    (goliath_rule::SIGMA_M365, &["m365"]),
    (goliath_rule::SIGMA_ZEEK, &["zeek"]),
];

fn main() {
    let mut args = env::args().skip(1);
    let (Some(bundle), Some(rules)) = (args.next(), args.next()) else {
        eprintln!("usage: attack_coverage <bundle> <rules directory> [sources] [layer file]");
        std::process::exit(2);
    };
    let sources = args.next().unwrap_or_else(|| "all".to_owned());
    let layer_file = args.next();

    let framework = Framework::from_stix(&fs::read_to_string(&bundle).expect("the bundle reads"))
        .expect("the bundle loads");

    let mut collected = Vec::new();
    let mut used = Vec::new();
    for (name, yaml) in BUILTIN {
        if sources != "all" && !sources.split(',').any(|wanted| wanted == *name) {
            continue;
        }
        used.push(*name);
        let normalizer = Normalizer::from_yaml(yaml).expect("the definition loads");
        for component in normalizer.data_components() {
            if !collected.contains(component) {
                collected.push(component.clone());
            }
        }
    }

    let sets: Vec<(MappingSet, &[&str])> = SETS
        .iter()
        .map(|(yaml, feeds)| (MappingSet::from_yaml(yaml).expect("the set loads"), *feeds))
        .collect();
    let can_fire = |rule: &goliath_sigma::Rule| {
        sets.iter().any(|(set, feeds)| {
            let feeds: &[&str] = if set.name == "sigma-windows"
                && rule.logsource.service.as_deref() == Some("security")
            {
                &["windows-security"]
            } else {
                feeds
            };
            feeds.iter().any(|feed| used.contains(feed)) && sigma::resolve(rule, set).is_ok()
        })
    };

    let mut files = Vec::new();
    walk(Path::new(&rules), &mut files);
    let mut refs = Vec::new();
    let mut unparsed = 0;
    for file in &files {
        let text = fs::read_to_string(file).expect("the rule reads");
        match goliath_sigma::parse_rule(&text) {
            Ok(rule) => refs.push(RuleRef::from_sigma_tags(
                &rule.title,
                &rule.tags,
                can_fire(&rule),
            )),
            Err(_) => unparsed += 1,
        }
    }
    let untagged = refs
        .iter()
        .filter(|rule| rule.techniques.is_empty())
        .count();

    let coverage = assess(&framework, &refs, &collected).expect("the declarations are known");
    let count = |verdict| coverage.with(verdict).count();

    println!(
        "# ATT&CK coverage, {} {}",
        framework.name(),
        framework.version()
    );
    println!();
    println!(
        "{} rules from {} ({} not parsed, {} with no technique); sources: {}; {} data components collected.",
        refs.len(),
        rules,
        unparsed,
        untagged,
        used.join(", "),
        collected.len()
    );
    println!();
    println!("| Verdict | Current techniques |");
    println!("| --- | ---: |");
    for (verdict, name) in [
        (Verdict::Detected, "Detected: a rule that can fire"),
        (Verdict::Blind, "Blind: rules, none of which can fire"),
        (Verdict::Collected, "Collected: data to detect it, no rule"),
        (Verdict::Uncovered, "Uncovered"),
    ] {
        println!("| {name} | {} |", count(verdict));
    }

    print_blind(&framework, &coverage);

    print_broken(&coverage);

    if let Some(path) = layer_file {
        let layer = layer(&framework, &coverage, "Goliath coverage");
        fs::write(&path, serde_json::to_string_pretty(&layer).expect("JSON"))
            .expect("the layer writes");
        println!("Navigator layer written to {path}.");
    }
}

/// How many rule references to techniques do not count, by why.
fn print_broken(coverage: &Coverage) {
    let mut broken: BTreeMap<&str, usize> = BTreeMap::new();
    for reference in &coverage.broken {
        let why = match reference.why {
            Broken::Revoked { .. } => "revoked",
            Broken::Deprecated => "deprecated",
            Broken::Unknown => "unknown",
        };
        *broken.entry(why).or_default() += 1;
    }
    println!();
    println!("Technique references that do not count: {broken:?}");
}

/// The blind techniques with the most rules: rules that exist and cannot
/// fire.
fn print_blind(framework: &Framework, coverage: &Coverage) {
    let mut blind: Vec<_> = coverage.with(Verdict::Blind).collect();
    blind.sort_by(|a, b| {
        b.blind_rules
            .len()
            .cmp(&a.blind_rules.len())
            .then(a.technique.cmp(&b.technique))
    });
    println!();
    println!("## Blind techniques with the most rules");
    println!();
    println!("| Technique | Rules that cannot fire | For example |");
    println!("| --- | ---: | --- |");
    for technique in blind.iter().take(15) {
        let name = framework
            .technique(&technique.technique)
            .map_or("", |known| known.name.as_str());
        println!(
            "| {} {} | {} | {} |",
            technique.technique,
            name,
            technique.blind_rules.len(),
            technique.blind_rules.first().map_or("", String::as_str)
        );
    }
}

fn walk(directory: &Path, files: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "yml") {
            files.push(path);
        }
    }
}
