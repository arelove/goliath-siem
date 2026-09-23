//! Runs `SigmaHQ`'s regression data through Goliath.
//!
//! ```text
//! cargo run --release -p goliath-match --example sigma_regression -- \
//!     <`SigmaHQ` checkout> <mapping set file>
//! ```
//!
//! `SigmaHQ` ships, for many rules, real Windows events recorded while the
//! attack was performed, with the number of times the rule must fire on them.
//! Each case here is checked end to end: the rule is parsed, resolved through
//! the mapping set, and evaluated by the reference evaluator against the
//! events converted to OCSF.
//!
//! The conversion from Sysmon to OCSF lives in this file for now. It stands in
//! for the Sysmon source definition that milestone M2 delivers, and covers
//! process creation only. Because the same project wrote both it and the
//! mapping set, a case passing shows that parsing, resolution, and evaluation
//! agree with `SigmaHQ`; it cannot show on its own that the mapping chose the
//! right OCSF attributes.
//!
//! Every event is also evaluated against every other loaded rule. A rule that
//! fires on another rule's attack is not necessarily wrong, since attacks
//! overlap, but the list is where overly broad rules show up.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

use goliath_match::ReferenceRule;
use goliath_rule::{MappingSet, sigma};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// The rule directories of a `SigmaHQ` checkout.
const RULE_SETS: [&str; 3] = ["rules", "rules-emerging-threats", "rules-threat-hunting"];

#[derive(Deserialize)]
struct Info {
    rule_metadata: Vec<RuleMetadata>,
    regression_tests_info: Vec<TestInfo>,
}

#[derive(Deserialize)]
struct RuleMetadata {
    id: String,
}

#[derive(Deserialize)]
struct TestInfo {
    #[serde(rename = "type")]
    kind: String,
    /// Absent in some cases, which then only require the rule to fire.
    match_count: Option<usize>,
    path: String,
}

struct Loaded {
    title: String,
    rule: ReferenceRule,
}

#[derive(Default)]
struct Report {
    passed: Vec<String>,
    failed: Vec<(String, String, usize)>,
    skipped: BTreeMap<&'static str, usize>,
    /// Rule title to the titles of other rules whose events it fired on.
    cross_fires: BTreeMap<String, Vec<String>>,
    events: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let (Some(root), Some(mapping)) = (args.next(), args.next()) else {
        return Err("usage: sigma_regression <SigmaHQ checkout> <mapping set file>".into());
    };
    let root = PathBuf::from(root);
    let mappings = MappingSet::from_yaml(&fs::read_to_string(mapping)?)?;

    let rules = load_rules(&root, &mappings)?;

    let mut infos = Vec::new();
    collect(&root.join("regression_data"), "info.yml", &mut infos)?;
    infos.sort();

    let mut report = Report::default();
    for info in &infos {
        run_case(&root, info, &rules, &mut report);
    }

    print!("{}", render(&report, infos.len(), rules.len()));
    Ok(())
}

/// Every rule that loads, by rule identifier.
fn load_rules(
    root: &Path,
    mappings: &MappingSet,
) -> Result<BTreeMap<String, Loaded>, Box<dyn Error>> {
    let mut files = Vec::new();
    for set in RULE_SETS {
        collect(&root.join(set), ".yml", &mut files)?;
    }

    let mut rules = BTreeMap::new();
    for file in files {
        let Ok(source) = fs::read_to_string(&file) else {
            continue;
        };
        let Ok(parsed) = goliath_sigma::parse_rule(&source) else {
            continue;
        };
        let Some(id) = parsed.id.clone() else {
            continue;
        };
        let Ok(resolved) = sigma::resolve(&parsed, mappings) else {
            continue;
        };
        let Ok(rule) = ReferenceRule::new(resolved) else {
            continue;
        };
        rules.insert(
            id,
            Loaded {
                title: parsed.title,
                rule,
            },
        );
    }
    Ok(rules)
}

fn collect(directory: &Path, suffix: &str, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, suffix, files)?;
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(suffix))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn run_case(root: &Path, info_path: &Path, rules: &BTreeMap<String, Loaded>, report: &mut Report) {
    let skip = |report: &mut Report, reason: &'static str| {
        *report.skipped.entry(reason).or_default() += 1;
    };

    let Ok(text) = fs::read_to_string(info_path) else {
        return skip(report, "info.yml unreadable");
    };
    let Ok(info) = goliath_sigma::yaml::from_str::<Info>(&text) else {
        return skip(report, "info.yml malformed");
    };
    let Some(id) = info.rule_metadata.first().map(|rule| rule.id.as_str()) else {
        return skip(report, "info.yml names no rule");
    };
    let Some(loaded) = rules.get(id) else {
        return skip(report, "rule not loaded (no mapping for its log source)");
    };
    // Every case has the EVTX recording; its JSON export sits beside it with
    // the same name, whether or not `info.yml` lists it.
    let Some(case) = info
        .regression_tests_info
        .iter()
        .find(|case| case.kind == "json")
        .or_else(|| info.regression_tests_info.first())
    else {
        return skip(report, "info.yml lists no test");
    };
    let events_path = root.join(&case.path).with_extension("json");

    // Antivirus software may refuse to open recorded attack telemetry.
    let Ok(raw) = fs::read_to_string(events_path) else {
        return skip(report, "event file unreadable (antivirus quarantine)");
    };
    let events: Vec<Value> = serde_json::Deserializer::from_str(&raw)
        .into_iter::<Value>()
        .filter_map(Result::ok)
        .collect();
    let converted: Vec<Value> = events.iter().filter_map(sysmon_process_creation).collect();
    if converted.is_empty() {
        return skip(report, "not Sysmon process creation events");
    }
    report.events += converted.len();

    let matches = converted
        .iter()
        .filter(|event| loaded.rule.matches(event))
        .count();
    let expected = case
        .match_count
        .map_or_else(|| "at least 1".to_owned(), |count| count.to_string());
    let passed = case
        .match_count
        .map_or(matches > 0, |count| matches == count);
    if passed {
        report.passed.push(loaded.title.clone());
    } else {
        report
            .failed
            .push((loaded.title.clone(), expected, matches));
    }

    for (other_id, other) in rules {
        if other_id != id && converted.iter().any(|event| other.rule.matches(event)) {
            report
                .cross_fires
                .entry(other.title.clone())
                .or_default()
                .push(loaded.title.clone());
        }
    }
}

/// Converts a Sysmon process creation event, as `SigmaHQ`'s EVTX to JSON export
/// writes it, into an OCSF Process Activity event.
///
/// Returns `None` for any other event. The attribute choices mirror the
/// `sigma-windows` mapping set.
fn sysmon_process_creation(record: &Value) -> Option<Value> {
    let event = record.get("Event")?;
    let system = event.get("System")?;
    let provider = system.pointer("/Provider/#attributes/Name")?.as_str()?;
    if provider != "Microsoft-Windows-Sysmon" || system.get("EventID")?.as_i64()? != 1 {
        return None;
    }
    let data = event.get("EventData")?;
    let field = |name: &str| data.get(name).filter(|value| !value.is_null()).cloned();

    let mut process = Map::new();
    let mut parent = Map::new();
    let mut unmapped = Map::new();

    set(&mut process, "file.path", field("Image"));
    set(&mut process, "cmd_line", field("CommandLine"));
    set(&mut process, "pid", field("ProcessId"));
    set(&mut process, "uid", field("ProcessGuid"));
    set(&mut process, "working_directory", field("CurrentDirectory"));
    set(&mut process, "integrity", field("IntegrityLevel"));
    set(&mut process, "user.name", field("User"));
    set(&mut process, "session.uid", field("LogonId"));
    set(&mut process, "file.product.name", field("Product"));
    set(&mut process, "file.company_name", field("Company"));
    set(&mut process, "file.desc", field("Description"));
    set(&mut process, "file.version", field("FileVersion"));

    set(&mut parent, "file.path", field("ParentImage"));
    set(&mut parent, "cmd_line", field("ParentCommandLine"));
    set(&mut parent, "pid", field("ParentProcessId"));
    set(&mut parent, "uid", field("ParentProcessGuid"));
    set(&mut parent, "user.name", field("ParentUser"));
    process.insert("parent_process".to_owned(), Value::Object(parent));

    for name in [
        "OriginalFileName",
        "Hashes",
        "LogonGuid",
        "TerminalSessionId",
    ] {
        if let Some(value) = field(name) {
            unmapped.insert(name.to_owned(), value);
        }
    }

    Some(json!({
        "class_uid": 1007,
        "category_uid": 1,
        "activity_id": 1,
        "type_uid": 100_701,
        "metadata": { "version": "1.5.0", "product": { "name": "Sysmon", "vendor_name": "Microsoft" } },
        "device": { "hostname": system.get("Computer"), "os": { "type_id": 100, "name": "Windows" } },
        "process": process,
        "unmapped": unmapped,
    }))
}

/// Sets a dotted path in an object, creating intermediate objects.
fn set(object: &mut Map<String, Value>, path: &str, value: Option<Value>) {
    let Some(value) = value else {
        return;
    };
    match path.split_once('.') {
        None => {
            object.insert(path.to_owned(), value);
        }
        Some((head, rest)) => {
            let child = object
                .entry(head.to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(child) = child {
                set(child, rest, Some(value));
            }
        }
    }
}

fn render(report: &Report, cases: usize, rules: usize) -> String {
    let mut out = String::new();
    let run = report.passed.len() + report.failed.len();

    let _ = writeln!(out, "# Sigma regression\n");
    let _ = writeln!(out, "| Outcome | Cases |\n| --- | ---: |");
    let _ = writeln!(out, "| Regression cases | {cases} |");
    let _ = writeln!(out, "| Run | {run} |");
    let _ = writeln!(out, "| Passed | {} |", report.passed.len());
    let _ = writeln!(out, "| Failed | {} |", report.failed.len());
    for (reason, count) in &report.skipped {
        let _ = writeln!(out, "| Skipped: {reason} | {count} |");
    }
    let _ = writeln!(
        out,
        "\n{} events converted; {rules} rules loaded for cross-checking.",
        report.events
    );

    let _ = writeln!(out, "\n## Failures\n");
    for (title, expected, actual) in &report.failed {
        let _ = writeln!(out, "- {title}: expected {expected}, matched {actual}");
    }

    let mut broad: Vec<_> = report.cross_fires.iter().collect();
    broad.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    let _ = writeln!(out, "\n## Rules firing on other rules' events\n");
    let _ = writeln!(
        out,
        "{} rules fired on at least one other rule's events. Most often:\n",
        broad.len()
    );
    for (title, others) in broad.into_iter().take(15) {
        let _ = writeln!(out, "- {title}: {}", others.len());
    }
    out
}
