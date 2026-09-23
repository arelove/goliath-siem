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
//! the Sysmon events the mapping set has entries for: process creation,
//! network connections, image loads, file creation, and registry value sets. Because the same project wrote both it and the
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
use std::time::{Duration, Instant};
use std::{env, fs};

use goliath_match::{Engine, ReferenceRule};
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
    /// Every converted event, for comparing the engine with the reference.
    converted: Vec<Value>,
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

    let comparison = compare_engine(&rules, &report.converted)?;
    print!("{}", render(&report, infos.len(), rules.len()));
    print!("{comparison}");
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
    let converted: Vec<Value> = events.iter().filter_map(sysmon).collect();
    if converted.is_empty() {
        return skip(report, "no Sysmon events of a converted type");
    }
    report.events += converted.len();
    report.converted.extend(converted.iter().cloned());

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

/// Minimum time spent timing each evaluator, so short runs are not noise.
const TIMING: Duration = Duration::from_secs(3);

/// Checks that the engine returns exactly what the reference evaluator
/// returns on every converted event, then times both.
fn compare_engine(
    rules: &BTreeMap<String, Loaded>,
    events: &[Value],
) -> Result<String, Box<dyn Error>> {
    let references: Vec<&ReferenceRule> = rules.values().map(|loaded| &loaded.rule).collect();
    let started = Instant::now();
    let engine = Engine::new(
        references
            .iter()
            .map(|reference| reference.rule().clone())
            .collect(),
    )?;
    let compile = started.elapsed();

    let reference_matches = |event: &Value| -> Vec<usize> {
        references
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.matches(event))
            .map(|(index, _)| index)
            .collect()
    };

    let mut disagreements = 0;
    let mut matches = 0;
    for event in events {
        let expected = reference_matches(event);
        matches += expected.len();
        if engine.matches(event) != expected {
            disagreements += 1;
        }
    }

    let reference_rate = rate(events, |event| reference_matches(event).len());
    let engine_rate = rate(events, |event| engine.matches(event).len());

    let mut out = String::new();
    let _ = writeln!(
        out,
        "
## Engine against the reference evaluator
"
    );
    let _ = writeln!(
        out,
        "| Measure | Value |
| --- | ---: |"
    );
    let _ = writeln!(out, "| Rules | {} |", references.len());
    let _ = writeln!(out, "| Events | {} |", events.len());
    let _ = writeln!(out, "| Rule matches | {matches} |");
    let _ = writeln!(out, "| Events where the two disagree | {disagreements} |");
    let _ = writeln!(
        out,
        "| Engine compile time | {:.0} ms |",
        compile.as_secs_f64() * 1e3
    );
    let _ = writeln!(
        out,
        "| Reference, events/s on one core | {reference_rate:.0} |"
    );
    let _ = writeln!(out, "| Engine, events/s on one core | {engine_rate:.0} |");
    let _ = writeln!(out, "| Speedup | {:.1}x |", engine_rate / reference_rate);
    Ok(out)
}

/// Events per second for `evaluate`, over repeated passes of `events`.
#[allow(clippy::cast_precision_loss)] // Event counts are far below 2^52.
fn rate(events: &[Value], mut evaluate: impl FnMut(&Value) -> usize) -> f64 {
    let started = Instant::now();
    let mut evaluated = 0_usize;
    let mut sink = 0_usize;
    while started.elapsed() < TIMING {
        for event in events {
            sink = sink.wrapping_add(evaluate(event));
        }
        evaluated += events.len();
    }
    std::hint::black_box(sink);
    evaluated as f64 / started.elapsed().as_secs_f64()
}

/// How one Sysmon event becomes an OCSF event.
struct SysmonEvent {
    event_id: i64,
    class_uid: u32,
    activity_id: u32,
    /// Sysmon field and the OCSF path it is written to. A name listed with
    /// no path is kept under `unmapped`.
    fields: &'static [(&'static str, Option<&'static str>)],
}

/// The Sysmon events converted, mirroring the `sigma-windows` mapping set.
const SYSMON: [SysmonEvent; 5] = [
    SysmonEvent {
        event_id: 1,
        class_uid: 1007,
        activity_id: 1,
        fields: &[
            ("Image", Some("process.file.path")),
            ("CommandLine", Some("process.cmd_line")),
            ("ProcessId", Some("process.pid")),
            ("ProcessGuid", Some("process.uid")),
            ("CurrentDirectory", Some("process.working_directory")),
            ("IntegrityLevel", Some("process.integrity")),
            ("User", Some("process.user.name")),
            ("LogonId", Some("process.session.uid")),
            ("Product", Some("process.file.product.name")),
            ("Company", Some("process.file.company_name")),
            ("Description", Some("process.file.desc")),
            ("FileVersion", Some("process.file.version")),
            ("ParentImage", Some("process.parent_process.file.path")),
            ("ParentCommandLine", Some("process.parent_process.cmd_line")),
            ("ParentProcessId", Some("process.parent_process.pid")),
            ("ParentProcessGuid", Some("process.parent_process.uid")),
            ("ParentUser", Some("process.parent_process.user.name")),
            ("OriginalFileName", None),
            ("Hashes", None),
            ("LogonGuid", None),
            ("TerminalSessionId", None),
        ],
    },
    SysmonEvent {
        event_id: 3,
        class_uid: 4001,
        activity_id: 1,
        fields: &[
            ("Image", Some("actor.process.file.path")),
            ("ProcessId", Some("actor.process.pid")),
            ("ProcessGuid", Some("actor.process.uid")),
            ("User", Some("actor.user.name")),
            ("Protocol", Some("connection_info.protocol_name")),
            ("SourceIp", Some("src_endpoint.ip")),
            ("SourceHostname", Some("src_endpoint.hostname")),
            ("SourcePort", Some("src_endpoint.port")),
            ("DestinationIp", Some("dst_endpoint.ip")),
            ("DestinationHostname", Some("dst_endpoint.hostname")),
            ("DestinationPort", Some("dst_endpoint.port")),
            ("Initiated", None),
            ("SourceIsIpv6", None),
            ("DestinationIsIpv6", None),
        ],
    },
    SysmonEvent {
        event_id: 7,
        class_uid: 1005,
        activity_id: 1,
        fields: &[
            ("Image", Some("actor.process.file.path")),
            ("ProcessId", Some("actor.process.pid")),
            ("ProcessGuid", Some("actor.process.uid")),
            ("User", Some("actor.user.name")),
            ("ImageLoaded", Some("module.file.path")),
            ("Product", Some("module.file.product.name")),
            ("Company", Some("module.file.company_name")),
            ("Description", Some("module.file.desc")),
            ("FileVersion", Some("module.file.version")),
            ("OriginalFileName", None),
            ("Hashes", None),
            ("Signed", None),
            ("Signature", None),
            ("SignatureStatus", None),
        ],
    },
    SysmonEvent {
        event_id: 11,
        class_uid: 1001,
        activity_id: 1,
        fields: &[
            ("Image", Some("actor.process.file.path")),
            ("ProcessId", Some("actor.process.pid")),
            ("ProcessGuid", Some("actor.process.uid")),
            ("User", Some("actor.user.name")),
            ("TargetFilename", Some("file.path")),
            ("CreationUtcTime", None),
        ],
    },
    SysmonEvent {
        event_id: 13,
        class_uid: 201_002,
        activity_id: 2,
        fields: &[
            ("Image", Some("actor.process.file.path")),
            ("ProcessId", Some("actor.process.pid")),
            ("ProcessGuid", Some("actor.process.uid")),
            ("User", Some("actor.user.name")),
            ("TargetObject", Some("reg_value.path")),
            ("Details", None),
            ("EventType", None),
        ],
    },
];

/// Converts a Sysmon event, as `SigmaHQ`'s EVTX to JSON export writes it,
/// into an OCSF event.
///
/// Returns `None` for events of other providers and for Sysmon events not in
/// [`SYSMON`].
fn sysmon(record: &Value) -> Option<Value> {
    let event = record.get("Event")?;
    let system = event.get("System")?;
    let provider = system.pointer("/Provider/#attributes/Name")?.as_str()?;
    if provider != "Microsoft-Windows-Sysmon" {
        return None;
    }
    let event_id = system.get("EventID")?.as_i64()?;
    let spec = SYSMON.iter().find(|spec| spec.event_id == event_id)?;
    let data = event.get("EventData")?;

    let mut ocsf = Map::new();
    let mut unmapped = Map::new();
    for (name, path) in spec.fields {
        let Some(value) = data.get(*name).filter(|value| !value.is_null()).cloned() else {
            continue;
        };
        match path {
            Some(path) => set(&mut ocsf, path, Some(value)),
            None => {
                unmapped.insert((*name).to_owned(), value);
            }
        }
    }

    let category_uid = spec.class_uid % 100_000 / 1000;
    ocsf.insert("class_uid".to_owned(), json!(spec.class_uid));
    ocsf.insert("category_uid".to_owned(), json!(category_uid));
    ocsf.insert("activity_id".to_owned(), json!(spec.activity_id));
    ocsf.insert(
        "type_uid".to_owned(),
        json!(u64::from(spec.class_uid) * 100 + u64::from(spec.activity_id)),
    );
    ocsf.insert(
        "metadata".to_owned(),
        json!({ "version": "1.5.0", "product": { "name": "Sysmon", "vendor_name": "Microsoft" } }),
    );
    ocsf.insert(
        "device".to_owned(),
        json!({ "hostname": system.get("Computer"), "os": { "type_id": 100, "name": "Windows" } }),
    );
    ocsf.insert("unmapped".to_owned(), Value::Object(unmapped));
    Some(Value::Object(ocsf))
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
