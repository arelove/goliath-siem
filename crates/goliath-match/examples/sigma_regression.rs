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
//! The events reach OCSF through the Sysmon source definition shipped with
//! `goliath-normalize`, exactly as a deployment would normalize them. Because
//! the same project wrote both it and the mapping set, a case passing shows
//! that normalization, parsing, resolution, and evaluation agree with
//! `SigmaHQ`; it cannot show on its own that the two chose the right OCSF
//! attributes.
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
use goliath_normalize::{Normalizer, Outcome};
use goliath_rule::{MappingSet, sigma};
use serde::Deserialize;
use serde_json::Value;

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
    /// Values the Sysmon definition could not convert, as `target: reason`.
    issues: Vec<String>,
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

    let sysmon = Normalizer::from_yaml(goliath_normalize::SYSMON)?;
    let mut report = Report::default();
    for info in &infos {
        run_case(&root, info, &rules, &sysmon, &mut report);
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

fn run_case(
    root: &Path,
    info_path: &Path,
    rules: &BTreeMap<String, Loaded>,
    sysmon: &Normalizer,
    report: &mut Report,
) {
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
    let Ok(raw) = fs::read(events_path) else {
        return skip(report, "event file unreadable (antivirus quarantine)");
    };
    // Records of other providers, and Sysmon events of kinds the definition
    // does not cover, come out as dead letters; only events are tested.
    let mut converted: Vec<Value> = Vec::new();
    sysmon.normalize(&raw, |outcome| {
        if let Outcome::Event(normalized) = outcome {
            report.issues.extend(
                normalized
                    .issues
                    .iter()
                    .map(|issue| format!("{}: {}", issue.target, issue.reason)),
            );
            converted.push(normalized.event);
        }
    });
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
    let mut scratch = engine.scratch();
    let mut found = Vec::new();
    let engine_rate = rate(events, |event| {
        engine.matches_into(event, &mut scratch, &mut found);
        found.len()
    });
    // Powers of two up to every hardware thread, and every hardware thread.
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut counts: Vec<usize> = std::iter::successors(Some(2_usize), |count| Some(count * 2))
        .take_while(|&count| count < available)
        .collect();
    counts.push(available);
    let scaling: Vec<(usize, f64)> = counts
        .into_iter()
        .map(|threads| (threads, parallel_rate(&engine, events, threads)))
        .collect();

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
    for (threads, rate) in &scaling {
        let _ = writeln!(
            out,
            "| Engine, events/s on {threads} threads sharing it | {rate:.0} |"
        );
    }
    Ok(out)
}

/// Events per second for one engine shared by `threads` threads, each with
/// its own scratch, as a detector evaluates a stream on every core.
#[allow(clippy::cast_precision_loss)] // Event counts are far below 2^52.
fn parallel_rate(engine: &Engine, events: &[Value], threads: usize) -> f64 {
    let started = Instant::now();
    let evaluated: usize = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|offset| {
                scope.spawn(move || {
                    let mut scratch = engine.scratch();
                    let mut found = Vec::new();
                    let mut evaluated = 0_usize;
                    // Each thread starts at a different event, so the threads
                    // are not all reading the same event at the same time.
                    let start = offset * events.len() / threads;
                    while started.elapsed() < TIMING {
                        for event in events[start..].iter().chain(&events[..start]) {
                            engine.matches_into(event, &mut scratch, &mut found);
                            std::hint::black_box(&found);
                        }
                        evaluated += events.len();
                    }
                    evaluated
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or(0))
            .sum()
    });
    evaluated as f64 / started.elapsed().as_secs_f64()
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
        "\n{} events converted, {} values that did not convert; {rules} rules loaded for cross-checking.",
        report.events,
        report.issues.len()
    );
    for issue in &report.issues {
        let _ = writeln!(out, "- {issue}");
    }

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
