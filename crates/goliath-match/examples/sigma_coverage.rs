//! Reports how much of a Sigma rule repository Goliath can load.
//!
//! ```text
//! cargo run --release -p goliath-match --example sigma_coverage -- \
//!     <rules directory> <mapping set file>
//! ```
//!
//! Every `.yml` file under the directory goes through the whole chain: parse,
//! resolve through the mapping set, compile for the reference evaluator. The
//! report counts where each rule stops, ranks the unmapped fields and log
//! sources that stopped the most, and lists parse failures by kind, which is
//! where a parser bug shows up first.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

use goliath_match::ReferenceRule;
use goliath_rule::{MappingError, MappingSet, ResolveError, sigma};

/// How many entries each ranked list shows.
const TOP: usize = 15;

#[derive(Default)]
struct Report {
    files: usize,
    loaded: usize,
    parse_failures: BTreeMap<String, Vec<PathBuf>>,
    no_mapping: BTreeMap<String, usize>,
    unmapped_fields: BTreeMap<String, usize>,
    other_resolve_failures: BTreeMap<String, Vec<PathBuf>>,
    compile_failures: Vec<(PathBuf, String)>,
    /// Loaded and total, per log source that has a mapping.
    mapped_sources: BTreeMap<String, (usize, usize)>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let (Some(rules), Some(mapping)) = (args.next(), args.next()) else {
        return Err("usage: sigma_coverage <rules directory> <mapping set file>".into());
    };
    let mappings = MappingSet::from_yaml(&fs::read_to_string(mapping)?)?;

    let mut files = Vec::new();
    collect(Path::new(&rules), &mut files)?;
    files.sort();

    let mut report = Report::default();
    for file in &files {
        report.files += 1;
        check(file, &mappings, &mut report)?;
    }

    print!("{}", render(&report, &mappings));
    Ok(())
}

fn collect(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "yml") {
            files.push(path);
        }
    }
    Ok(())
}

fn check(file: &Path, mappings: &MappingSet, report: &mut Report) -> Result<(), Box<dyn Error>> {
    let source = fs::read_to_string(file)?;
    let rule = match goliath_sigma::parse_rule(&source) {
        Ok(rule) => rule,
        Err(error) => {
            report
                .parse_failures
                .entry(kind(&error))
                .or_default()
                .push(file.to_owned());
            return Ok(());
        }
    };

    let logsource = goliath_rule::LogSourceSelector::from(&rule.logsource).to_string();
    let has_mapping = mappings.select(&(&rule.logsource).into()).is_ok();
    if has_mapping {
        report
            .mapped_sources
            .entry(logsource.clone())
            .or_default()
            .1 += 1;
    }

    let resolved = match sigma::resolve(&rule, mappings) {
        Ok(resolved) => resolved,
        Err(ResolveError::Mapping(MappingError::NoMapping { .. })) => {
            *report.no_mapping.entry(logsource).or_default() += 1;
            return Ok(());
        }
        Err(ResolveError::UnmappedField { field, .. }) => {
            *report
                .unmapped_fields
                .entry(format!("{field} ({logsource})"))
                .or_default() += 1;
            return Ok(());
        }
        Err(error) => {
            report
                .other_resolve_failures
                .entry(error.to_string())
                .or_default()
                .push(file.to_owned());
            return Ok(());
        }
    };

    match ReferenceRule::new(resolved) {
        Ok(_) => {
            report.loaded += 1;
            if has_mapping {
                report.mapped_sources.entry(logsource).or_default().0 += 1;
            }
        }
        Err(error) => report
            .compile_failures
            .push((file.to_owned(), error.to_string())),
    }
    Ok(())
}

/// The variant name of an error, from its debug form.
fn kind(error: &impl std::fmt::Debug) -> String {
    let debug = format!("{error:?}");
    debug
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn render(report: &Report, mappings: &MappingSet) -> String {
    let mut out = String::new();
    let failed_parse: usize = report.parse_failures.values().map(Vec::len).sum();
    let no_mapping: usize = report.no_mapping.values().sum();
    let unmapped: usize = report.unmapped_fields.values().sum();
    let other: usize = report.other_resolve_failures.values().map(Vec::len).sum();

    let _ = writeln!(
        out,
        "# Sigma coverage with {} v{}\n",
        mappings.name, mappings.version
    );
    let _ = writeln!(out, "| Outcome | Rules |\n| --- | ---: |");
    let _ = writeln!(out, "| Files | {} |", report.files);
    let _ = writeln!(out, "| Loaded | {} |", report.loaded);
    let _ = writeln!(out, "| Parse failed | {failed_parse} |");
    let _ = writeln!(out, "| No mapping for log source | {no_mapping} |");
    let _ = writeln!(out, "| Unmapped field | {unmapped} |");
    let _ = writeln!(out, "| Other resolution failure | {other} |");
    let _ = writeln!(out, "| Regex refused | {} |", report.compile_failures.len());

    let _ = writeln!(out, "\n## Log sources with a mapping\n");
    let _ = writeln!(
        out,
        "| Log source | Loaded | Rules | Share |\n| --- | ---: | ---: | ---: |"
    );
    for (source, (loaded, total)) in &report.mapped_sources {
        let _ = writeln!(
            out,
            "| {source} | {loaded} | {total} | {:.1}% |",
            percent(*loaded, *total)
        );
    }

    ranked(
        &mut out,
        "Log sources without a mapping",
        &report.no_mapping,
    );
    ranked(&mut out, "Unmapped fields", &report.unmapped_fields);

    let _ = writeln!(out, "\n## Parse failures by kind\n");
    for (kind, files) in &report.parse_failures {
        let _ = writeln!(
            out,
            "- {kind}: {} (e.g. {})",
            files.len(),
            files[0].display()
        );
    }

    let _ = writeln!(out, "\n## Other resolution failures\n");
    for (reason, files) in &report.other_resolve_failures {
        let _ = writeln!(
            out,
            "- {reason}: {} (e.g. {})",
            files.len(),
            files[0].display()
        );
    }

    let _ = writeln!(out, "\n## Refused regular expressions\n");
    for (file, reason) in &report.compile_failures {
        let first_line = reason.lines().next().unwrap_or_default();
        let _ = writeln!(out, "- {}: {first_line}", file.display());
    }
    out
}

fn ranked(out: &mut String, title: &str, counts: &BTreeMap<String, usize>) {
    let mut entries: Vec<_> = counts.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let _ = writeln!(out, "\n## {title}\n");
    for (name, count) in entries.into_iter().take(TOP) {
        let _ = writeln!(out, "- {name}: {count}");
    }
}

#[allow(clippy::cast_precision_loss)] // Rule counts are far below 2^52.
fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}
