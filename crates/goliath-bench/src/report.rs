//! The benchmark rig's report: what a run observed, turned into the metrics
//! of `docs/architecture.md`'s benchmark method, as `report.md` and
//! `report.json`.
//!
//! Everything is computed from the platform's own metrics and the platform
//! process's CPU time and memory, sampled by the driver
//! (`docs/benchmark-rig.md`). The computation is pure; [`write`] adds the
//! only I/O: two bounded ClickHouse queries, the machine's description, and
//! the files.
//!
//! Three windows are kept apart. The first sample, at zero, is the baseline
//! after startup. The load window runs to [`Run::duration`]. Samples after it
//! are the drain, which proves the platform caught up but never counts
//! towards a sustained rate.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

/// One observation of the platform during a run.
#[derive(Debug, Clone, Default)]
pub struct Sample {
    /// Time since the load started.
    pub elapsed: Duration,
    /// The platform's `/metrics` text, as served.
    pub metrics: String,
    /// CPU time the platform process has used, in milliseconds.
    pub cpu_ms: u64,
    /// The platform process's resident memory.
    pub memory_bytes: u64,
    /// Records the driver had sent, and had acknowledged by the broker.
    pub sent_records: u64,
    /// Bytes of those records as the source wrote them, before stamping.
    pub sent_bytes: u64,
}

/// A run, as the driver describes it.
#[derive(Debug, Clone, Default)]
pub struct Run {
    /// The profile's name, such as `ci` or `laptop`.
    pub profile: String,
    /// The rate offered, in records per second.
    pub rate: u64,
    /// How long load was offered.
    pub duration: Duration,
    /// The run's own database.
    pub database: String,
    /// What `goliath --version` printed.
    pub goliath_version: String,
    /// Observations, the first at zero elapsed.
    pub samples: Vec<Sample>,
}

/// Why a report could not be written.
#[derive(Debug)]
pub struct ReportError(String);

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "report: {}", self.0)
    }
}

impl std::error::Error for ReportError {}

/// When a rate counts as sustained: the backlog, in records, over the second
/// half of the load window, grows by at most this share of the offered rate
/// each second...
pub const MAX_GROWTH: f64 = 0.01;

/// ...and never holds more than this many seconds of the offered rate.
pub const MAX_BACKLOG_SECONDS: f64 = 10.0;

/// The platform must have been offered at least this share of the target
/// rate for a verdict about the target: backpressure can hold the driver
/// back, and a rate not offered cannot be sustained.
pub const MIN_OFFERED: f64 = 0.95;

/// What a run showed, for the driver to print.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    /// Whether the target rate was sustained, and if not, why.
    pub verdict: Verdict,
    /// Outcomes stored per second over the load window.
    pub stored_rate: f64,
    /// Outcomes stored per second of platform CPU time over the load window.
    pub per_core: Option<f64>,
}

/// Whether a run sustained its target rate.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Offered in full, and the backlog stayed bounded.
    Sustained,
    /// The driver could not offer the target rate.
    NotOffered {
        /// The rate it did offer.
        offered: f64,
    },
    /// The backlog grew or held too much.
    Unbounded {
        /// Growth of the backlog over the second half, in records per second.
        growth: f64,
        /// The largest backlog there, in records.
        backlog: f64,
    },
    /// Too few samples in the load window to judge.
    Unmeasured(String),
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sustained => write!(f, "sustained"),
            Self::NotOffered { offered } => {
                write!(f, "not offered: the driver reached {offered:.0} records/s")
            }
            Self::Unbounded { growth, backlog } => write!(
                f,
                "not sustained: the backlog grew {growth:.0} records/s, up to {backlog:.0} records"
            ),
            Self::Unmeasured(reason) => write!(f, "not measured: {reason}"),
        }
    }
}

/// Writes `report.md` and `report.json` for `run` into `out`, reading the
/// run's database through `clickhouse` for what the platform stored.
///
/// # Errors
///
/// Returns [`ReportError`] if the run has no samples or a file cannot be
/// written. A failed ClickHouse query does not fail the report: its
/// measurement is marked unavailable, with the reason.
pub async fn write(
    run: &Run,
    clickhouse: &clickhouse::Client,
    out: &Path,
) -> Result<Summary, ReportError> {
    let storage = storage(clickhouse).await;
    let machine = machine();
    let computed = compute(run, storage)?;
    let report = document(run, &computed, &machine);
    std::fs::write(
        out.join("report.json"),
        serde_json::to_string_pretty(&report).unwrap_or_default() + "\n",
    )
    .map_err(|error| ReportError(format!("report.json: {error}")))?;
    std::fs::write(out.join("report.md"), markdown(run, &computed, &machine))
        .map_err(|error| ReportError(format!("report.md: {error}")))?;
    Ok(computed.summary())
}

/// A metric's samples in one `/metrics` text: labels and value.
type Series = Vec<(BTreeMap<String, String>, f64)>;

/// Reads Prometheus or `OpenMetrics` text into metrics by name. Comments,
/// and lines that do not parse, are skipped.
fn parse(text: &str) -> BTreeMap<String, Series> {
    let mut metrics: BTreeMap<String, Series> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, labels, rest) = match line.find('{') {
            Some(open) => {
                let Some(close) = line[open..].rfind('}').map(|at| open + at) else {
                    continue;
                };
                (
                    &line[..open],
                    labels(&line[open + 1..close]),
                    &line[close + 1..],
                )
            }
            None => match line.split_once(' ') {
                Some((name, rest)) => (name, BTreeMap::new(), rest),
                None => continue,
            },
        };
        // A value may be followed by a timestamp.
        let Some(value) = rest.split_whitespace().next().and_then(number) else {
            continue;
        };
        metrics
            .entry(name.to_owned())
            .or_default()
            .push((labels, value));
    }
    metrics
}

fn labels(text: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let mut rest = text;
    while let Some((name, after)) = rest.split_once("=\"") {
        let mut value = String::new();
        let mut chars = after.char_indices();
        let mut end = after.len();
        while let Some((at, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, escaped)) = chars.next() {
                        value.push(if escaped == 'n' { '\n' } else { escaped });
                    }
                }
                '"' => {
                    end = at + 1;
                    break;
                }
                other => value.push(other),
            }
        }
        labels.insert(name.trim_start_matches(',').trim().to_owned(), value);
        rest = &after[end..];
    }
    labels
}

fn number(text: &str) -> Option<f64> {
    match text {
        "+Inf" => Some(f64::INFINITY),
        "-Inf" => Some(f64::NEG_INFINITY),
        _ => text.parse().ok(),
    }
}

/// The sum of a metric's samples whose labels include every pair in
/// `filter`; zero if it has none.
fn total(metrics: &BTreeMap<String, Series>, name: &str, filter: &[(&str, &str)]) -> f64 {
    metrics.get(name).map_or(0.0, |series| {
        series
            .iter()
            .filter(|(labels, _)| {
                filter
                    .iter()
                    .all(|(key, value)| labels.get(*key).is_some_and(|found| found == value))
            })
            .map(|(_, value)| value)
            .sum()
    })
}

/// A histogram's cumulative counts by upper bound, `+Inf` last.
fn buckets(metrics: &BTreeMap<String, Series>, name: &str) -> Vec<(f64, f64)> {
    let mut buckets: Vec<(f64, f64)> = metrics
        .get(&format!("{name}_bucket"))
        .map(|series| {
            series
                .iter()
                .filter_map(|(labels, count)| Some((number(labels.get("le")?)?, *count)))
                .collect()
        })
        .unwrap_or_default();
    buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
    buckets
}

/// The value below which `quantile` of observations fall, interpolated
/// linearly within its bucket. `None` if nothing was observed; infinity if
/// it lies beyond the largest finite bound.
fn quantile(buckets: &[(f64, f64)], quantile: f64) -> Option<f64> {
    let count = buckets.last()?.1;
    if count <= 0.0 {
        return None;
    }
    let target = quantile * count;
    let mut lower = (0.0, 0.0);
    for &(bound, cumulative) in buckets {
        if cumulative >= target {
            if bound.is_infinite() {
                return Some(f64::INFINITY);
            }
            let within = cumulative - lower.1;
            let share = if within > 0.0 {
                (target - lower.1) / within
            } else {
                1.0
            };
            return Some(lower.0 + (bound - lower.0) * share);
        }
        lower = (bound, cumulative);
    }
    Some(f64::INFINITY)
}

/// The difference of two histograms' cumulative counts, bucket by bucket.
fn since(later: &[(f64, f64)], earlier: &[(f64, f64)]) -> Vec<(f64, f64)> {
    later
        .iter()
        .map(|&(bound, count)| {
            let before = earlier
                .iter()
                .find(|(other, _)| other.total_cmp(&bound).is_eq())
                .map_or(0.0, |(_, count)| *count);
            (bound, (count - before).max(0.0))
        })
        .collect()
}

/// A sample's metrics, parsed once.
struct Observed<'a> {
    sample: &'a Sample,
    metrics: BTreeMap<String, Series>,
}

impl Observed<'_> {
    fn seconds(&self) -> f64 {
        self.sample.elapsed.as_secs_f64()
    }

    fn stored(&self) -> f64 {
        total(&self.metrics, "goliath_stored_outcomes_total", &[])
    }

    fn events(&self) -> f64 {
        total(
            &self.metrics,
            "goliath_outcomes_total",
            &[("outcome", "event")],
        )
    }

    fn dead_letters(&self) -> f64 {
        total(
            &self.metrics,
            "goliath_outcomes_total",
            &[("outcome", "dead_letter")],
        )
    }

    /// Raw payloads the normalizer read.
    fn payloads(&self) -> f64 {
        total(&self.metrics, "goliath_normalized_records_total", &[])
    }

    fn lag(&self, reader: &str) -> f64 {
        total(
            &self.metrics,
            "goliath_reader_lag_records",
            &[("reader", reader)],
        )
    }
}

/// What the run's database holds, or why it could not be read.
#[derive(Debug, Clone)]
struct Storage {
    rows: Result<u64, String>,
    compressed_bytes: Result<u64, String>,
    uncompressed_bytes: Result<u64, String>,
}

impl Storage {
    fn unavailable(reason: &str) -> Self {
        Self {
            rows: Err(reason.to_owned()),
            compressed_bytes: Err(reason.to_owned()),
            uncompressed_bytes: Err(reason.to_owned()),
        }
    }
}

/// Everything the report states, computed.
#[derive(Debug, Clone)]
struct Computed {
    load_seconds: f64,
    offered_rate: f64,
    stored_rate: f64,
    sent_records: u64,
    sent_bytes: u64,
    stored_outcomes: f64,
    events: f64,
    dead_letters: BTreeMap<String, f64>,
    complete: bool,
    load_cpu_seconds: f64,
    drain_cpu_seconds: f64,
    cores_used: Option<f64>,
    per_core: Option<f64>,
    peak_memory: u64,
    latency_load: [Option<f64>; 3],
    latency_all: [Option<f64>; 3],
    backlog_growth: Option<f64>,
    backlog_peak: Option<f64>,
    verdict: Verdict,
    storage: Storage,
}

impl Computed {
    fn summary(&self) -> Summary {
        Summary {
            verdict: self.verdict.clone(),
            stored_rate: self.stored_rate,
            per_core: self.per_core,
        }
    }
}

const QUANTILES: [f64; 3] = [0.5, 0.95, 0.99];

// One pass over the run, in the order the report states things; split, it
// would only pass the same windows around.
#[allow(clippy::too_many_lines)]
fn compute(run: &Run, storage: Storage) -> Result<Computed, ReportError> {
    let observed: Vec<Observed<'_>> = run
        .samples
        .iter()
        .map(|sample| Observed {
            sample,
            metrics: parse(&sample.metrics),
        })
        .collect();
    let (Some(baseline), Some(last)) = (observed.first(), observed.last()) else {
        return Err(ReportError("the run has no samples".to_owned()));
    };
    // A sample a moment past the window still belongs to it: the driver
    // samples on a five-second tick.
    let window = run.duration.as_secs_f64() + 1.0;
    let load: Vec<&Observed<'_>> = observed
        .iter()
        .filter(|observed| observed.seconds() <= window)
        .collect();
    let end = load.last().copied().unwrap_or(baseline);
    let load_seconds = end.seconds();

    let per_second = |value: f64| {
        if load_seconds > 0.0 {
            value / load_seconds
        } else {
            0.0
        }
    };
    #[allow(clippy::cast_precision_loss)]
    let offered_rate = per_second(
        end.sample
            .sent_records
            .saturating_sub(baseline.sample.sent_records) as f64,
    );
    let stored_in_load = end.stored() - baseline.stored();
    let stored_rate = per_second(stored_in_load);

    #[allow(clippy::cast_precision_loss)]
    let cpu = |from: &Observed<'_>, to: &Observed<'_>| {
        to.sample.cpu_ms.saturating_sub(from.sample.cpu_ms) as f64 / 1000.0
    };
    let load_cpu_seconds = cpu(baseline, end);
    let drain_cpu_seconds = cpu(end, last);
    let cores_used = (load_seconds > 0.0).then(|| load_cpu_seconds / load_seconds);
    let per_core = (load_cpu_seconds > 0.0).then(|| stored_in_load / load_cpu_seconds);

    let histogram = "goliath_receipt_to_stored_seconds";
    let load_latency = since(
        &buckets(&end.metrics, histogram),
        &buckets(&baseline.metrics, histogram),
    );
    let all_latency = buckets(&last.metrics, histogram);

    // The backlog in records: raw lag counts payloads, each holding as many
    // records as the run's payloads did on average.
    let payloads = last.payloads();
    #[allow(clippy::cast_precision_loss)]
    let per_payload = if payloads > 0.0 {
        (last.events() + last.dead_letters()) / payloads
    } else {
        0.0
    };
    let backlog =
        |observed: &Observed<'_>| observed.lag("normalizer") * per_payload + observed.lag("writer");
    let half = load_seconds / 2.0;
    let late: Vec<(f64, f64)> = load
        .iter()
        .filter(|observed| observed.seconds() >= half && observed.seconds() > 0.0)
        .map(|observed| (observed.seconds(), backlog(observed)))
        .collect();
    let backlog_growth = slope(&late);
    let backlog_peak = late.iter().map(|&(_, backlog)| backlog).reduce(f64::max);

    #[allow(clippy::cast_precision_loss)]
    let rate = run.rate as f64;
    let verdict = match (backlog_growth, backlog_peak) {
        _ if offered_rate < rate * MIN_OFFERED => Verdict::NotOffered {
            offered: offered_rate,
        },
        (Some(growth), Some(peak)) => {
            if growth <= rate * MAX_GROWTH && peak <= rate * MAX_BACKLOG_SECONDS {
                Verdict::Sustained
            } else {
                Verdict::Unbounded {
                    growth,
                    backlog: peak,
                }
            }
        }
        _ => Verdict::Unmeasured(format!(
            "{} samples in the second half of the load window; at least 3 are needed",
            late.len()
        )),
    };

    let mut dead_letters = BTreeMap::new();
    if let Some(series) = last.metrics.get("goliath_dead_letters_total") {
        for (labels, count) in series {
            let key = format!(
                "{}/{}",
                labels.get("source").map_or("?", String::as_str),
                labels.get("stage").map_or("?", String::as_str)
            );
            *dead_letters.entry(key).or_insert(0.0) += count;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let complete = last.stored() >= last.sample.sent_records as f64
        && last.lag("normalizer") == 0.0
        && last.lag("writer") == 0.0;

    Ok(Computed {
        load_seconds,
        offered_rate,
        stored_rate,
        sent_records: last.sample.sent_records,
        sent_bytes: last.sample.sent_bytes,
        stored_outcomes: last.stored(),
        events: last.events(),
        dead_letters,
        complete,
        load_cpu_seconds,
        drain_cpu_seconds,
        cores_used,
        per_core,
        peak_memory: observed
            .iter()
            .map(|observed| observed.sample.memory_bytes)
            .max()
            .unwrap_or(0),
        latency_load: QUANTILES.map(|q| quantile(&load_latency, q)),
        latency_all: QUANTILES.map(|q| quantile(&all_latency, q)),
        backlog_growth,
        backlog_peak,
        verdict,
        storage,
    })
}

/// The least-squares slope of `points`, if there are at least three.
fn slope(points: &[(f64, f64)]) -> Option<f64> {
    if points.len() < 3 {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    let count = points.len() as f64;
    let mean_x = points.iter().map(|p| p.0).sum::<f64>() / count;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / count;
    let covariance: f64 = points.iter().map(|p| (p.0 - mean_x) * (p.1 - mean_y)).sum();
    let variance: f64 = points.iter().map(|p| (p.0 - mean_x).powi(2)).sum();
    (variance > 0.0).then(|| covariance / variance)
}

/// What the run's database holds, each query bounded in time.
async fn storage(clickhouse: &clickhouse::Client) -> Storage {
    let query = clickhouse
        .query(
            "SELECT sum(rows), sum(data_compressed_bytes), sum(data_uncompressed_bytes) \
             FROM system.parts \
             WHERE database = currentDatabase() AND table = 'events' AND active",
        )
        .with_setting("max_execution_time", "10")
        .fetch_one::<(u64, u64, u64)>();
    match tokio::time::timeout(Duration::from_secs(15), query).await {
        Ok(Ok((rows, compressed, uncompressed))) => Storage {
            rows: Ok(rows),
            compressed_bytes: Ok(compressed),
            uncompressed_bytes: Ok(uncompressed),
        },
        Ok(Err(error)) => Storage::unavailable(&format!("ClickHouse: {error}")),
        Err(_) => Storage::unavailable("ClickHouse did not answer within 15 seconds"),
    }
}

/// The machine the run was measured on, and the source it was built from.
fn machine() -> Value {
    let mut system = sysinfo::System::new();
    system.refresh_cpu_all();
    system.refresh_memory();
    let cpu = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_owned())
        .unwrap_or_default();
    let git = |arguments: &[&str]| {
        Command::new("git")
            .args(arguments)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    json!({
        "cpu": cpu,
        "physical_cores": sysinfo::System::physical_core_count(),
        "logical_cpus": system.cpus().len(),
        "memory_bytes": system.total_memory(),
        "os": sysinfo::System::long_os_version(),
        "kernel": sysinfo::System::kernel_version(),
        "commit": git(&["rev-parse", "HEAD"]),
        "dirty": git(&["status", "--porcelain"]).map(|status| !status.is_empty()),
    })
}

/// Metrics of the benchmark method no component built yet can produce, with
/// the milestone that brings each.
const NOT_YET: &[(&str, &str)] = &[
    (
        "Events/s per core at 100, 1,000, and 3,000 rules",
        "M5, the streaming detector",
    ),
    (
        "p50, p95, and p99 latency from ingestion to alert",
        "M5, the streaming detector",
    ),
    (
        "Precision and recall on the labelled set",
        "M3's attack injector and M5's detections",
    ),
    (
        "Memory per node at 10^6 and 10^8 indicators",
        "M4, threat intelligence",
    ),
];

fn seconds(value: Option<f64>) -> Value {
    match value {
        Some(value) if value.is_finite() => json!(value),
        Some(_) => json!("beyond the largest bucket"),
        None => Value::Null,
    }
}

fn measured(value: &Result<u64, String>) -> Value {
    match value {
        Ok(value) => json!(value),
        Err(reason) => json!({ "unavailable": reason }),
    }
}

fn document(run: &Run, computed: &Computed, machine: &Value) -> Value {
    let compression = match (&computed.storage.compressed_bytes, computed.sent_bytes) {
        (Ok(compressed), sent) if *compressed > 0 => {
            #[allow(clippy::cast_precision_loss)]
            let ratio = sent as f64 / *compressed as f64;
            json!(ratio)
        }
        (Ok(_), _) => json!({ "unavailable": "nothing compressed was stored" }),
        (Err(reason), _) => json!({ "unavailable": reason }),
    };
    json!({
        "run": {
            "profile": run.profile,
            "target_rate": run.rate,
            "load_seconds": run.duration.as_secs_f64(),
            "database": run.database,
            "goliath": run.goliath_version,
            "samples": run.samples.len(),
        },
        "machine": machine,
        "criteria": {
            "max_growth_share_of_rate_per_second": MAX_GROWTH,
            "max_backlog_seconds_of_rate": MAX_BACKLOG_SECONDS,
            "min_offered_share_of_rate": MIN_OFFERED,
        },
        "verdict": computed.verdict.to_string(),
        "throughput": {
            "offered_records_per_second": computed.offered_rate,
            "stored_outcomes_per_second": computed.stored_rate,
            "stored_outcomes_per_cpu_second": computed.per_core,
            "platform_cores_used": computed.cores_used,
            "platform_cpu_seconds_load": computed.load_cpu_seconds,
            "platform_cpu_seconds_drain": computed.drain_cpu_seconds,
            "platform_peak_memory_bytes": computed.peak_memory,
        },
        "backlog": {
            "growth_records_per_second": computed.backlog_growth,
            "peak_records": computed.backlog_peak,
        },
        "receipt_to_stored_seconds": {
            "load": { "p50": seconds(computed.latency_load[0]), "p95": seconds(computed.latency_load[1]), "p99": seconds(computed.latency_load[2]) },
            "whole_run": { "p50": seconds(computed.latency_all[0]), "p95": seconds(computed.latency_all[1]), "p99": seconds(computed.latency_all[2]) },
        },
        "totals": {
            "sent_records": computed.sent_records,
            "sent_bytes": computed.sent_bytes,
            "stored_outcomes": computed.stored_outcomes,
            "events": computed.events,
            "dead_letters": computed.dead_letters,
            "complete": computed.complete,
        },
        "storage": {
            "rows": measured(&computed.storage.rows),
            "compressed_bytes": measured(&computed.storage.compressed_bytes),
            "uncompressed_bytes": measured(&computed.storage.uncompressed_bytes),
            "compression_ratio_from_source_bytes": compression,
        },
        "not_measured": NOT_YET
            .iter()
            .map(|(metric, milestone)| json!({ "metric": metric, "needs": milestone }))
            .collect::<Vec<_>>(),
    })
}

fn format_seconds(value: Option<f64>) -> String {
    match value {
        Some(value) if value.is_finite() => format!("{:.0} ms", value * 1000.0),
        Some(_) => "beyond the largest bucket".to_owned(),
        None => "none observed".to_owned(),
    }
}

fn format_optional(value: Option<f64>, unit: &str) -> String {
    value.map_or_else(
        || "not measured".to_owned(),
        |value| format!("{value:.0} {unit}"),
    )
}

// A document written top to bottom.
#[allow(clippy::too_many_lines)]
fn markdown(run: &Run, computed: &Computed, machine: &Value) -> String {
    let text = |key: &str| machine[key].as_str().unwrap_or("unknown").to_owned();
    let mut out = String::new();
    let _ = writeln!(out, "# Benchmark report: {}\n", run.profile);
    let _ = writeln!(out, "**Verdict:** {}\n", computed.verdict);
    let _ = writeln!(
        out,
        "A rate is sustained when at least {:.0}% of it was offered and, over the second half \
         of the load window, the backlog grew by at most {:.0}% of it per second and never held \
         more than {:.0} seconds of it. The drain after the window never counts towards it.\n",
        MIN_OFFERED * 100.0,
        MAX_GROWTH * 100.0,
        MAX_BACKLOG_SECONDS
    );
    let _ = writeln!(out, "## Machine\n");
    let _ = writeln!(out, "| | |\n| --- | --- |");
    let _ = writeln!(out, "| CPU | {} |", text("cpu"));
    let _ = writeln!(
        out,
        "| Cores | {} physical, {} logical |",
        machine["physical_cores"], machine["logical_cpus"]
    );
    let _ = writeln!(
        out,
        "| Memory | {:.1} GiB |",
        machine["memory_bytes"].as_f64().unwrap_or(0.0) / f64::from(1_u32 << 30)
    );
    let _ = writeln!(out, "| OS | {} |", text("os"));
    let _ = writeln!(
        out,
        "| Commit | {}{} |",
        text("commit"),
        if machine["dirty"] == json!(true) {
            ", with changes"
        } else {
            ""
        }
    );
    let _ = writeln!(out, "| Platform | {} |\n", run.goliath_version);
    let _ = writeln!(out, "## Throughput\n");
    let _ = writeln!(out, "| Measure | Value |\n| --- | ---: |");
    let _ = writeln!(out, "| Target rate | {} records/s |", run.rate);
    let _ = writeln!(out, "| Load window | {:.0} s |", computed.load_seconds);
    let _ = writeln!(out, "| Offered | {:.0} records/s |", computed.offered_rate);
    let _ = writeln!(
        out,
        "| Stored during load | {:.0} outcomes/s |",
        computed.stored_rate
    );
    let _ = writeln!(
        out,
        "| Per second of platform CPU | {} |",
        format_optional(computed.per_core, "outcomes")
    );
    let _ = writeln!(
        out,
        "| Platform cores used | {} |",
        computed
            .cores_used
            .map_or_else(|| "not measured".to_owned(), |cores| format!("{cores:.2}"))
    );
    let _ = writeln!(
        out,
        "| Platform CPU, load and drain | {:.1} s and {:.1} s |",
        computed.load_cpu_seconds, computed.drain_cpu_seconds
    );
    #[allow(clippy::cast_precision_loss)]
    let memory = computed.peak_memory as f64 / f64::from(1_u32 << 20);
    let _ = writeln!(out, "| Platform peak memory | {memory:.0} MiB |");
    let _ = writeln!(
        out,
        "| Backlog growth, second half | {} |",
        format_optional(computed.backlog_growth, "records/s")
    );
    let _ = writeln!(
        out,
        "| Backlog peak, second half | {} |\n",
        format_optional(computed.backlog_peak, "records")
    );
    let _ = writeln!(
        out,
        "CPU and memory are the platform process's only: Kafka, ClickHouse, and the load \
         generator are not included, so this is not the whole machine's cost.\n"
    );
    let _ = writeln!(out, "## Receipt to stored\n");
    let _ = writeln!(out, "| | p50 | p95 | p99 |\n| --- | ---: | ---: | ---: |");
    for (name, values) in [
        ("Load window", &computed.latency_load),
        ("Whole run", &computed.latency_all),
    ] {
        let _ = writeln!(
            out,
            "| {name} | {} | {} | {} |",
            format_seconds(values[0]),
            format_seconds(values[1]),
            format_seconds(values[2])
        );
    }
    let _ = writeln!(out, "\n## Totals\n");
    let _ = writeln!(out, "| Measure | Value |\n| --- | ---: |");
    let _ = writeln!(out, "| Records sent | {} |", computed.sent_records);
    let _ = writeln!(out, "| Source bytes sent | {} |", computed.sent_bytes);
    let _ = writeln!(out, "| Outcomes stored | {:.0} |", computed.stored_outcomes);
    let _ = writeln!(out, "| Events | {:.0} |", computed.events);
    // An empty sum is negative zero, which would print as "-0".
    let dead: f64 = computed.dead_letters.values().sum::<f64>() + 0.0;
    let _ = writeln!(out, "| Dead letters | {dead:.0} |");
    let _ = writeln!(
        out,
        "| Caught up after the drain | {} |",
        if computed.complete { "yes" } else { "no" }
    );
    for (key, count) in &computed.dead_letters {
        let _ = writeln!(out, "| Dead letters, {key} | {count:.0} |");
    }
    let _ = writeln!(out, "\n## Storage\n");
    let _ = writeln!(out, "| Measure | Value |\n| --- | ---: |");
    let show = |value: &Result<u64, String>| match value {
        Ok(value) => value.to_string(),
        Err(reason) => format!("unavailable: {reason}"),
    };
    let _ = writeln!(
        out,
        "| Rows in `events` | {} |",
        show(&computed.storage.rows)
    );
    let _ = writeln!(
        out,
        "| Compressed bytes | {} |",
        show(&computed.storage.compressed_bytes)
    );
    let ratio = match &computed.storage.compressed_bytes {
        #[allow(clippy::cast_precision_loss)]
        Ok(compressed) if *compressed > 0 => {
            format!("{:.1}x", computed.sent_bytes as f64 / *compressed as f64)
        }
        Ok(_) => "unavailable: nothing compressed was stored".to_owned(),
        Err(reason) => format!("unavailable: {reason}"),
    };
    let _ = writeln!(out, "| Source bytes per stored byte | {ratio} |");
    let _ = writeln!(out, "\n## Not measured yet\n");
    let _ = writeln!(out, "| Metric | Needs |\n| --- | --- |");
    for (metric, milestone) in NOT_YET {
        let _ = writeln!(out, "| {metric} | {milestone} |");
    }
    out
}

#[cfg(test)]
// The values compared are whole numbers, exact in floating point.
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    const METRICS: &str = r#"# HELP goliath_outcomes What normalization made of records.
# TYPE goliath_outcomes counter
goliath_outcomes_total{source="sysmon",outcome="event"} 998
goliath_outcomes_total{source="sysmon",outcome="dead_letter"} 2
goliath_dead_letters_total{source="sysmon",stage="decoding"} 2
goliath_stored_outcomes_total 1000
goliath_normalized_records_total{source="sysmon"} 1
goliath_reader_lag_records{topic="raw-sysmon",reader="normalizer"} 0
goliath_reader_lag_records{topic="normalized",reader="writer"} 0
goliath_receipt_to_stored_seconds_bucket{le="0.5"} 10
goliath_receipt_to_stored_seconds_bucket{le="1.0"} 90
goliath_receipt_to_stored_seconds_bucket{le="+Inf"} 100
# EOF
"#;

    #[test]
    fn parses_names_labels_and_values() {
        let metrics = parse(METRICS);
        assert_eq!(total(&metrics, "goliath_outcomes_total", &[]), 1000.0);
        assert_eq!(
            total(&metrics, "goliath_outcomes_total", &[("outcome", "event")]),
            998.0
        );
        assert_eq!(
            total(&metrics, "goliath_stored_outcomes_total", &[]),
            1000.0
        );
        let labels = labels(r#"a="x\"y",b="z""#);
        assert_eq!(labels["a"], "x\"y");
        assert_eq!(labels["b"], "z");
    }

    #[test]
    fn quantiles_interpolate_within_their_bucket() {
        let buckets = buckets(&parse(METRICS), "goliath_receipt_to_stored_seconds");
        assert_eq!(buckets.len(), 3);
        // The median is the 50th of 100: 40 of the 80 between 0.5 and 1.0.
        assert!((quantile(&buckets, 0.5).unwrap() - 0.75).abs() < 1e-9);
        assert_eq!(quantile(&buckets, 0.99), Some(f64::INFINITY));
        assert_eq!(quantile(&[(1.0, 0.0)], 0.5), None);
    }

    fn sample(
        seconds: u64,
        sent: u64,
        stored: u64,
        raw_lag: u64,
        writer_lag: u64,
        cpu_ms: u64,
    ) -> Sample {
        Sample {
            elapsed: Duration::from_secs(seconds),
            metrics: format!(
                "goliath_stored_outcomes_total {stored}\n\
                 goliath_outcomes_total{{source=\"sysmon\",outcome=\"event\"}} {stored}\n\
                 goliath_normalized_records_total{{source=\"sysmon\"}} {}\n\
                 goliath_reader_lag_records{{topic=\"raw-sysmon\",reader=\"normalizer\"}} {raw_lag}\n\
                 goliath_reader_lag_records{{topic=\"normalized\",reader=\"writer\"}} {writer_lag}\n",
                (stored / 1000).max(1)
            ),
            cpu_ms,
            memory_bytes: 1 << 20,
            sent_records: sent,
            sent_bytes: sent * 700,
        }
    }

    fn run(samples: Vec<Sample>) -> Run {
        Run {
            profile: "ci".to_owned(),
            rate: 1_000,
            duration: Duration::from_secs(60),
            samples,
            ..Run::default()
        }
    }

    fn unavailable() -> Storage {
        Storage::unavailable("not queried in tests")
    }

    #[test]
    fn a_rate_kept_up_with_is_sustained() {
        let samples = (0..=12)
            .map(|tick| {
                let seconds = tick * 5;
                sample(
                    seconds,
                    seconds * 1_000,
                    seconds * 1_000,
                    0,
                    200,
                    seconds * 400,
                )
            })
            .collect();
        let computed = compute(&run(samples), unavailable()).unwrap();
        assert_eq!(computed.verdict, Verdict::Sustained);
        assert!((computed.offered_rate - 1_000.0).abs() < 1e-9);
        assert!((computed.stored_rate - 1_000.0).abs() < 1e-9);
        // 60,000 outcomes in 24 CPU seconds.
        assert!((computed.per_core.unwrap() - 2_500.0).abs() < 1e-9);
    }

    #[test]
    fn a_growing_backlog_is_not_sustained_whatever_the_drain() {
        let mut samples: Vec<Sample> = (0..=12)
            .map(|tick| {
                let seconds = tick * 5;
                // Stores 700 of every 1,000 offered; the rest waits in raw.
                let stored = seconds * 700;
                sample(
                    seconds,
                    seconds * 1_000,
                    stored,
                    (seconds * 300) / 1_000,
                    0,
                    seconds * 900,
                )
            })
            .collect();
        // The drain catches up completely afterwards.
        samples.push(sample(120, 60_000, 60_000, 0, 0, 100_000));
        let computed = compute(&run(samples), unavailable()).unwrap();
        assert!(
            matches!(computed.verdict, Verdict::Unbounded { growth, .. } if growth > 100.0),
            "{:?}",
            computed.verdict
        );
        assert!(computed.complete);
        assert!((computed.stored_rate - 700.0).abs() < 1e-9);
    }

    #[test]
    fn a_rate_the_driver_could_not_offer_is_not_judged_on_the_platform() {
        let samples = (0..=12)
            .map(|tick| {
                let seconds = tick * 5;
                sample(seconds, seconds * 500, seconds * 500, 0, 0, seconds * 100)
            })
            .collect();
        let computed = compute(&run(samples), unavailable()).unwrap();
        assert!(matches!(computed.verdict, Verdict::NotOffered { .. }));
    }

    #[test]
    fn too_few_samples_are_not_judged() {
        let samples = vec![
            sample(0, 0, 0, 0, 0, 0),
            sample(60, 60_000, 60_000, 0, 0, 1_000),
        ];
        let computed = compute(&run(samples), unavailable()).unwrap();
        assert!(matches!(computed.verdict, Verdict::Unmeasured(_)));
        assert!(compute(&run(Vec::new()), unavailable()).is_err());
    }

    #[test]
    fn the_report_names_what_it_could_not_measure() {
        let samples = (0..=12)
            .map(|tick| sample(tick * 5, tick * 5_000, tick * 5_000, 0, 0, tick * 2_000))
            .collect();
        let run = run(samples);
        let computed = compute(&run, unavailable()).unwrap();
        let machine = json!({ "cpu": "test", "commit": "abc" });
        let document = document(&run, &computed, &machine);
        assert_eq!(document["verdict"], "sustained");
        assert_eq!(
            document["storage"]["rows"]["unavailable"],
            "not queried in tests"
        );
        assert_eq!(
            document["not_measured"].as_array().unwrap().len(),
            NOT_YET.len()
        );
        let text = markdown(&run, &computed, &machine);
        assert!(text.contains("**Verdict:** sustained"));
        assert!(text.contains("unavailable: not queried in tests"));
        assert!(text.contains("M5, the streaming detector"));
    }
}
