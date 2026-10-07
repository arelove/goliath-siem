//! Measures the detector against the budgets of
//! `docs/adr/0021-enrichment-placement.md`.
//!
//! ```text
//! cargo build --release -p goliath
//! cargo run --release -p goliath-bench --features intel --bin intel -- \
//!     --indicators 1000000 --events 2000000
//! ```
//!
//! It writes feeds of generated indicators, fills the event topic beforehand
//! with normalized events of which a share hold one, and then starts
//! `goliath` with the detector role alone, so that neither generating nor
//! normalizing takes a core from what is measured. It reads the platform's
//! own metrics once a second, and afterwards the findings, and reports the
//! rate, what was found against what was planted, memory, and disk. How to
//! run it and how to read the report is in `docs/benchmark-rig.md`.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufWriter, Write as _};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use goliath_gen::{Generator, Options, Organization, intel};
use goliath_normalize::{BUILTIN, Envelope, Normalizer, Outcome};
use goliath_pipe::{DiskOptions, DiskTopic, Receiver, Sender};
use serde_json::{Value, json};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

type Failure = Box<dyn std::error::Error + Send + Sync>;

const METRICS: &str = "127.0.0.1:9466";
/// The simulated time of the first event: a Monday morning, when the
/// organization is at work.
const START: i64 = 1_790_000_000_000 + 4 * 86_400_000 + 9 * 3_600_000;
/// Of the planted events, one in this many holds an allowlisted indicator.
const ALLOWED_EVERY: u64 = 50;
/// The allowlist names every indicator at a multiple of this, below
/// [`ALLOWED_BELOW`]: addresses, which every such index is.
const ALLOWED_STEP: u64 = 200;
const ALLOWED_BELOW: u64 = 20_000;
/// A run in which the detector does nothing for this long has failed.
const STALLED: Duration = Duration::from_secs(180);

/// The budgets of ADR-0021 that one run can be held to.
const MEMORY_BUDGET: u64 = 2 << 30;
const DISK_BUDGET: u64 = 8 << 30;
const RATE_BUDGET: f64 = 0.9;

struct Settings {
    indicators: u64,
    events: u64,
    planted: f64,
    threads: usize,
    feed_size: u64,
    out: PathBuf,
    binary: PathBuf,
    baseline: Option<PathBuf>,
}

impl Settings {
    fn read() -> Result<Self, Failure> {
        let mut settings = Self {
            indicators: 1_000,
            events: 500_000,
            planted: 0.01,
            threads: 1,
            feed_size: 10_000_000,
            out: PathBuf::from(format!("bench/out/intel{}", unix_seconds())),
            binary: std::env::var_os("GOLIATH_BIN").map_or_else(
                || {
                    PathBuf::from(if cfg!(windows) {
                        "target/release/goliath.exe"
                    } else {
                        "target/release/goliath"
                    })
                },
                PathBuf::from,
            ),
            baseline: None,
        };
        let mut arguments = std::env::args().skip(1);
        while let Some(name) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| format!("{name} needs a value"))?;
            match name.as_str() {
                "--indicators" => settings.indicators = value.parse()?,
                "--events" => settings.events = value.parse()?,
                "--planted" => settings.planted = value.parse()?,
                "--threads" => settings.threads = value.parse()?,
                "--feed-size" => settings.feed_size = value.parse()?,
                "--out" => settings.out = PathBuf::from(value),
                "--baseline" => settings.baseline = Some(PathBuf::from(value)),
                other => return Err(format!("unknown argument {other}").into()),
            }
        }
        if settings.indicators < 20 || settings.events == 0 || settings.feed_size == 0 {
            return Err("at least 20 indicators, one event, and one indicator a feed".into());
        }
        if !(0.0..=0.5).contains(&settings.planted) {
            return Err("--planted is a share of the events, at most 0.5".into());
        }
        Ok(settings)
    }

    /// One planted event in this many.
    fn period(&self) -> u64 {
        if self.planted == 0.0 {
            u64::MAX
        } else {
            (1.0 / self.planted).round().max(2.0) as u64
        }
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The indicator the `plant`th planted event holds. One in
/// [`ALLOWED_EVERY`] is on the allowlist; the others are spread over the
/// whole set, and none of them is on it.
fn planted_indicator(plant: u64, indicators: u64) -> u64 {
    let allowed = indicators.min(ALLOWED_BELOW).div_ceil(ALLOWED_STEP);
    if plant.is_multiple_of(ALLOWED_EVERY) {
        return ALLOWED_STEP * ((plant / ALLOWED_EVERY) % allowed);
    }
    let mut index = (plant.wrapping_mul(7_919) + 1) % indicators;
    while is_allowed(index, indicators) {
        index = (index + 1) % indicators;
    }
    index
}

fn is_allowed(index: u64, indicators: u64) -> bool {
    index < indicators.min(ALLOWED_BELOW) && index.is_multiple_of(ALLOWED_STEP)
}

/// A path as TOML and YAML take it on every system.
fn written(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Writes the feeds and the allowlist, and returns the configuration of the
/// detector that reads them.
fn prepare(settings: &Settings) -> Result<String, Failure> {
    let feeds = settings.out.join("feeds");
    fs::create_dir_all(&feeds)?;
    let mut config = format!(
        "roles = [\"detector\"]\ndata = \"{}\"\n\n[metrics]\nlisten = \"{METRICS}\"\n\n\
         [detector]\nthreads = {}\nlook_back_days = 0\nallowlists = [\"{}\"]\n",
        written(&settings.out.join("data")),
        settings.threads,
        written(&settings.out.join("allow.yaml")),
    );
    let mut from = 0;
    let mut number = 0;
    while from < settings.indicators {
        let until = settings.indicators.min(from + settings.feed_size);
        let name = format!("generated-{number:02}");
        fs::write(
            feeds.join(format!("{name}.yaml")),
            intel::feed_definition(&name),
        )?;
        let mut publication = BufWriter::new(File::create(feeds.join(format!("{name}.csv")))?);
        intel::write_feed(&mut publication, from..until)?;
        publication.flush()?;
        let _ = write!(
            config,
            "\n[[detector.feeds]]\ndefinition = \"{}\"\nfile = \"{}\"\n",
            written(&feeds.join(format!("{name}.yaml"))),
            written(&feeds.join(format!("{name}.csv"))),
        );
        from = until;
        number += 1;
    }
    let mut allow = String::from("name: bench\nversion: 1\nentries:\n");
    for index in (0..settings.indicators.min(ALLOWED_BELOW)).step_by(ALLOWED_STEP as usize) {
        let (_, value) = intel::indicator(index);
        let _ = writeln!(
            allow,
            "  - {{ kind: ip, value: {value}, reason: Planted to be suppressed }}"
        );
    }
    fs::write(settings.out.join("allow.yaml"), allow)?;
    Ok(config)
}

/// What was put in the topic.
#[derive(Default)]
struct Filled {
    events: u64,
    /// How many planted events hold each indicator, by `kind value`, and
    /// whether it is on the allowlist.
    planted: BTreeMap<String, (u64, bool)>,
}

/// Fills the event topic with normalized events, a share of them planted,
/// before any detector runs.
async fn fill(settings: &Settings) -> Result<Filled, Failure> {
    // No bound: nothing reads while it is filled.
    let options = DiskOptions {
        capacity: NonZeroU64::MAX,
        ..DiskOptions::default()
    };
    let topic = DiskTopic::open(settings.out.join("data/normalized"), options)?;
    // Both readers are placed at the start. A group that first subscribes
    // to a topic that holds records starts after them; and the writer's
    // place, which never moves here, keeps every record for the detector.
    drop(topic.subscribe("writer")?);
    drop(topic.observe("detector")?);
    let sender = topic.sender();

    let normalizers: BTreeMap<&str, Normalizer> = BUILTIN
        .iter()
        .filter(|(name, _)| ["sysmon", "entra", "suricata"].contains(name))
        .map(|(name, definition)| Ok((*name, Normalizer::from_yaml(definition)?)))
        .collect::<Result<_, Failure>>()?;
    let organization = Organization::generate(&Options::default());
    let mut generator = Generator::new(&organization, 1);
    let period = settings.period();
    let mut filled = Filled::default();
    let mut batch = Vec::with_capacity(1024);
    let mut plants = 0;
    for record in 0..settings.events {
        // A hundred events a simulated second.
        let time = START + i64::try_from(record)? * 10;
        let raw = if record % period == period / 2 {
            let index = planted_indicator(plants, settings.indicators);
            plants += 1;
            let (kind, value) = intel::indicator(index);
            let entry = filled
                .planted
                .entry(format!("{} {value}", kind.name()))
                .or_insert((0, is_allowed(index, settings.indicators)));
            entry.0 += 1;
            generator.planted(time, index)
        } else {
            generator.next(time)
        };
        let normalizer = normalizers
            .get(raw.source)
            .ok_or_else(|| format!("no definition for {}", raw.source))?;
        let mut failed = None;
        normalizer.normalize(&raw.bytes, |outcome| {
            if !matches!(outcome, Outcome::Event(_)) {
                failed = Some(format!("{outcome:?}"));
            }
            filled.events += 1;
            batch.push(
                Envelope::new(normalizer.name(), normalizer.version(), outcome)
                    .received_at(time)
                    .encode(),
            );
        });
        if let Some(failed) = failed {
            return Err(format!("a generated record did not normalize: {failed}").into());
        }
        if batch.len() >= 1024 {
            sender.send(std::mem::take(&mut batch)).await?;
        }
    }
    if !batch.is_empty() {
        sender.send(batch).await?;
    }
    Ok(filled)
}

/// The platform, killed when the run ends however it ends.
struct Platform(Child);

impl Drop for Platform {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The platform's metrics, as text.
fn metrics() -> Result<String, Failure> {
    use std::io::Read as _;
    let mut stream = std::net::TcpStream::connect(METRICS)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET /metrics HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    let (_, body) = text
        .split_once("\r\n\r\n")
        .ok_or("the metrics endpoint did not answer in HTTP")?;
    Ok(body.to_owned())
}

/// The sum of the samples of `name` whose labels hold all of `labels`.
fn metric(text: &str, name: &str, labels: &[&str]) -> Option<f64> {
    let mut sum = None;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(name) else {
            continue;
        };
        if !(rest.starts_with('{') || rest.starts_with(' ')) {
            continue;
        }
        if labels.iter().all(|label| rest.contains(label))
            && let Some(value) = rest
                .split_whitespace()
                .last()
                .and_then(|v| v.parse::<f64>().ok())
        {
            *sum.get_or_insert(0.0) += value;
        }
    }
    sum
}

/// One look at the running detector.
struct Sample {
    at: Duration,
    detected: u64,
    cpu_ms: u64,
    memory: u64,
}

/// What the detector did, as its metrics said.
struct Observed {
    samples: Vec<Sample>,
    /// From the start to every feed being in the store.
    loaded_after: Duration,
    reported: u64,
    suppressed: u64,
    skipped: u64,
}

fn observe(platform: &mut Platform, feeds: u64, events: u64) -> Result<Observed, Failure> {
    let pid = Pid::from_u32(platform.0.id());
    let mut system = System::new();
    let start = Instant::now();
    let mut observed = Observed {
        samples: Vec::new(),
        loaded_after: Duration::ZERO,
        reported: 0,
        suppressed: 0,
        skipped: 0,
    };
    let mut progress = (0, Instant::now());
    loop {
        std::thread::sleep(Duration::from_secs(1));
        if let Some(status) = platform.0.try_wait()? {
            return Err(format!("goliath stopped: {status}; see platform.log").into());
        }
        // Not listening yet while the store opens.
        let Ok(text) = metrics() else {
            if start.elapsed() > STALLED && observed.samples.is_empty() {
                return Err("goliath never served its metrics; see platform.log".into());
            }
            continue;
        };
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        let process = system.process(pid).ok_or("goliath disappeared")?;
        let count = |name: &str, labels: &[&str]| metric(&text, name, labels).unwrap_or(0.0) as u64;
        let detected = count("goliath_detected_events_total", &[]);
        let in_store = count("goliath_feed_refreshes_total", &["result=\"loaded\""])
            + count("goliath_feed_refreshes_total", &["result=\"unchanged\""]);
        if observed.loaded_after.is_zero() && in_store >= feeds {
            observed.loaded_after = start.elapsed();
        }
        observed.samples.push(Sample {
            at: start.elapsed(),
            detected,
            cpu_ms: process.accumulated_cpu_time(),
            memory: process.memory(),
        });
        observed.reported = count("goliath_indicator_hits_total", &["status=\"reported\""]);
        observed.suppressed = count("goliath_indicator_hits_total", &["status=\"suppressed\""]);
        observed.skipped = count("goliath_detector_skipped_records_total", &[]);
        if detected != progress.0 {
            progress = (detected, Instant::now());
        }
        let lag = metric(
            &text,
            "goliath_reader_lag_records",
            &["topic=\"normalized\"", "reader=\"detector\""],
        );
        if detected >= events && lag == Some(0.0) {
            return Ok(observed);
        }
        if progress.1.elapsed() > STALLED {
            return Err(format!(
                "the detector matched {detected} of {events} events and then nothing for {} s",
                STALLED.as_secs()
            )
            .into());
        }
    }
}

/// The findings the detector sent, by `kind value`: how many were reported
/// and how many suppressed.
async fn findings(out: &Path) -> Result<BTreeMap<String, (u64, u64)>, Failure> {
    let options = DiskOptions {
        capacity: NonZeroU64::MAX,
        ..DiskOptions::default()
    };
    let topic = DiskTopic::open(out.join("data/findings"), options)?;
    let mut receiver = topic.subscribe("writer")?;
    let mut found: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    loop {
        let deliveries = receiver.receive(4096, Duration::from_millis(200)).await?;
        if deliveries.is_empty() {
            return Ok(found);
        }
        for delivery in &deliveries {
            let Outcome::Event(finding) = Envelope::decode(&delivery.payload)?.outcome else {
                return Err("the findings topic holds what is not a finding".into());
            };
            let title = finding.event["finding_info"]["title"]
                .as_str()
                .unwrap_or_default();
            let indicator = title.strip_prefix("Indicator match: ").unwrap_or(title);
            let entry = found.entry(indicator.to_owned()).or_default();
            if finding.event["is_alert"] == json!(true) {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
    }
}

fn directory_bytes(directory: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(directory) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.metadata() {
            Ok(metadata) if metadata.is_dir() => directory_bytes(&entry.path()),
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        })
        .sum()
}

fn median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

/// The report: what was measured, and each budget it can be held to.
#[allow(clippy::too_many_lines)] // One measure after another, each a few lines.
fn report(
    settings: &Settings,
    filled: &Filled,
    observed: &Observed,
    found: &BTreeMap<String, (u64, u64)>,
) -> Result<Value, Failure> {
    // The samples from the first event matched to the last.
    let matching: Vec<&Sample> = observed
        .samples
        .iter()
        .skip_while(|sample| sample.detected == 0)
        .collect();
    let before = observed
        .samples
        .iter()
        .rev()
        .find(|sample| sample.detected == 0);
    let first = before.or(matching.first().copied());
    let last = matching.last().copied();
    let (wall, cpu) = match (first, last) {
        (Some(first), Some(last)) if last.at > first.at => {
            let events = (last.detected - first.detected) as f64;
            let cpu_seconds = (last.cpu_ms.saturating_sub(first.cpu_ms)) as f64 / 1000.0;
            (
                events / last.at.saturating_sub(first.at).as_secs_f64(),
                if cpu_seconds > 0.0 {
                    events / cpu_seconds
                } else {
                    0.0
                },
            )
        }
        _ => (0.0, 0.0),
    };
    // Each second's rate; the last second is cut short by the end.
    let seconds: Vec<f64> = matching
        .windows(2)
        .map(|pair| {
            (pair[1].detected - pair[0].detected) as f64
                / pair[1].at.saturating_sub(pair[0].at).as_secs_f64()
        })
        .collect();
    let steady = median(seconds[..seconds.len().saturating_sub(1)].to_vec());
    let first_minute = matching.first().map_or(0.0, |start| {
        let minute: Vec<&&Sample> = matching
            .iter()
            .take_while(|sample| sample.at.saturating_sub(start.at) <= Duration::from_secs(60))
            .collect();
        match (minute.first(), minute.last()) {
            (Some(a), Some(b)) if b.at > a.at => {
                (b.detected - a.detected) as f64 / b.at.saturating_sub(a.at).as_secs_f64()
            }
            _ => 0.0,
        }
    });

    // Every planted match found, and no finding beyond them.
    let mut wrong = Vec::new();
    for (indicator, (count, allowed)) in &filled.planted {
        let expected = if *allowed { (0, *count) } else { (*count, 0) };
        let got = found.get(indicator).copied().unwrap_or_default();
        if got != expected && wrong.len() < 10 {
            wrong.push(format!(
                "{indicator}: reported {} and suppressed {}, planted {} and {}",
                got.0, got.1, expected.0, expected.1
            ));
        }
    }
    for indicator in found.keys() {
        if !filled.planted.contains_key(indicator) && wrong.len() < 10 {
            wrong.push(format!("{indicator}: found, and never planted"));
        }
    }
    let planted: u64 = filled.planted.values().map(|(count, _)| count).sum();
    let correct = wrong.is_empty() && observed.skipped == 0;

    let memory = observed
        .samples
        .iter()
        .map(|sample| sample.memory)
        .max()
        .unwrap_or(0);
    let disk = directory_bytes(&settings.out.join("data/intel"));
    let baseline = match &settings.baseline {
        Some(path) => {
            let baseline: Value = serde_json::from_slice(&fs::read(path)?)?;
            baseline["events_per_cpu_second"].as_f64()
        }
        None => None,
    };
    let mut budgets = vec![
        json!({ "measure": "correctness", "passed": correct,
                "detail": if correct { format!("{planted} planted matches found, and no other") } else { wrong.join("; ") } }),
        json!({ "measure": "memory", "passed": memory <= MEMORY_BUDGET,
                "detail": format!("{:.2} GiB resident at most, budget 2 GiB at 10^8 indicators", memory as f64 / f64::from(1 << 30)) }),
        json!({ "measure": "disk", "passed": disk <= DISK_BUDGET,
                "detail": format!("{:.2} GiB, budget 8 GiB at 10^8 indicators", disk as f64 / f64::from(1 << 30)) }),
    ];
    if let Some(baseline) = baseline.filter(|baseline| *baseline > 0.0) {
        let share = cpu / baseline;
        budgets.push(json!({ "measure": "rate", "passed": share >= RATE_BUDGET,
            "detail": format!("{:.1}% of the baseline's events a CPU second, budget 90%", share * 100.0) }));
    }
    Ok(json!({
        "indicators": settings.indicators,
        "events": filled.events,
        "planted_events": planted,
        "threads": settings.threads,
        "feeds_in_store_after_seconds": observed.loaded_after.as_secs_f64(),
        "events_per_second": wall,
        "events_per_second_median": steady,
        "events_per_cpu_second": cpu,
        "events_per_second_first_minute": first_minute,
        "reported": observed.reported,
        "suppressed": observed.suppressed,
        "skipped": observed.skipped,
        "memory_bytes": memory,
        "disk_bytes": disk,
        "budgets": budgets,
    }))
}

async fn run() -> Result<bool, Failure> {
    let mut settings = Settings::read()?;
    // The platform reads the paths of its configuration from where that
    // file is, so the ones written there are whole.
    settings.out = std::path::absolute(&settings.out)?;
    if !settings.binary.exists() {
        return Err(format!(
            "{} is not there; build it with `cargo build --release -p goliath`, or set GOLIATH_BIN",
            settings.binary.display()
        )
        .into());
    }
    if let Some(parent) = settings.out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&settings.out)?; // Never an earlier run's directory.
    println!("report directory: {}", settings.out.display());

    let started = Instant::now();
    let config = prepare(&settings)?;
    let path = settings.out.join("goliath.toml");
    fs::write(&path, config)?;
    println!(
        "{} indicators written in {:.1} s",
        settings.indicators,
        started.elapsed().as_secs_f64()
    );

    let started = Instant::now();
    let filled = fill(&settings).await?;
    println!(
        "{} events in the topic, {} of them planted, in {:.1} s",
        filled.events,
        filled.planted.values().map(|(count, _)| count).sum::<u64>(),
        started.elapsed().as_secs_f64()
    );

    let log = File::create(settings.out.join("platform.log"))?;
    let mut platform = Platform(
        Command::new(&settings.binary)
            .args(["run", "--config"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    );
    let feeds = settings.indicators.div_ceil(settings.feed_size);
    let observed = observe(&mut platform, feeds, filled.events)?;
    drop(platform);

    let found = findings(&settings.out).await?;
    let report = report(&settings, &filled, &observed, &found)?;
    fs::write(
        settings.out.join("report.json"),
        serde_json::to_string_pretty(&report)?,
    )?;

    println!();
    println!(
        "feeds in the store after     {:>12.1} s",
        report["feeds_in_store_after_seconds"]
            .as_f64()
            .unwrap_or(0.0)
    );
    for (label, key) in [
        ("events a second             ", "events_per_second"),
        ("events a second, median     ", "events_per_second_median"),
        ("events a CPU second         ", "events_per_cpu_second"),
        (
            "events a second, first min. ",
            "events_per_second_first_minute",
        ),
    ] {
        println!("{label} {:>12.0}", report[key].as_f64().unwrap_or(0.0));
    }
    let mut passed = true;
    for budget in report["budgets"].as_array().into_iter().flatten() {
        let ok = budget["passed"] == json!(true);
        passed &= ok;
        println!(
            "{:<5} {:<12} {}",
            if ok { "pass" } else { "FAIL" },
            budget["measure"].as_str().unwrap_or_default(),
            budget["detail"].as_str().unwrap_or_default()
        );
    }
    println!("report: {}", settings.out.join("report.json").display());
    Ok(passed)
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("intel: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("intel: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planted_indicators_are_spread_and_one_in_fifty_is_allowed() {
        for indicators in [1_000, 1_000_000] {
            let mut allowed = 0;
            for plant in 0..5_000 {
                let index = planted_indicator(plant, indicators);
                assert!(index < indicators);
                let on_list = is_allowed(index, indicators);
                assert_eq!(
                    on_list,
                    plant % ALLOWED_EVERY == 0,
                    "{plant} of {indicators}"
                );
                allowed += u64::from(on_list);
                if on_list {
                    assert_eq!(intel::indicator(index).0, intel::IndicatorKind::Ip);
                }
            }
            assert_eq!(allowed, 100);
        }
    }

    #[test]
    fn a_metric_is_summed_over_the_samples_its_labels_select() {
        let text = "goliath_feed_refreshes_total{feed=\"a\",result=\"loaded\"} 1\n\
                    goliath_feed_refreshes_total{feed=\"b\",result=\"loaded\"} 2\n\
                    goliath_feed_refreshes_total{feed=\"b\",result=\"refused\"} 4\n\
                    goliath_detected_events_total 7\n\
                    goliath_detected_events_total_other 9\n";
        assert_eq!(
            metric(text, "goliath_feed_refreshes_total", &["result=\"loaded\""]),
            Some(3.0)
        );
        assert_eq!(
            metric(text, "goliath_detected_events_total", &[]),
            Some(7.0)
        );
        assert_eq!(metric(text, "goliath_missing", &[]), None);
    }
}
