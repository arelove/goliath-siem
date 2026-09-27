//! Drives an isolated platform over Kafka and passes observations to report.
//!
//! See `docs/benchmark-rig.md` for prerequisites and reproduction.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use goliath_bench::{
    Fleet,
    report::{self, Run, Sample},
};
use goliath_pipe::{KafkaOptions, KafkaSender, KafkaTopic, Sender};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, interval_at, sleep, sleep_until, timeout};

type Failure = Box<dyn Error + Send + Sync>;
const BATCH: u64 = 1_000;
const SAMPLE_EVERY: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const METRICS: &str = "127.0.0.1:9465";
const SEED: u64 = 42;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Ci,
    Laptop,
}

impl Profile {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        match args {
            [flag, name] if flag == "--profile" => match name.as_str() {
                "ci" => Ok(Self::Ci),
                "laptop" => Ok(Self::Laptop),
                _ => Err("profile must be ci or laptop".into()),
            },
            _ => Err("usage: rig --profile ci|laptop".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Ci => "ci",
            Self::Laptop => "laptop",
        }
    }
    fn rate(self) -> u64 {
        match self {
            Self::Ci => 5_000,
            Self::Laptop => 100_000,
        }
    }
    fn duration(self) -> Duration {
        Duration::from_secs(match self {
            Self::Ci => 60,
            Self::Laptop => 1_800,
        })
    }
}

struct Settings {
    profile: Profile,
    url: String,
    user: String,
    brokers: String,
    binary: PathBuf,
    out: PathBuf,
    database: String,
    prefix: String,
}

impl Settings {
    fn read() -> Result<Self, Failure> {
        let profile = Profile::parse(&env::args().skip(1).collect::<Vec<_>>())?;
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(Self {
            profile,
            url: env::var("GOLIATH_CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8123".to_owned()),
            user: env::var("GOLIATH_CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_owned()),
            brokers: env::var("GOLIATH_KAFKA_BROKERS")
                .unwrap_or_else(|_| "127.0.0.1:9092".to_owned()),
            binary: env::var_os("GOLIATH_BIN").map_or_else(
                || {
                    PathBuf::from(if cfg!(windows) {
                        "target/release/goliath.exe"
                    } else {
                        "target/release/goliath"
                    })
                },
                PathBuf::from,
            ),
            out: PathBuf::from(format!("bench/out/rig{epoch}")),
            database: format!("goliath_rig_{epoch}"),
            prefix: format!("rig{epoch}-"),
        })
    }

    fn config(&self) -> String {
        // JSON string escaping is also valid for these TOML basic strings.
        let quote = |s: &str| serde_json::Value::String(s.to_owned()).to_string();
        format!(
            "roles = [\"normalizer\", \"writer\"]\n\
            [kafka]\nbrokers = {}\nprefix = {}\nreplication = 1\n\
            [[sources]]\ndefinition = \"sysmon\"\n\
            [store]\nurl = {}\ndatabase = {}\nuser = {}\npassword_env = \"GOLIATH_CLICKHOUSE_PASSWORD\"\n\
            [metrics]\nlisten = \"{METRICS}\"\n",
            quote(&self.brokers),
            quote(&self.prefix),
            quote(&self.url),
            quote(&self.database),
            quote(&self.user)
        )
    }
}

/// Reaps the child on errors as well as on the normal path.
struct Platform(Child);
impl Platform {
    fn check(&mut self) -> Result<(), Failure> {
        if let Some(status) = self.0.try_wait()? {
            return Err(format!("platform exited: {status}; see platform.log").into());
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Failure> {
        if self.0.try_wait()?.is_none() {
            self.0.kill()?;
        }
        self.0.wait()?;
        Ok(())
    }
}
impl Drop for Platform {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Clone, Copy, Default)]
struct Counts {
    records: u64,
    bytes: u64,
}

fn counts(shared: &Mutex<Counts>) -> Result<Counts, Failure> {
    Ok(*shared.lock().map_err(|_| "sender counters poisoned")?)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rig: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)] // Keep ownership and cleanup of the child and workers together.
async fn run() -> Result<(), Failure> {
    let settings = Settings::read()?;
    // Refuse to scrape an unrelated process that already owns this port.
    let probe = std::net::TcpListener::bind(METRICS)?;
    let version = Command::new(&settings.binary).arg("--version").output()?;
    if !version.status.success() {
        return Err("goliath --version failed".into());
    }
    fs::create_dir_all("bench/out")?;
    fs::create_dir(&settings.out)?; // Never reuse an earlier run's namespace.
    let config = settings.out.join("goliath.toml");
    fs::write(&config, settings.config())?;
    goliath::Config::load(&config)?;
    let log = File::create(settings.out.join("platform.log"))?;
    drop(probe);
    let mut platform = Platform(
        Command::new(&settings.binary)
            .args(["run", "--config"])
            .arg(&config)
            .env(
                "GOLIATH_CLICKHOUSE_PASSWORD",
                env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default(),
            )
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    );
    println!("report directory: {}", settings.out.display());
    tokio::select! {
        result = ready(&mut platform) => result?,
        result = tokio::signal::ctrl_c() => { result?; return Err("interrupted during startup".into()); }
    }
    let mut options = KafkaOptions::new(&settings.brokers);
    options
        .readers
        .insert(format!("{}normalizer", settings.prefix));
    options.replication = 1;
    let topic = timeout(
        Duration::from_secs(60),
        KafkaTopic::open(&format!("{}raw-sysmon", settings.prefix), options),
    )
    .await??;
    let workers = std::thread::available_parallelism()?.get().clamp(2, 8);
    write_manifest(&settings.out, workers)?;
    let mut run = Run {
        profile: settings.profile.name().to_owned(),
        rate: settings.profile.rate(),
        duration: settings.profile.duration(),
        database: settings.database.clone(),
        goliath_version: String::from_utf8(version.stdout)?.trim().to_owned(),
        samples: Vec::new(),
    };
    let mut system = System::new();
    let counters = Arc::new(Mutex::new(Counts::default()));
    let mut baseline = sample(&mut system, &mut platform, Instant::now(), &counters).await?;
    baseline.elapsed = Duration::ZERO;
    run.samples.push(baseline);
    let start = Instant::now();
    let (stop, stopped) = watch::channel(false);
    let mut jobs = JoinSet::new();
    for worker in 0..workers {
        let sender = topic.sender();
        let shared = counters.clone();
        let stopped = stopped.clone();
        let profile = settings.profile;
        // Each blocking task owns a Fleet and runs on a separate worker thread.
        jobs.spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(produce(
                sender, shared, stopped, start, profile, worker, workers,
            ))
        });
    }
    let measured = tokio::select! {
        result = observe(&mut run, &mut jobs, &mut system, &mut platform, start, &counters) => result,
        result = tokio::signal::ctrl_c() => result.map_err(Failure::from).and(Err("interrupted during load".into())),
    };
    let _ = stop.send(true);
    let mut result = measured;
    // In-flight sends either acknowledge and count, or fail within SEND_TIMEOUT.
    // Never drop an unobserved send and then claim all accepted records drained.
    while let Some(done) = jobs.join_next().await {
        if let Err(error) = done.map_err(Failure::from).and_then(std::convert::identity)
            && result.is_ok()
        {
            result = Err(error);
        }
    }
    if result.is_ok() {
        result = tokio::select! {
            result = drain(&mut run, &mut system, &mut platform, start, &counters) => result,
            signal = tokio::signal::ctrl_c() => signal.map_err(Failure::from).and(Err("interrupted during drain".into())),
        };
    }
    // Keep the last available observation even when the run failed.
    match sample(&mut system, &mut platform, start, &counters).await {
        Ok(last) => run.samples.push(last),
        Err(error) if result.is_ok() => result = Err(error),
        Err(_) => {}
    }
    if let Err(error) = platform.stop()
        && result.is_ok()
    {
        result = Err(error);
    }
    persist_samples(&run, &settings.out)?;
    if let Err(error) = &result {
        fs::write(settings.out.join("failure.txt"), error.to_string())?;
    }
    let clickhouse = clickhouse::Client::default()
        .with_url(&settings.url)
        .with_user(&settings.user)
        .with_password(env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default())
        .with_database(&settings.database);
    report::write(&run, &clickhouse, &settings.out).await?;
    result
}

async fn ready(platform: &mut Platform) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        platform.check()?;
        if let Ok(text) = metrics().await {
            // A HELP/TYPE declaration, or only the writer, is not readiness.
            if readers_ready(&text) {
                platform.check()?;
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("readers not ready within 120 seconds; see platform.log".into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

fn readers_ready(text: &str) -> bool {
    reader_lag(text, "raw-sysmon", "normalizer").is_some()
        && reader_lag(text, "normalized", "writer").is_some()
}

fn reader_lag(text: &str, topic: &str, role: &str) -> Option<u64> {
    text.lines()
        .find(|line| {
            line.starts_with("goliath_reader_lag_records{")
                && line.contains(&format!("topic=\"{topic}\""))
                && line.contains(&format!("reader=\"{role}\""))
        })
        .and_then(|line| line.split_whitespace().last()?.parse().ok())
}

async fn metrics() -> Result<String, Failure> {
    metrics_at(METRICS).await
}

async fn metrics_at(address: &str) -> Result<String, Failure> {
    timeout(REQUEST_TIMEOUT, async {
        let mut stream = TcpStream::connect(address).await?;
        // HTTP/1.0 plus Connection: close avoids chunked transfer coding.
        stream
            .write_all(b"GET /metrics HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await?;
        let mut bytes = Vec::new();
        stream
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("metrics response exceeds 4 MiB".into());
        }
        parse_http(&String::from_utf8(bytes)?)
    })
    .await?
}

fn parse_http(text: &str) -> Result<String, Failure> {
    let (header, body) = text
        .split_once("\r\n\r\n")
        .ok_or("invalid metrics HTTP response")?;
    if !matches!(
        header
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1)),
        Some("200")
    ) {
        return Err("metrics endpoint did not return HTTP 200".into());
    }
    for line in header.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length")
                && value.trim().parse::<usize>()? != body.len()
            {
                return Err("truncated metrics HTTP response".into());
            }
            if key.eq_ignore_ascii_case("transfer-encoding") {
                return Err("unexpected transfer coding on HTTP/1.0 response".into());
            }
        }
    }
    Ok(body.to_owned())
}

async fn sample(
    system: &mut System,
    platform: &mut Platform,
    start: Instant,
    shared: &Mutex<Counts>,
) -> Result<Sample, Failure> {
    platform.check()?;
    let metrics = metrics().await?;
    let pid = Pid::from_u32(platform.0.id());
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_cpu().with_memory(),
    );
    let process = system.process(pid).ok_or("platform process disappeared")?;
    let sent = counts(shared)?;
    Ok(Sample {
        elapsed: start.elapsed(),
        metrics,
        cpu_ms: process.accumulated_cpu_time(),
        memory_bytes: process.memory(),
        sent_records: sent.records,
        sent_bytes: sent.bytes,
    })
}

fn scheduled(batch: u64, rate: u64) -> Duration {
    Duration::from_nanos(batch * BATCH * 1_000_000_000 / rate)
}

async fn produce(
    sender: KafkaSender,
    shared: Arc<Mutex<Counts>>,
    mut stopped: watch::Receiver<bool>,
    start: Instant,
    profile: Profile,
    worker: usize,
    workers: usize,
) -> Result<(), Failure> {
    let mut fleet = Fleet::new(SEED + u64::try_from(worker)?);
    let mut batch = u64::try_from(worker)?;
    let batches = profile.rate() * profile.duration().as_secs() / BATCH;
    let mut bytes = Vec::with_capacity(2_000_000);
    while batch < batches {
        if *stopped.borrow() {
            break;
        }
        tokio::select! {
            _ = stopped.changed() => break,
            () = sleep_until(start + scheduled(batch, profile.rate())) => {},
        }
        if start.elapsed() >= profile.duration() {
            break;
        }
        bytes.clear();
        let now = goliath::raw::now();
        for _ in 0..BATCH {
            serde_json::to_writer(&mut bytes, &fleet.record(now))?;
            bytes.push(b'\n');
        }
        if *stopped.borrow() || start.elapsed() >= profile.duration() {
            break;
        }
        let payload = goliath::raw::stamp(goliath::raw::now(), &bytes);
        timeout(SEND_TIMEOUT, sender.send(vec![payload]))
            .await
            .map_err(|_| "send timed out; acceptance is unknown, run is invalid")??;
        {
            let mut sent = shared.lock().map_err(|_| "sender counters poisoned")?;
            sent.records += BATCH;
            sent.bytes += u64::try_from(bytes.len())?;
        }
        batch += u64::try_from(workers)?;
    }
    Ok(())
}

async fn observe(
    run: &mut Run,
    jobs: &mut JoinSet<Result<(), Failure>>,
    system: &mut System,
    platform: &mut Platform,
    start: Instant,
    counters: &Mutex<Counts>,
) -> Result<(), Failure> {
    let mut ticks = interval_at(start + SAMPLE_EVERY, SAMPLE_EVERY);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = sleep_until(start + run.duration) => break,
            Some(done) = jobs.join_next(), if !jobs.is_empty() => { done??; },
            _ = ticks.tick() => { run.samples.push(sample(system, platform, start, counters).await?); },
        }
    }
    run.samples
        .push(sample(system, platform, start, counters).await?);
    Ok(())
}

fn stored(text: &str) -> Result<u64, Failure> {
    text.lines()
        .find_map(|line| line.strip_prefix("goliath_stored_outcomes_total "))
        .ok_or_else(|| "stored outcomes counter is missing".into())
        .and_then(|value| value.trim().parse().map_err(Failure::from))
}

async fn drain(
    run: &mut Run,
    system: &mut System,
    platform: &mut Platform,
    start: Instant,
    counters: &Mutex<Counts>,
) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let last = sample(system, platform, start, counters).await?;
        let caught_up = stored(&last.metrics)? >= last.sent_records
            && reader_lag(&last.metrics, "raw-sysmon", "normalizer") == Some(0)
            && reader_lag(&last.metrics, "normalized", "writer") == Some(0);
        run.samples.push(last);
        if caught_up {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("writer did not drain within 120 seconds".into());
        }
        sleep_until((Instant::now() + SAMPLE_EVERY).min(deadline)).await;
    }
}

fn persist_samples(run: &Run, out: &Path) -> Result<(), Failure> {
    let mut file = File::create(out.join("samples.jsonl"))?;
    for s in &run.samples {
        serde_json::to_writer(
            &mut file,
            &serde_json::json!({
                "elapsed_ms": s.elapsed.as_millis(), "metrics": s.metrics, "cpu_ms": s.cpu_ms,
                "memory_bytes": s.memory_bytes, "sent_records": s.sent_records, "sent_bytes": s.sent_bytes
            }),
        )?;
        writeln!(file)?;
    }
    Ok(())
}

fn write_manifest(out: &Path, workers: usize) -> Result<(), Failure> {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    let mut system = System::new_all();
    system.refresh_memory();
    fs::write(
        out.join("machine.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "commit": commit, "os": System::long_os_version(), "cpu": system.cpus().first().map(sysinfo::Cpu::brand),
            "logical_cpus": system.cpus().len(), "memory_bytes": system.total_memory(), "workers": workers,
            "seed": SEED, "generator": "Fleet", "batch_records": BATCH,
            "timing": "live UTC event time; global batch schedule; independent seeded workers"
        }))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_and_global_schedule() {
        assert_eq!(
            Profile::parse(&["--profile".into(), "ci".into()]).unwrap(),
            Profile::Ci
        );
        assert!(Profile::parse(&["--profile".into(), "typo".into()]).is_err());
        assert!(Profile::parse(&[]).is_err());
        assert_eq!(scheduled(0, 5_000), Duration::ZERO);
        assert_eq!(scheduled(1, 5_000), Duration::from_millis(200));
        assert_eq!(
            scheduled(179_999, 100_000),
            Duration::from_millis(1_799_990)
        );
    }
    #[test]
    fn readiness_requires_both_reader_samples() {
        let help =
            "# HELP goliath_reader_lag_records lag\n# TYPE goliath_reader_lag_records gauge\n";
        assert!(!readers_ready(help));
        let writer = format!(
            "{help}goliath_reader_lag_records{{topic=\"normalized\",reader=\"writer\"}} 0\n"
        );
        assert!(!readers_ready(&writer));
        assert!(readers_ready(&format!(
            "{writer}goliath_reader_lag_records{{reader=\"normalizer\",topic=\"raw-sysmon\"}} 0\n"
        )));
    }
    #[test]
    fn drain_counter_is_not_a_help_declaration() {
        assert!(stored("# HELP goliath_stored_outcomes_total outcomes").is_err());
        assert_eq!(
            stored(
                "# TYPE goliath_stored_outcomes_total counter\ngoliath_stored_outcomes_total 123\n"
            )
            .unwrap(),
            123
        );
        let lag = "goliath_reader_lag_records{topic=\"raw-sysmon\",reader=\"normalizer\"} 7\n";
        assert_eq!(reader_lag(lag, "raw-sysmon", "normalizer"), Some(7));
        assert_eq!(reader_lag(lag, "normalized", "writer"), None);
    }

    #[test]
    fn incomplete_http_cannot_be_a_successful_snapshot() {
        assert!(parse_http("HTTP/1.0 503 Busy\r\n\r\n").is_err());
        assert!(parse_http("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\n123").is_err());
        assert!(
            parse_http("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").is_err()
        );
        assert_eq!(
            parse_http("HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\n123\n").unwrap(),
            "123\n"
        );
    }

    #[tokio::test]
    async fn scrape_preserves_metric_text() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 512];
            let read = stream.read(&mut request).await.unwrap();
            assert!(request[..read].starts_with(b"GET /metrics HTTP/1.0\r\n"));
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nx 1\n")
                .await
                .unwrap();
        });
        assert_eq!(metrics_at(&address.to_string()).await.unwrap(), "x 1\n");
        server.await.unwrap();
    }
}
