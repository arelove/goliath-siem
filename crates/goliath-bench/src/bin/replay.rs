//! Replays a recording of real telemetry into a collector's inbox, as if it
//! were happening now.
//!
//! ```text
//! cargo run --release -p goliath-bench --bin replay -- \
//!     --source sysmon --recording bench/datasets/example.json --out inbox/sysmon
//! ```
//!
//! The records' times are moved so that the first is now; the gaps between
//! them are kept, divided by `--speed`. Every quarter of a second, what has
//! come due is written as one file, under a temporary name and then renamed,
//! as a collector expects. `--times` plays the recording again after it ends,
//! each pass continuing the clock. See `goliath_bench::replay`.

use std::env;
use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use goliath_bench::replay::{Clock, Recording};

/// How often what has come due is written.
const TICK: i64 = 250;
/// Bytes a file holds at most, well under the collector's limit.
const MAX_FILE: usize = 16 << 20;

type Failure = Box<dyn Error>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Failure> {
    let (mut source, mut recording, mut out) = (None, None, None);
    let (mut speed, mut times) = (1.0_f64, 1_u32);
    let mut arguments = env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--source" => source = Some(value),
            "--recording" => recording = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            "--speed" => speed = value.parse()?,
            "--times" => times = value.parse()?,
            _ => return Err(format!("unknown option {flag}").into()),
        }
    }
    let source = source.ok_or("--source names the source definition the recording is for")?;
    let clock = Clock::of(&source).ok_or_else(|| {
        format!("no clock for source {source}; known: sysmon, entra, falco, auditd")
    })?;
    let path = recording.ok_or("--recording names the file to replay")?;
    let out = out.ok_or("--out names the inbox to write to")?;
    if !(speed.is_finite() && speed > 0.0) || times == 0 {
        return Err("--speed must be above 0, and --times at least 1".into());
    }
    let recording = Recording::read(clock, &fs::read(&path)?)?;
    if recording.is_empty() {
        return Err(format!("{} holds no records", path.display()).into());
    }
    fs::create_dir_all(&out)?;
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let pass = (recording.span() as f64 / speed).round() as i64 + 1000;
    eprintln!(
        "replaying {} records spanning {} s, at {speed}x, {times} time(s)",
        recording.len(),
        recording.span() / 1000,
    );

    let start = now()?;
    let mut writer = Batches::new(out);
    for round in 0..i64::from(times) {
        for (due, bytes) in recording.schedule(start + round * pass, speed) {
            // Write what is due before waiting for this record.
            while now()? + TICK < due {
                writer.flush()?;
                sleep(Duration::from_millis(TICK.unsigned_abs()));
            }
            writer.push(&bytes)?;
        }
    }
    writer.flush()?;
    eprintln!("wrote {} records in {} files", writer.records, writer.files);
    Ok(())
}

/// Records gathered into files, each written under a temporary name and
/// then renamed into the inbox.
struct Batches {
    out: PathBuf,
    bytes: Vec<u8>,
    pending: u64,
    records: u64,
    files: u64,
}

impl Batches {
    fn new(out: PathBuf) -> Self {
        Self {
            out,
            bytes: Vec::new(),
            pending: 0,
            records: 0,
            files: 0,
        }
    }

    fn push(&mut self, record: &[u8]) -> Result<(), Failure> {
        if self.bytes.len() + record.len() > MAX_FILE {
            self.flush()?;
        }
        self.bytes.extend_from_slice(record);
        self.pending += 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Failure> {
        if self.bytes.is_empty() {
            return Ok(());
        }
        let name = format!("replay-{}-{:06}", now()?, self.files);
        write_into(&self.out, &name, &self.bytes)?;
        self.files += 1;
        self.records += self.pending;
        self.bytes.clear();
        self.pending = 0;
        Ok(())
    }
}

/// Writes `bytes` as `name` in `directory`, appearing only once complete.
fn write_into(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), Failure> {
    let temporary = directory.join(format!("{name}.tmp"));
    let mut file = fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, directory.join(format!("{name}.json")))?;
    Ok(())
}

fn now() -> Result<i64, Failure> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
