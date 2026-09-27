//! Writes a Sysmon recording of a fleet, with one intrusion in it, as files
//! a collector's inbox takes. The demo drops it into the running platform.
//!
//! ```text
//! cargo run --release -p goliath-bench --bin fleet -- --out inbox/sysmon
//! ```
//!
//! The recording ends now and covers the hours before it, so the search
//! view's default window shows it. The intrusion starts three hours before the
//! end, on `WS-0042.corp.example`; see [`goliath_bench::Fleet::intrusion`].

use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use goliath_bench::Fleet;
use serde_json::Value;

/// Records per file, well under the collector's limit on a file's size.
const PER_FILE: u64 = 20_000;

const HOUR: i64 = 3_600_000;

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
    let mut out = None;
    let (mut events, mut hours) = (100_000_u64, 24_i64);
    let mut arguments = env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--out" => out = Some(PathBuf::from(value)),
            "--events" => events = value.parse()?,
            "--hours" => hours = value.parse()?,
            _ => return Err(format!("unknown option {flag}").into()),
        }
    }
    let out = out.ok_or("--out names the directory to write to")?;
    if events == 0 || !(4..=24 * 30).contains(&hours) {
        return Err("--events must be at least 1, and --hours from 4 to 720".into());
    }
    fs::create_dir_all(&out)?;

    let end = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let start = end - hours * HOUR;
    let mut fleet = Fleet::new(end.unsigned_abs());
    // Newest last, so the stream is in time order as a host would send it.
    let mut intrusion = fleet.intrusion(end - 3 * HOUR);
    intrusion.reverse();

    let span = i128::from(hours * HOUR);
    let mut file = None;
    let (mut written, mut files) = (0, 0);
    for index in 0..events {
        let at = start + i64::try_from(i128::from(index) * span / i128::from(events))?;
        while intrusion.last().is_some_and(|(time, _)| *time <= at) {
            if let Some((_, record)) = intrusion.pop() {
                write(&mut file, &out, &mut files, &mut written, &record)?;
            }
        }
        write(&mut file, &out, &mut files, &mut written, &fleet.record(at))?;
    }
    while let Some((_, record)) = intrusion.pop() {
        write(&mut file, &out, &mut files, &mut written, &record)?;
    }
    finish(&mut file)?;
    println!("{written} records in {files} files in {}", out.display());
    Ok(())
}

/// A file being written, under a name the collector skips until it is
/// renamed to its own.
struct Open {
    writer: BufWriter<File>,
    partial: PathBuf,
    done: PathBuf,
}

fn write(
    file: &mut Option<Open>,
    out: &Path,
    files: &mut u64,
    written: &mut u64,
    record: &Value,
) -> Result<(), Failure> {
    if file.is_none() {
        *files += 1;
        let name = format!("fleet-{}-{files:03}.json", std::process::id());
        let partial = out.join(format!("{name}.tmp"));
        *file = Some(Open {
            writer: BufWriter::new(File::create(&partial)?),
            partial,
            done: out.join(name),
        });
    }
    if let Some(open) = file {
        serde_json::to_writer(&mut open.writer, record)?;
        open.writer.write_all(b"\n")?;
    }
    *written += 1;
    if written.is_multiple_of(PER_FILE) {
        finish(file)?;
    }
    Ok(())
}

fn finish(file: &mut Option<Open>) -> Result<(), Failure> {
    if let Some(mut open) = file.take() {
        open.writer.flush()?;
        drop(open.writer);
        fs::rename(&open.partial, &open.done)?;
    }
    Ok(())
}
