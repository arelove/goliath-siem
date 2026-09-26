//! Stores a fleet's Sysmon records in ClickHouse and times searches over
//! them, as the M2.5 exit criterion asks. See `docs/benchmarks.md`.
//!
//! ```text
//! GOLIATH_CLICKHOUSE_URL=http://127.0.0.1:8123 GOLIATH_CLICKHOUSE_USER=goliath \
//! GOLIATH_CLICKHOUSE_PASSWORD=... \
//! cargo run --release -p goliath-bench --features search --bin search -- --events 10000000
//! ```
//!
//! Records go through the shipped Sysmon definition and `Store::write`, the
//! path the writer role takes, into a database of their own, which is kept:
//! a second run with the same count searches without loading again.

use std::env;
use std::error::Error;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use goliath_bench::{Fleet, rfc3339};
use goliath_normalize::{Normalizer, SYSMON};
use goliath_search::{Limits, Search};
use goliath_store::{Batch, SearchLimits, Store};
use serde_json::{Value, json};

/// The end of the recording, 2026-09-25T00:00:00Z. Fixed, so that every run
/// stores the same events and searches the same windows.
const END: i64 = 1_790_294_400_000;

const DAY: i64 = 86_400_000;

/// Records normalized and written together, as the writer role batches them.
const BATCH: u64 = 50_000;

/// How long after its time the platform takes a record.
const DELAY: i64 = 2_000;

type Failure = Box<dyn Error + Send + Sync>;

struct Options {
    events: u64,
    days: i64,
    runs: usize,
    database: String,
}

/// A search as the interface would send it.
struct Case {
    name: &'static str,
    search: Value,
}

fn cases() -> Vec<Case> {
    let search = |hours: i64, classes: &[u32], filters: Value| {
        let from = rfc3339(END - hours * 3_600_000);
        json!({ "from": from, "to": rfc3339(END), "classes": classes, "filters": filters })
    };
    vec![
        Case {
            name: "last hour, every class",
            search: search(1, &[], json!([])),
        },
        Case {
            name: "last 24 hours, launches, command line contains",
            search: search(
                24,
                &[1007],
                json!([{ "path": "process.cmd_line", "op": "contains", "value": "shadowcopy delete" }]),
            ),
        },
        Case {
            name: "last 24 hours, every class, one host",
            search: search(
                24,
                &[],
                json!([{ "path": "device.hostname", "op": "equals", "value": "WS-0042.corp.example" }]),
            ),
        },
        Case {
            name: "last 7 days, connections, destination port",
            search: search(
                7 * 24,
                &[4001],
                json!([{ "path": "dst_endpoint.port", "op": "equals", "value": 4444 }]),
            ),
        },
        Case {
            name: "last 30 days, launches, one user",
            search: search(
                30 * 24,
                &[1007],
                json!([{ "path": "process.user.name", "op": "equals", "value": r"corp\user0042" }]),
            ),
        },
    ]
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Failure> {
    let options = options()?;
    let url = env::var("GOLIATH_CLICKHOUSE_URL").map_err(|_| "set GOLIATH_CLICKHOUSE_URL")?;
    let user = env::var("GOLIATH_CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_owned());
    let password = env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default();
    let admin = clickhouse::Client::default()
        .with_url(&url)
        .with_user(&user)
        .with_password(&password);
    let store = Store::new(&url, &options.database)?.with_credentials(&user, &password);
    store.migrate().await?;

    let stored = count(&admin, &options.database).await?;
    if stored == options.events {
        println!("{stored} events already stored in {}", options.database);
    } else {
        admin
            .query(&format!("TRUNCATE TABLE {}.events", options.database))
            .execute()
            .await?;
        load(&store, &options).await?;
    }
    let parts: u64 = admin
        .query(
            "SELECT count() FROM system.parts \
             WHERE database = ? AND table = 'events' AND active",
        )
        .bind(&options.database)
        .fetch_one()
        .await?;
    let version: String = admin.query("SELECT version()").fetch_one().await?;
    println!("ClickHouse {version}, {parts} active parts\n");

    println!("| Search | Found | Fastest | Median | Slowest | Rows read |");
    println!("| --- | ---: | ---: | ---: | ---: | ---: |");
    for case in cases() {
        let search: Search = serde_json::from_value(case.search)?;
        let checked = search.check(&Limits::default())?;
        let mut times = Vec::with_capacity(options.runs);
        let mut found = 0;
        for _ in 0..options.runs {
            let started = Instant::now();
            let page = store.search(&checked, SearchLimits::default()).await?;
            times.push(started.elapsed());
            found = page.events.len();
        }
        times.sort();
        let read = rows_read(&admin, &options.database).await?;
        println!(
            "| {} | {found} | {} | {} | {} | {read} |",
            case.name,
            millis(times[0]),
            millis(times[times.len() / 2]),
            millis(times[times.len() - 1]),
        );
    }
    Ok(())
}

/// Generates and normalizes on one thread while this one writes.
async fn load(store: &Store, options: &Options) -> Result<(), Failure> {
    let started = Instant::now();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Batch>(4);
    let (events, days) = (options.events, options.days);
    let producer = thread::spawn(move || produce(events, days, &sender));
    let mut written = 0;
    while let Some(batch) = receiver.recv().await {
        store.write(&batch).await?;
        written += BATCH.min(events - written);
        if written % 1_000_000 < BATCH {
            println!("{written} events stored after {:.0?}", started.elapsed());
        }
    }
    producer.join().map_err(|_| "the generator panicked")??;
    let seconds = started.elapsed().as_secs_f64();
    #[allow(clippy::cast_precision_loss)]
    let rate = events as f64 / seconds;
    println!("{events} events stored in {seconds:.0} s, {rate:.0} events/s");
    Ok(())
}

fn produce(
    events: u64,
    days: i64,
    sender: &tokio::sync::mpsc::Sender<Batch>,
) -> Result<(), Failure> {
    let normalizer = Normalizer::from_yaml(SYSMON)?;
    let mut fleet = Fleet::new(1);
    let start = END - days * DAY;
    let span = i128::from(days * DAY);
    let mut index = 0;
    while index < events {
        let size = BATCH.min(events - index);
        let mut records = Vec::with_capacity(usize::try_from(size)? * 1_000);
        let mut last = start;
        for offset in 0..size {
            // Evenly spread, so every window holds its share.
            let at = i128::from(index + offset) * span / i128::from(events);
            last = start + i64::try_from(at)?;
            serde_json::to_writer(&mut records, &fleet.record(last))?;
            records.push(b'\n');
        }
        let mut batch = Batch::received_at(&normalizer, last + DELAY);
        let mut failed = None;
        normalizer.normalize(&records, |outcome| {
            if let Err(error) = batch.push(outcome) {
                failed.get_or_insert(error);
            }
        });
        if let Some(error) = failed {
            return Err(error.into());
        }
        if sender.blocking_send(batch).is_err() {
            break;
        }
        index += size;
    }
    Ok(())
}

async fn count(admin: &clickhouse::Client, database: &str) -> Result<u64, Failure> {
    Ok(admin
        .query(&format!("SELECT count() FROM {database}.events"))
        .fetch_one()
        .await?)
}

/// The rows the last search read, as the server logged it.
async fn rows_read(admin: &clickhouse::Client, database: &str) -> Result<u64, Failure> {
    admin.query("SYSTEM FLUSH LOGS").execute().await?;
    Ok(admin
        .query(
            "SELECT read_rows FROM system.query_log \
             WHERE type = 'QueryFinish' AND current_database = ? \
             AND query LIKE '%FROM events FINAL%' \
             ORDER BY event_time_microseconds DESC LIMIT 1",
        )
        .bind(database)
        .fetch_one()
        .await?)
}

fn options() -> Result<Options, Failure> {
    let mut options = Options {
        events: 10_000_000,
        days: 30,
        runs: 5,
        database: "goliath_bench".to_owned(),
    };
    let mut arguments = env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--events" => options.events = value.parse()?,
            "--days" => options.days = value.parse()?,
            "--runs" => options.runs = value.parse()?,
            "--database" => options.database = value,
            _ => return Err(format!("unknown option {flag}").into()),
        }
    }
    if options.events == 0 || options.days < 1 || options.runs == 0 {
        return Err("--events, --days, and --runs must be at least 1".into());
    }
    if !options
        .database
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("--database takes letters, digits, and underscores".into());
    }
    Ok(options)
}

fn millis(duration: Duration) -> String {
    format!("{} ms", duration.as_millis())
}
