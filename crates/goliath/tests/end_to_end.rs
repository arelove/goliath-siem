//! A raw Sysmon file, dropped into an inbox, reaches ClickHouse through every
//! role and topic of one process.
//!
//! Needs a server, like the store's tests: set `GOLIATH_CLICKHOUSE_URL`, and
//! `GOLIATH_CLICKHOUSE_USER` and `GOLIATH_CLICKHOUSE_PASSWORD` if it needs
//! them. Without the URL the test passes without running, unless
//! `GOLIATH_REQUIRE_CLICKHOUSE` is set.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::env;
use std::path::Path;
use std::time::{Duration, Instant};

use clickhouse::Client;
use goliath::Config;
use goliath_normalize::{Normalizer, Outcome, SYSMON};

const KINDS: &str = include_str!("../../goliath-normalize/sources/sysmon/kinds.input.json");
const MALFORMED: &str = include_str!("../../goliath-normalize/sources/sysmon/malformed.input.json");

/// Events and dead letters the definition makes of `input`.
fn expected(input: &str) -> (u64, u64) {
    let sysmon = Normalizer::from_yaml(SYSMON).unwrap();
    let (mut events, mut dead) = (0, 0);
    sysmon.normalize(input.as_bytes(), |outcome| match outcome {
        Outcome::Event(_) => events += 1,
        _ => dead += 1,
    });
    (events, dead)
}

/// Writes a file into the inbox the way a producer must: under a temporary
/// name, then renamed.
fn drop_file(inbox: &Path, name: &str, contents: &str) {
    std::fs::create_dir_all(inbox).unwrap();
    let temporary = inbox.join(format!("{name}.tmp"));
    std::fs::write(&temporary, contents).unwrap();
    std::fs::rename(temporary, inbox.join(name)).unwrap();
}

async fn count(client: &Client, query: &str) -> u64 {
    client.query(query).fetch_one::<u64>().await.unwrap_or(0)
}

/// Waits until `query` counts `expected`, or fails after 30 seconds.
async fn eventually(client: &Client, query: &str, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let found = count(client, query).await;
        if found == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{query}: {found}, expected {expected}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Runs the configured roles until the returned sender is used.
fn start(
    config: Config,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), goliath::RunError>>,
) {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(goliath::run(config, async move {
        let _ = stopped.await;
    }));
    (stop, running)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_file_reaches_clickhouse_once() {
    let Ok(url) = env::var("GOLIATH_CLICKHOUSE_URL") else {
        assert!(
            env::var_os("GOLIATH_REQUIRE_CLICKHOUSE").is_none(),
            "GOLIATH_CLICKHOUSE_URL is not set"
        );
        eprintln!("GOLIATH_CLICKHOUSE_URL is not set; skipping");
        return;
    };
    let user = env::var("GOLIATH_CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_owned());
    let database = format!("goliath_test_e2e_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("goliath.toml");
    std::fs::write(
        &path,
        format!(
            r#"
roles = ["collector", "normalizer", "writer"]
data = "data"

[[sources]]
definition = "sysmon"
inbox = "inbox/sysmon"

[store]
url = "{url}"
database = "{database}"
user = "{user}"
password_env = "GOLIATH_CLICKHOUSE_PASSWORD"
retention_days = 30

[writer]
max_rows = 1000
max_delay_ms = 100
"#
        ),
    )
    .unwrap();
    let client = Client::default()
        .with_url(&url)
        .with_user(&user)
        .with_password(env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default())
        .with_database(&database)
        .with_setting("network_compression_method", "lz4");
    let inbox = directory.path().join("inbox/sysmon");
    let (events, dead) = expected(KINDS);
    let (more_events, more_dead) = expected(MALFORMED);

    let (stop, running) = start(Config::load(&path).unwrap());
    drop_file(&inbox, "001-kinds.json", KINDS);
    drop_file(&inbox, "002-malformed.json", MALFORMED);
    eventually(&client, "SELECT count() FROM events", events + more_events).await;
    eventually(
        &client,
        "SELECT count() FROM dead_letters",
        dead + more_dead,
    )
    .await;
    assert!(inbox.join("done/001-kinds.json").exists());
    assert!(!inbox.join("001-kinds.json").exists());
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();

    // Restarted, and given the same file again: it is stored once.
    let (stop, running) = start(Config::load(&path).unwrap());
    drop_file(&inbox, "003-kinds-again.json", KINDS);
    eventually(
        &client,
        "SELECT count() FROM events",
        2 * events + more_events,
    )
    .await;
    eventually(
        &client,
        "SELECT count() FROM events FINAL",
        events + more_events,
    )
    .await;
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();

    Client::default()
        .with_url(&url)
        .with_user(&user)
        .with_password(env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default())
        .with_setting("network_compression_method", "lz4")
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}
