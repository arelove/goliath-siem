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
use serde_json::Value;

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

/// The server's URL, or `None` if the test should be skipped.
fn clickhouse_url() -> Option<String> {
    let url = env::var("GOLIATH_CLICKHOUSE_URL").ok();
    if url.is_none() {
        assert!(
            env::var_os("GOLIATH_REQUIRE_CLICKHOUSE").is_none(),
            "GOLIATH_CLICKHOUSE_URL is not set"
        );
        eprintln!("GOLIATH_CLICKHOUSE_URL is not set; skipping");
    }
    url
}

fn clickhouse_user() -> String {
    env::var("GOLIATH_CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_owned())
}

fn connect(url: &str) -> Client {
    Client::default()
        .with_url(url)
        .with_user(clickhouse_user())
        .with_password(env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default())
        .with_setting("network_compression_method", "lz4")
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
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
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
    let client = connect(&url).with_database(&database);
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

    connect(&url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}

/// Sends one HTTP/1.1 request to the API and returns the status and the JSON
/// body.
async fn http(port: u16, method: &str, path: &str, token: &str, body: &str) -> (u16, Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

/// The pipeline and the API in one process: a Sysmon file dropped into the
/// inbox is found by a search over HTTP, and fetched again by where it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_api_finds_what_the_pipeline_stored() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_api_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let token = "0123456789abcdef".repeat(4);
    std::fs::write(directory.path().join("token"), &token).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = directory.path().join("goliath.toml");
    std::fs::write(
        &path,
        format!(
            r#"
roles = ["collector", "normalizer", "writer", "api"]
data = "data"

[[sources]]
definition = "sysmon"
inbox = "inbox/sysmon"

[store]
url = "{url}"
database = "{database}"
user = "{user}"
password_env = "GOLIATH_CLICKHOUSE_PASSWORD"

[writer]
max_rows = 1000
max_delay_ms = 100

[api]
listen = "127.0.0.1:{port}"
token_file = "token"
"#
        ),
    )
    .unwrap();
    let client = connect(&url).with_database(&database);
    let (events, _) = expected(KINDS);

    let (stop, running) = start(Config::load(&path).unwrap());
    drop_file(&directory.path().join("inbox/sysmon"), "001.json", KINDS);
    eventually(&client, "SELECT count() FROM events", events).await;

    let search = r#"{"from": "2026-09-24T00:00:00Z", "to": "2026-09-25T00:00:00Z",
        "classes": [1007], "filters": [{"path": "process.cmd_line", "op": "exists"}]}"#;
    let (status, _) = http(port, "POST", "/api/v1/search", "wrong", search).await;
    assert_eq!(status, 401);
    let (status, page) = http(port, "POST", "/api/v1/search", &token, search).await;
    assert_eq!(status, 200, "{page}");
    let found = page["events"].as_array().unwrap();
    assert!(!found.is_empty(), "{page}");
    assert!(found.iter().all(|event| event["class_uid"] == 1007));

    let at = found[0]["at"].as_str().unwrap();
    let (status, event) = http(port, "GET", &format!("/api/v1/events/{at}"), &token, "").await;
    assert_eq!(status, 200, "{event}");
    assert_eq!(event["source"], "sysmon");
    assert_eq!(event["event"], found[0]["event"]);

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    connect(&url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}

/// The same pipeline with each role in a process of its own, meeting through
/// Kafka. The collector runs and sends first; the normalizer and writer
/// start later and still receive everything.
///
/// Built with `--features kafka`; needs `GOLIATH_KAFKA_BROKERS` as well as
/// the ClickHouse settings above.
#[cfg(feature = "kafka")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roles_in_separate_processes_meet_through_kafka() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let brokers = env::var("GOLIATH_KAFKA_BROKERS")
        .expect("set GOLIATH_KAFKA_BROKERS to run the Kafka tests");
    let user = clickhouse_user();
    let run = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let database = format!("goliath_test_kafka_{}", run.replace('-', "_"));
    let kafka = format!(
        r#"
[kafka]
brokers = "{brokers}"
prefix = "goliath-test-{run}-"
replication = 1
"#
    );
    let directory = tempfile::tempdir().unwrap();
    let config = |name: &str, text: String| {
        let path = directory.path().join(name);
        std::fs::write(&path, text).unwrap();
        Config::load(&path).unwrap()
    };
    let collector = config(
        "collector.toml",
        format!(
            r#"
roles = ["collector"]

[[sources]]
definition = "sysmon"
inbox = "inbox/sysmon"
{kafka}"#
        ),
    );
    let normalizer = config(
        "normalizer.toml",
        format!(
            r#"
roles = ["normalizer"]

[[sources]]
definition = "sysmon"
{kafka}"#
        ),
    );
    let writer = config(
        "writer.toml",
        format!(
            r#"
roles = ["writer"]

[store]
url = "{url}"
database = "{database}"
user = "{user}"
password_env = "GOLIATH_CLICKHOUSE_PASSWORD"

[writer]
max_rows = 1000
max_delay_ms = 100
{kafka}"#
        ),
    );
    let client = connect(&url).with_database(&database);
    let inbox = directory.path().join("inbox/sysmon");
    let (events, dead) = expected(KINDS);

    let (stop_collector, collecting) = start(collector);
    drop_file(&inbox, "001-kinds.json", KINDS);
    let collected = inbox.join("done/001-kinds.json");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !collected.exists() {
        if collecting.is_finished() {
            let ended = collecting.await;
            panic!("the collector stopped: {ended:?}");
        }
        assert!(Instant::now() < deadline, "the collector took nothing");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (stop_normalizer, normalizing) = start(normalizer);
    let (stop_writer, writing) = start(writer);
    eventually(&client, "SELECT count() FROM events", events).await;
    eventually(&client, "SELECT count() FROM dead_letters", dead).await;
    for (stop, running) in [
        (stop_collector, collecting),
        (stop_normalizer, normalizing),
        (stop_writer, writing),
    ] {
        stop.send(()).unwrap();
        running.await.unwrap().unwrap();
    }

    client
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}
