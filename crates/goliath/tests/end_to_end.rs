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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
instance = "e2e"
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
    // The process said who it is, through the pipe, and the writer kept it.
    eventually(
        &client,
        "SELECT uniqExact(started) FROM platform_reports          WHERE instance = 'e2e' AND roles = ['collector', 'normalizer', 'writer']",
        1,
    )
    .await;
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
    // A process that started again is a second run under the same name.
    eventually(
        &client,
        "SELECT uniqExact(started) FROM platform_reports WHERE instance = 'e2e'",
        2,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_store_records_when_the_collector_took_a_record() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_received_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let config = |roles: &str| {
        let path = directory.path().join(format!("{}.toml", roles.len()));
        std::fs::write(
            &path,
            format!(
                r#"
roles = [{roles}]
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
"#
            ),
        )
        .unwrap();
        Config::load(&path).unwrap()
    };
    let inbox = directory.path().join("inbox/sysmon");

    // Collected and normalized with no writer running.
    let (stop, running) = start(config(r#""collector", "normalizer""#));
    let taken = SystemTime::now();
    drop_file(&inbox, "kinds.json", KINDS);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !inbox.join("done/kinds.json").exists() {
        assert!(Instant::now() < deadline, "the file was not collected");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();

    // Written seconds later: the store still records when it was taken.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (stop, running) = start(config(r#""writer""#));
    let client = connect(&url).with_database(&database);
    eventually(&client, "SELECT count() FROM events", expected(KINDS).0).await;
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    let taken = i64::try_from(taken.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap();
    let (earliest, latest) = client
        .query("SELECT min(toUnixTimestamp64Milli(received)), max(toUnixTimestamp64Milli(received)) FROM events")
        .fetch_one::<(i64, i64)>()
        .await
        .unwrap();
    assert!(
        earliest >= taken - 1_000 && latest <= taken + 1_500,
        "received from {earliest} to {latest}, but the file was taken at {taken}"
    );

    connect(&url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}

/// Sends one HTTP/1.1 request to the API and returns the status and the JSON
/// body.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_indicator_match_is_stored_as_a_finding_beside_its_event() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_detector_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("goliath.toml");
    std::fs::write(
        &path,
        format!(
            r#"
roles = ["collector", "normalizer", "detector", "writer"]
data = "data"

[[sources]]
definition = "sysmon"
inbox = "inbox/sysmon"

# What is counted here is matched as it arrives, and once.
[detector]
look_back_days = 0

[[detector.feeds]]
definition = "feodo-tracker"
file = "feodo.csv"

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
    // The address the fixture's network connection goes to, online until
    // long after the test runs.
    std::fs::write(
        directory.path().join("feodo.csv"),
        "\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\
         \"2026-01-01 00:00:00\",\"192.0.2.10\",\"443\",\"online\",\"2099-01-01\",\"Example\"\n",
    )
    .unwrap();
    let client = connect(&url).with_database(&database);
    let inbox = directory.path().join("inbox/sysmon");
    let (events, _) = expected(KINDS);

    let (stop, running) = start(Config::load(&path).unwrap());
    drop_file(&inbox, "001-kinds.json", KINDS);
    // Every event is stored as it was, and one finding beside them.
    eventually(&client, "SELECT count() FROM events", events + 1).await;
    eventually(
        &client,
        "SELECT count() FROM events WHERE class_uid = 2004",
        1,
    )
    .await;
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();

    // Restarted with the same file: the same finding, stored once.
    let (stop, running) = start(Config::load(&path).unwrap());
    drop_file(&inbox, "002-kinds-again.json", KINDS);
    eventually(&client, "SELECT count() FROM events", 2 * (events + 1)).await;
    eventually(
        &client,
        "SELECT count() FROM events FINAL WHERE class_uid = 2004",
        1,
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

const FINDINGS: &str = "SELECT count() FROM events FINAL WHERE class_uid = 2004";

/// A detector that was moved past events finds them in the store: here the
/// events were stored before there was a detector, and it starts with their
/// range of receipt time noted as unmatched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_the_detector_was_moved_past_are_matched_from_the_store() {
    events_stored_before_are_matched_from_the_store("rematch", true).await;
}

/// An indicator that arrives after an event finds it in the store: here the
/// events were stored before there was a detector, and to a detector that
/// starts with an empty indicator store every indicator is new.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_indicator_that_arrives_late_is_matched_against_stored_events() {
    events_stored_before_are_matched_from_the_store("late", false).await;
}

/// Stores events with no detector running, then starts one: with their
/// receipt time noted as `moved_past` and no look back, or with nothing
/// noted and a look back of a day.
#[allow(clippy::too_many_lines)]
async fn events_stored_before_are_matched_from_the_store(test: &str, moved_past: bool) {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_{test}_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let look_back_days = u8::from(!moved_past);
    // The roles, and a data directory of their own for each run, so that
    // the detector finds nothing in a topic.
    let config = |roles: &str, data: &str| {
        let path = directory.path().join(format!("{data}.toml"));
        std::fs::write(
            &path,
            format!(
                r#"
roles = [{roles}]
data = "{data}"

[[sources]]
definition = "sysmon"
inbox = "inbox-{data}"

[detector]
look_back_days = {look_back_days}

[[detector.feeds]]
definition = "feodo-tracker"
file = "feodo.csv"

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
        Config::load(&path).unwrap()
    };
    std::fs::write(
        directory.path().join("feodo.csv"),
        "\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\
         \"2026-01-01 00:00:00\",\"192.0.2.10\",\"443\",\"online\",\"2099-01-01\",\"Example\"\n",
    )
    .unwrap();
    let client = connect(&url).with_database(&database);
    let (events, _) = expected(KINDS);

    // Stored with no detector running: nothing is found.
    let (stop, running) = start(config(r#""collector", "normalizer", "writer""#, "before"));
    drop_file(
        &directory.path().join("inbox-before"),
        "001-kinds.json",
        KINDS,
    );
    eventually(&client, "SELECT count() FROM events", events).await;
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    assert_eq!(count(&client, FINDINGS).await, 0);
    let (earliest, latest) = client
        .query("SELECT min(toUnixTimestamp64Milli(received)), max(toUnixTimestamp64Milli(received)) FROM events")
        .fetch_one::<(i64, i64)>()
        .await
        .unwrap();

    // A detector that has their receipt time noted as unmatched, or one
    // that finds its feed new and looks back.
    let state = directory.path().join("after/intel");
    if moved_past {
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("unmatched.json"),
            format!(
                r#"{{"matched_until":{earliest},"ranges":[{{"from":{earliest},"to":{}}}]}}"#,
                latest + 1
            ),
        )
        .unwrap();
    }
    let (stop, running) = start(config(
        r#""collector", "normalizer", "detector", "writer""#,
        "after",
    ));
    if !moved_past {
        // The look back reads up to when the feed was in the store. The
        // later event must be taken after that, so wait for it to be noted.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let noted: Value = std::fs::read(state.join("unmatched.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Value::Null);
            if !noted["added"].is_null() || !noted["late"].is_null() {
                break;
            }
            assert!(Instant::now() < deadline, "no added indicator was noted");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    // What is read back waits for the writer to be past it: for an event
    // taken later. This one goes to another address, which no feed names.
    drop_file(
        &directory.path().join("inbox-after"),
        "002-elsewhere.json",
        &KINDS.replace("192.0.2.10", "192.0.2.99"),
    );
    eventually(&client, FINDINGS, 1).await;
    // The finding is of the event stored before, and was taken when it was.
    let (received, finding) = client
        .query(
            "SELECT toUnixTimestamp64Milli(received), toJSONString(event) \
             FROM events FINAL WHERE class_uid = 2004",
        )
        .fetch_one::<(i64, String)>()
        .await
        .unwrap();
    assert!(
        (earliest..=latest).contains(&received),
        "taken at {received}"
    );
    assert!(finding.contains("192.0.2.10"), "{finding}");
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    // What was read is given up, and is not read again.
    let noted: Value =
        serde_json::from_slice(&std::fs::read(state.join("unmatched.json")).unwrap()).unwrap();
    assert_eq!(noted["ranges"], serde_json::json!([]));
    assert_eq!(noted["late"], Value::Null, "{noted}");
    assert_eq!(noted["added"], Value::Null, "{noted}");
    drop_database(&url, &database).await;
}

async fn drop_database(url: &str, database: &str) {
    connect(url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}

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

/// Records sent over HTTP reach ClickHouse through the receiver, the
/// normalizer, and the writer, and are answered only once they are in the
/// pipe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_sent_over_http_reach_clickhouse() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_receiver_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let token = "fedcba9876543210".repeat(4);
    std::fs::write(directory.path().join("falco_token"), &token).unwrap();
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
roles = ["receiver", "normalizer", "writer"]
data = "data"

[receiver]
listen = "127.0.0.1:{port}"

[[sources]]
definition = "falco"
http = {{ token_file = "falco_token" }}

[store]
url = "{url}"
database = "{database}"
user = "{user}"
password_env = "GOLIATH_CLICKHOUSE_PASSWORD"

[writer]
max_rows = 1000
max_delay_ms = 100
"#
        ),
    )
    .unwrap();
    let falco = include_str!("../../goliath-normalize/sources/falco/kinds.input.json");
    let normalizer = Normalizer::from_yaml(goliath_normalize::FALCO).unwrap();
    let mut events = 0;
    normalizer.normalize(falco.as_bytes(), |outcome| {
        if matches!(outcome, Outcome::Event(_)) {
            events += 1;
        }
    });
    assert!(events > 0);

    let (stop, running) = start(Config::load(&path).unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < deadline, "the receiver did not listen");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, _) = http(port, "POST", "/ingest/falco", "wrong", falco).await;
    assert_eq!(status, 401);
    let (status, answer) = http(port, "POST", "/ingest/falco", &token, falco).await;
    assert_eq!(status, 200, "{answer}");
    let client = connect(&url).with_database(&database);
    eventually(&client, "SELECT count() FROM events", events).await;

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    connect(&url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn syslog_over_tcp_reaches_clickhouse() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_syslog_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("ssh.yaml"),
        r"
name: ssh
version: 1
framing: syslog
decoding: syslog
common:
  time: { from: timestamp, as: timestamp }
  device.hostname: hostname
  message: message
kinds:
  - name: login
    when: { app_name: sshd }
    class: { class_uid: 3002, activity_id: 1 }
    fields:
      src_endpoint.port: { from: proc_id, as: integer }
",
    )
    .unwrap();
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
roles = ["receiver", "normalizer", "writer"]
data = "data"

[[sources]]
definition = "ssh.yaml"
syslog = {{ listen = "127.0.0.1:{port}" }}

[store]
url = "{url}"
database = "{database}"
user = "{user}"
password_env = "GOLIATH_CLICKHOUSE_PASSWORD"

[writer]
max_rows = 1000
max_delay_ms = 100
"#
        ),
    )
    .unwrap();

    let (stop, running) = start(Config::load(&path).unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut sender = loop {
        if let Ok(stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            break stream;
        }
        assert!(Instant::now() < deadline, "the receiver did not listen");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let counted = "<38>1 2026-09-28T10:00:01Z bastion sshd 2222 - - Accepted\npublickey";
    let stream = format!(
        "<38>Sep 28 10:00:00 bastion sshd[22]: Accepted password\n{} {counted}<78>Sep 28 10:00:02 bastion CRON[1]: tick\n",
        counted.len()
    );
    tokio::io::AsyncWriteExt::write_all(&mut sender, stream.as_bytes())
        .await
        .unwrap();
    let client = connect(&url).with_database(&database);
    eventually(&client, "SELECT count() FROM events", 2).await;

    drop(sender);
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    connect(&url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn otlp_logs_reach_clickhouse() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_otlp_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let token = "0a1b2c3d4e5f6a7b".repeat(4);
    std::fs::write(directory.path().join("auth_token"), &token).unwrap();
    std::fs::write(
        directory.path().join("auth.yaml"),
        r"
name: auth
version: 1
framing: lines
decoding: json
common:
  time: { from: time, as: timestamp }
  device.hostname: resource.host.name
  message: body
kinds:
  - name: login
    when: { event_name: login }
    class: { class_uid: 3002, activity_id: 1 }
    fields:
      user.name: attributes.user.name
",
    )
    .unwrap();
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
roles = ["receiver", "normalizer", "writer"]
data = "data"

[receiver]
listen = "127.0.0.1:{port}"

[[sources]]
definition = "auth.yaml"
http = {{ token_file = "auth_token" }}

[store]
url = "{url}"
database = "{database}"
user = "{user}"
password_env = "GOLIATH_CLICKHOUSE_PASSWORD"

[writer]
max_rows = 1000
max_delay_ms = 100
"#
        ),
    )
    .unwrap();

    let (stop, running) = start(Config::load(&path).unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        assert!(Instant::now() < deadline, "the receiver did not listen");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let login = |name: &str| {
        format!(
            r#"{{"timeUnixNano":"1790589600000000000","eventName":"login","body":{{"stringValue":"signed in"}},"attributes":[{{"key":"user.name","value":{{"stringValue":"{name}"}}}}]}}"#
        )
    };
    let export = format!(
        r#"{{"resourceLogs":[{{"resource":{{"attributes":[{{"key":"host.name","value":{{"stringValue":"web-01"}}}}]}},"scopeLogs":[{{"logRecords":[{},{}]}}]}}]}}"#,
        login("adam"),
        login("eve")
    );
    let (status, answer) = http(port, "POST", "/v1/logs", &token, &export).await;
    assert_eq!(status, 200, "{answer}");
    let client = connect(&url).with_database(&database);
    eventually(&client, "SELECT count() FROM events", 2).await;

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    connect(&url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}

/// The value of the sample `name` on the platform's metrics endpoint.
async fn metric(port: u16, name: &str) -> Option<f64> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .ok()?;
    let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await.ok()?;
    response
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
}

/// A writer acknowledges each insert once it is written, and nothing it
/// still holds: a full writer inserts and acknowledges, while later outcomes
/// too few to fill it wait, unacknowledged, for `max_delay`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_writer_acknowledges_what_it_inserted_and_not_what_it_holds() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_acknowledged_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (events, dead) = expected(KINDS);
    let max_rows = events + dead;
    let (more_events, more_dead) = expected(MALFORMED);
    let held = more_events + more_dead;
    // The first file fills the writer; the second does not, and waits an
    // hour.
    assert!(held > 0 && held < max_rows);
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

[writer]
max_rows = {max_rows}
max_delay_ms = 3600000

[metrics]
listen = "127.0.0.1:{port}"
"#
        ),
    )
    .unwrap();
    let client = connect(&url).with_database(&database);

    let (stop, running) = start(Config::load(&path).unwrap());
    drop_file(&directory.path().join("inbox/sysmon"), "001.json", KINDS);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let stored = metric(port, "goliath_stored_outcomes_total").await;
        #[allow(clippy::cast_precision_loss)]
        if stored == Some(max_rows as f64) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "stored {stored:?}, expected {max_rows} acknowledged"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop_file(
        &directory.path().join("inbox/sysmon"),
        "002.json",
        MALFORMED,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let lag = metric(
            port,
            r#"goliath_reader_lag_records{topic="normalized",reader="writer"}"#,
        )
        .await;
        #[allow(clippy::cast_precision_loss)]
        if lag == Some(held as f64) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "lag {lag:?}, expected {held} held"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    #[allow(clippy::cast_precision_loss)]
    let stored = Some(max_rows as f64);
    assert_eq!(metric(port, "goliath_stored_outcomes_total").await, stored);
    let written = count(&client, "SELECT count() FROM events").await
        + count(&client, "SELECT count() FROM dead_letters").await;
    assert_eq!(written, max_rows);

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    connect(&url)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
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

[[sources]]
definition = "zeek"
inbox = "inbox/zeek"
silent_after_minutes = 240

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

    // Sysmon has events, counted this hour, so no baseline yet; Zeek, none.
    let (status, health) = http(port, "GET", "/api/v1/sources", &token, "").await;
    assert_eq!(status, 200, "{health}");
    let sources = health["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 2, "{health}");
    assert_eq!(sources[0]["source"], "zeek");
    assert_eq!(sources[0]["status"], "waiting");
    assert_eq!(sources[0]["silent_after_minutes"], 240);
    assert_eq!(sources[1]["source"], "sysmon");
    assert_eq!(sources[1]["status"], "learning");
    assert!(sources[1]["last_event"].as_i64().unwrap() > 0, "{health}");

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

/// The links and claims of a dropped file's events reach the store through
/// the graph role, beside the events and without waiting for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_events_show_reaches_the_graph_tables() {
    let Some(url) = clickhouse_url() else {
        return;
    };
    let user = clickhouse_user();
    let database = format!("goliath_test_graph_{}", std::process::id());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("goliath.toml");
    std::fs::write(
        &path,
        format!(
            r#"
roles = ["collector", "normalizer", "graph", "writer"]
instance = "e2e-graph"
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
"#
        ),
    )
    .unwrap();
    let client = connect(&url).with_database(&database);
    let inbox = directory.path().join("inbox/sysmon");

    // What the events of the file show, read here as the role reads it.
    let sysmon = Normalizer::from_yaml(SYSMON).unwrap();
    let mut links = std::collections::BTreeSet::new();
    let mut seen = 0;
    sysmon.normalize(KINDS.as_bytes(), |outcome| {
        if let Outcome::Event(normalized) = outcome {
            for link in goliath_graph::observe(&normalized.event).links {
                seen += 1;
                links.insert((
                    link.from.to_string(),
                    link.kind.as_str(),
                    link.to.to_string(),
                ));
            }
        }
    });
    assert!(links.len() >= 4, "the fixture shows links: {links:?}");

    let (stop, running) = start(Config::load(&path).unwrap());
    drop_file(&inbox, "001-kinds.json", KINDS);
    eventually(
        &client,
        "SELECT count() FROM (SELECT src, link, dst FROM graph_links GROUP BY src, link, dst)",
        links.len() as u64,
    )
    .await;
    eventually(&client, "SELECT sum(events) FROM graph_links", seen).await;
    // A link names where its events are: the first is a stored event.
    eventually(
        &client,
        "SELECT count() FROM (SELECT min(first_event) AS first FROM graph_links \
         WHERE link = 'connected_to') AS link \
         INNER JOIN events ON events.id = toFixedString(substring(link.first, 9, 16), 16)",
        1,
    )
    .await;
    // The role says that it runs, and the writer how storing its rows goes.
    eventually(
        &client,
        "SELECT uniqExact(type) FROM platform_conditions WHERE instance = 'e2e-graph' \
         AND ((role = 'graph' AND type = 'keeping_up:normalized') \
         OR (role = 'writer' AND type = 'storing_graph' AND status = 'ok'))",
        2,
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
