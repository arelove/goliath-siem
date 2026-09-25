//! The store against a real ClickHouse server.
//!
//! Set `GOLIATH_CLICKHOUSE_URL` (and `GOLIATH_CLICKHOUSE_USER`,
//! `GOLIATH_CLICKHOUSE_PASSWORD` if the server needs them) to run these;
//! without it they pass without running, unless
//! `GOLIATH_REQUIRE_CLICKHOUSE` is set, as it is in CI, where skipping would
//! hide that nothing was tested. Every test uses a database of its own and
//! drops it afterwards.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::env;

use clickhouse::Client;
use goliath_normalize::{Normalizer, SYSMON};
use goliath_store::{Batch, MIGRATIONS, Store, StoreError};

const KINDS: &str = include_str!("../../goliath-normalize/sources/sysmon/kinds.input.json");
const MALFORMED: &str = include_str!("../../goliath-normalize/sources/sysmon/malformed.input.json");

/// A server to test against, or `None` to skip.
fn server() -> Option<(String, String, String)> {
    let Ok(url) = env::var("GOLIATH_CLICKHOUSE_URL") else {
        assert!(
            env::var_os("GOLIATH_REQUIRE_CLICKHOUSE").is_none(),
            "GOLIATH_REQUIRE_CLICKHOUSE is set but GOLIATH_CLICKHOUSE_URL is not"
        );
        eprintln!("GOLIATH_CLICKHOUSE_URL is not set; skipping");
        return None;
    };
    let user = env::var("GOLIATH_CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_owned());
    let password = env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default();
    Some((url, user, password))
}

/// A store in a database of its own, and a client to inspect it.
struct Scratch {
    store: Store,
    client: Client,
}

impl Scratch {
    fn new(test: &str) -> Option<Self> {
        let (url, user, password) = server()?;
        let database = format!("goliath_test_{test}_{}", std::process::id());
        let store = Store::new(&url, &database)
            .unwrap()
            .with_credentials(&user, &password);
        let client = Client::default()
            .with_url(&url)
            .with_user(&user)
            .with_password(&password)
            .with_database(&database)
            .with_setting("network_compression_method", "lz4");
        Some(Self { store, client })
    }

    async fn count(&self, query: &str) -> u64 {
        self.client.query(query).fetch_one::<u64>().await.unwrap()
    }

    async fn drop(self) {
        self.client
            .query(&format!(
                "DROP DATABASE IF EXISTS {}",
                self.store.database()
            ))
            .execute()
            .await
            .unwrap();
    }
}

fn batch(input: &str, received: i64) -> Batch {
    let sysmon = Normalizer::from_yaml(SYSMON).unwrap();
    let mut batch = Batch::received_at(&sysmon, received);
    let mut outcomes = Vec::new();
    sysmon.normalize(input.as_bytes(), |outcome| outcomes.push(outcome));
    for outcome in outcomes {
        batch.push(outcome).unwrap();
    }
    batch
}

#[tokio::test]
async fn migrations_apply_once_and_refuse_edits() {
    let Some(scratch) = Scratch::new("migrate") else {
        return;
    };
    let all: Vec<u32> = MIGRATIONS
        .iter()
        .map(|migration| migration.version)
        .collect();
    assert_eq!(scratch.store.migrate().await.unwrap(), all);
    assert_eq!(scratch.store.migrate().await.unwrap(), Vec::<u32>::new());

    // A recorded migration whose text no longer matches.
    scratch
        .client
        .query("INSERT INTO schema_migrations (version, name, checksum) VALUES (1, 'events', 'edited')")
        .execute()
        .await
        .unwrap();
    assert!(matches!(
        scratch.store.migrate().await,
        Err(StoreError::MigrationChanged { version: 1, .. })
    ));
    scratch.drop().await;
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let Some(scratch) = Scratch::new("newer") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    scratch
        .client
        .query(
            "INSERT INTO schema_migrations (version, name, checksum) VALUES (999, 'future', 'x')",
        )
        .execute()
        .await
        .unwrap();
    assert!(matches!(
        scratch.store.migrate().await,
        Err(StoreError::SchemaNewer { database: 999, .. })
    ));
    scratch.drop().await;
}

#[tokio::test]
async fn events_are_queryable_by_their_ocsf_paths() {
    let Some(scratch) = Scratch::new("events") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    let batch = batch(KINDS, 1_790_000_000_000);
    assert!(batch.events() > 0);
    scratch.store.write(&batch).await.unwrap();

    assert_eq!(
        scratch.count("SELECT count() FROM events").await,
        batch.events() as u64
    );
    // Paths into the event are columns of their own, and times are the
    // event's, not the batch's.
    let launches = scratch
        .count(
            "SELECT count() FROM events WHERE class_uid = 1007 \
             AND event.process.cmd_line::String != '' \
             AND time != received",
        )
        .await;
    assert!(launches > 0);
    // Nothing is lost on the way: the stored event is the normalized one.
    let stored = scratch
        .client
        .query("SELECT toJSONString(event) FROM events WHERE class_uid = 1007 LIMIT 1")
        .fetch_one::<String>()
        .await
        .unwrap();
    let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored["class_uid"], 1007);
    assert!(stored["unmapped"].is_object());
    scratch.drop().await;
}

#[tokio::test]
async fn a_batch_written_twice_is_stored_once() {
    let Some(scratch) = Scratch::new("dedup") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    let batch = batch(KINDS, 1_790_000_000_000);
    scratch.store.write(&batch).await.unwrap();
    scratch.store.write(&batch).await.unwrap();

    let expected = batch.events() as u64;
    assert_eq!(
        scratch.count("SELECT count() FROM events").await,
        2 * expected
    );
    assert_eq!(
        scratch.count("SELECT count() FROM events FINAL").await,
        expected
    );
    scratch.drop().await;
}

#[tokio::test]
async fn dead_letters_keep_their_raw_bytes() {
    let Some(scratch) = Scratch::new("dead") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    let batch = batch(MALFORMED, 1_790_000_000_000);
    assert!(batch.dead_letters() > 0);
    scratch.store.write(&batch).await.unwrap();

    assert_eq!(
        scratch.count("SELECT count() FROM dead_letters").await,
        batch.dead_letters() as u64
    );
    let raw = scratch
        .client
        .query("SELECT raw FROM dead_letters ORDER BY received, raw")
        .fetch_all::<String>()
        .await
        .unwrap();
    for text in raw {
        assert!(MALFORMED.contains(text.trim()), "{text}");
    }
    scratch.drop().await;
}
