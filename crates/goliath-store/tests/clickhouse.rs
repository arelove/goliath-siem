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
use goliath_normalize::{Envelope, Normalizer, SYSMON};
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
async fn events_are_read_back_by_when_they_were_received() {
    let Some(scratch) = Scratch::new("reread") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    let (first, second) = (1_790_000_000_000, 1_790_000_060_000);
    let batch = batch(KINDS, first);
    scratch.store.write(&batch).await.unwrap();
    scratch
        .store
        .write(&self::batch(KINDS, second))
        .await
        .unwrap();

    // The first minute alone: every event of the first batch, whole.
    let mut reading = scratch.store.received_between(first, second).unwrap();
    let mut read = Vec::new();
    while let Some(kept) = reading.next().await.unwrap() {
        read.push(kept);
    }
    assert_eq!(read.len(), batch.events());
    let mut ids: Vec<_> = read.iter().map(|kept| kept.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), read.len());
    for kept in &read {
        assert_eq!((kept.received, kept.source.as_str()), (first, "sysmon"));
        let event: serde_json::Value = serde_json::from_str(&kept.event).unwrap();
        // Numbers come back as numbers, the time among them.
        assert!(event["time"].is_i64(), "{}", kept.event);
        assert!(event["class_uid"].is_u64());
    }
    // A range that holds nothing reads as nothing.
    let mut reading = scratch
        .store
        .received_between(second + 1, second + 2)
        .unwrap();
    assert_eq!(reading.next().await.unwrap(), None);

    assert!(scratch.store.holds_received_from(second).await.unwrap());
    assert!(!scratch.store.holds_received_from(second + 1).await.unwrap());
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

/// One day in milliseconds.
const DAY: i64 = 86_400_000;

fn now() -> i64 {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    i64::try_from(elapsed.as_millis()).unwrap()
}

#[tokio::test]
async fn retention_counts_from_receipt_not_from_the_claimed_time() {
    let Some(scratch) = Scratch::new("retention") else {
        return;
    };
    scratch.store.migrate().await.unwrap();

    // Received 60 days ago, with ordinary times.
    let old = batch(KINDS, now() - 60 * DAY);
    // Received now, but claiming to be from 2001: a forged time must not
    // make evidence expire.
    let forged = batch(
        &KINDS.replace("\"SystemTime\": \"2026-", "\"SystemTime\": \"2001-"),
        now(),
    );
    scratch.store.write(&old).await.unwrap();
    scratch.store.write(&forged).await.unwrap();
    assert_eq!(
        scratch
            .count("SELECT count() FROM events WHERE toYear(time) = 2001")
            .await,
        forged.events() as u64
    );

    let thirty = std::num::NonZeroU16::new(30);
    scratch.store.set_retention(thirty).await.unwrap();
    assert_eq!(scratch.store.retention().await.unwrap(), thirty);
    // Setting it again changes nothing.
    scratch.store.set_retention(thirty).await.unwrap();

    scratch
        .client
        .query("OPTIMIZE TABLE events FINAL")
        .execute()
        .await
        .unwrap();
    assert_eq!(
        scratch.count("SELECT count() FROM events").await,
        forged.events() as u64
    );

    scratch.store.set_retention(None).await.unwrap();
    assert_eq!(scratch.store.retention().await.unwrap(), None);
    scratch.drop().await;
}

#[tokio::test]
async fn the_writer_flushes_when_full_and_keeps_rows_until_written() {
    use goliath_store::{Limits, Writer};
    use std::time::Duration;

    let Some(scratch) = Scratch::new("writer") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    let sysmon = Normalizer::from_yaml(SYSMON).unwrap();
    let mut outcomes = Vec::new();
    sysmon.normalize(KINDS.as_bytes(), |outcome| outcomes.push(outcome));
    sysmon.normalize(MALFORMED.as_bytes(), |outcome| outcomes.push(outcome));
    let total = outcomes.len();
    assert!(total > 3);

    let limits = Limits {
        max_rows: 3,
        max_delay: Duration::from_secs(3600),
    };
    let mut writer = Writer::new(scratch.store.clone(), limits);
    assert_eq!(writer.deadline(), None);
    for outcome in outcomes {
        let envelope = Envelope::new(sysmon.name(), sysmon.version(), outcome);
        writer.push(envelope).await.unwrap();
        assert!(writer.waiting() < 3);
    }
    assert!(writer.deadline().is_some());
    // Not due for an hour, so nothing moves.
    writer.flush_if_due().await.unwrap();
    let written = scratch.count("SELECT count() FROM events").await
        + scratch.count("SELECT count() FROM dead_letters").await;
    assert_eq!(written, (total - writer.waiting()) as u64);

    writer.flush().await.unwrap();
    assert_eq!(writer.waiting(), 0);
    assert_eq!(writer.deadline(), None);
    let written = scratch.count("SELECT count() FROM events").await
        + scratch.count("SELECT count() FROM dead_letters").await;
    assert_eq!(written, total as u64);
    scratch.drop().await;
}

#[tokio::test]
async fn rows_taken_from_several_writers_and_absorbed_by_one_are_all_written() {
    use goliath_normalize::Outcome;
    use goliath_store::{Limits, Writer};

    let Some(scratch) = Scratch::new("absorb") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    let sysmon = Normalizer::from_yaml(SYSMON).unwrap();
    let mut outcomes = Vec::new();
    sysmon.normalize(KINDS.as_bytes(), |outcome| outcomes.push(outcome));
    sysmon.normalize(MALFORMED.as_bytes(), |outcome| outcomes.push(outcome));
    let total = outcomes.len();
    let (events, dead) = outcomes
        .iter()
        .fold((0, 0), |(events, dead), outcome| match outcome {
            Outcome::Event(_) => (events + 1, dead),
            _ => (events, dead + 1),
        });

    // Two threads' worth of rows, each built by a writer of its own.
    let mut halves = [
        Writer::new(scratch.store.clone(), Limits::default()),
        Writer::new(scratch.store.clone(), Limits::default()),
    ];
    let half = total / 2;
    for (index, outcome) in outcomes.into_iter().enumerate() {
        let envelope = Envelope::new(sysmon.name(), sysmon.version(), outcome);
        halves[usize::from(index >= half)].add(envelope).unwrap();
    }
    let mut writer = Writer::new(scratch.store.clone(), Limits::default());
    for part in &mut halves {
        writer.absorb(part.take());
        assert_eq!(part.waiting(), 0);
    }
    assert_eq!(writer.waiting(), total);
    assert!(writer.deadline().is_some());

    writer.flush().await.unwrap();
    assert_eq!(scratch.count("SELECT count() FROM events").await, events);
    assert_eq!(
        scratch.count("SELECT count() FROM dead_letters").await,
        dead
    );
    scratch.drop().await;
}

#[tokio::test]
async fn an_overview_counts_what_is_stored_by_time_severity_and_value() {
    use goliath_store::SearchLimits;

    let Some(scratch) = Scratch::new("overview") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    // The samples' events are from 2026-09-24; received that day too.
    let day = 24 * 3_600_000;
    let received = 1_790_208_000_000; // 2026-09-24T00:00:00Z
    let mut events = 0;
    for input in [KINDS, MALFORMED] {
        let written = batch(input, received + day / 2);
        events += written.events() as u64;
        scratch.store.write(&written).await.unwrap();
    }

    let hour = 3_600_000;
    let overview = scratch
        .store
        .overview(
            received - day,
            received + 2 * day,
            hour,
            SearchLimits::default(),
        )
        .await
        .unwrap();
    let total: u64 = overview.series.iter().map(|bucket| bucket.count).sum();
    assert_eq!(total, events);
    assert!(overview.series.iter().all(|bucket| bucket.at % hour == 0));
    let classes: u64 = overview.classes.iter().map(|entry| entry.count).sum();
    assert!(classes > 0 && classes <= events);
    assert_eq!(overview.sources.len(), 1);
    assert_eq!(overview.sources[0].key, "sysmon");
    assert!(!overview.hosts.is_empty(), "Sysmon events name their host");
    assert!(overview.hosts.iter().all(|entry| !entry.key.is_empty()));
    let top_host: u64 = overview
        .host_series
        .iter()
        .filter(|bucket| bucket.host == overview.hosts[0].key)
        .map(|bucket| bucket.count)
        .sum();
    assert_eq!(top_host, overview.hosts[0].count);
    assert!(overview.dead_letters > 0);

    // Arrivals count by when records were taken: only what was taken now.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let recent = batch(KINDS, i64::try_from(now).unwrap());
    scratch.store.write(&recent).await.unwrap();
    let arrived = scratch
        .store
        .arrivals(60, SearchLimits::default())
        .await
        .unwrap();
    assert_eq!(
        arrived.iter().map(|second| second.count).sum::<u64>(),
        recent.events() as u64
    );
    scratch.drop().await;
}

#[tokio::test]
async fn events_and_dead_letters_are_counted_by_source_and_hour() {
    use goliath_store::{SearchLimits, Status, Watched};

    let Some(scratch) = Scratch::new("health") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    // The counts are kept five weeks, so they are received now.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let hour = now / 3_600_000 * 3_600;
    let kinds = batch(KINDS, hour * 1000 + 1);
    let malformed = batch(MALFORMED, hour * 1000 + 2);
    assert!(malformed.dead_letters() > 0);
    scratch.store.write(&kinds).await.unwrap();
    scratch.store.write(&malformed).await.unwrap();

    let hours = scratch
        .store
        .source_hours(SearchLimits::default())
        .await
        .unwrap();
    assert_eq!(hours.len(), 1, "{hours:?}");
    assert_eq!(hours[0].source, "sysmon");
    assert_eq!(i64::from(hours[0].hour), hour);
    assert_eq!(
        hours[0].events,
        u64::try_from(kinds.events() + malformed.events()).unwrap()
    );
    assert_eq!(hours[0].last_received, hour * 1000 + 2);

    let dead_letters = scratch
        .store
        .dead_letter_hours(SearchLimits::default())
        .await
        .unwrap();
    let counted: u64 = dead_letters.iter().map(|hour| hour.dead_letters).sum();
    assert_eq!(counted, u64::try_from(malformed.dead_letters()).unwrap());

    // Counted this hour only: no baseline yet, and not quiet.
    let watched = [Watched {
        source: "zeek".to_owned(),
        silent_after_minutes: 60,
    }];
    let health = scratch
        .store
        .source_health(now, &watched, SearchLimits::default())
        .await
        .unwrap();
    let statuses: Vec<(&str, Status)> = health
        .iter()
        .map(|health| (health.source.as_str(), health.status))
        .collect();
    assert_eq!(
        statuses,
        [("zeek", Status::Waiting), ("sysmon", Status::Learning)]
    );
    scratch.drop().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One story, told in order.
async fn reports_keep_the_newest_of_each_run_and_how_long_each_status_held() {
    use goliath_store::{Condition, Report, SearchLimits, Standing};

    let Some(scratch) = Scratch::new("platform") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    // Reports are kept a day, so they are taken now.
    let now = now();
    let condition = |status, reason: &str, since| Condition {
        role: "writer".to_owned(),
        kind: "storing".to_owned(),
        status,
        reason: reason.to_owned(),
        message: format!("{reason}."),
        since,
    };
    let report = |instance: &str, started, sent, conditions| Report {
        instance: instance.to_owned(),
        roles: vec!["writer".to_owned(), "detector".to_owned()],
        version: "0.1.0".to_owned(),
        started,
        sent,
        counters: [("stored".to_owned(), 7)].into(),
        conditions,
    };
    let started = now - 60_000;
    let ok = condition(Standing::Ok, "stored", started);
    let failing = condition(Standing::Failing, "store_refused", now - 20_000);
    // Two reports while it stored, two while it was refused; a collector
    // with nothing to say; and the writer started again.
    for (reports, received) in [
        (
            vec![report("writer-0", started, now - 45_000, vec![ok.clone()])],
            now - 45_000,
        ),
        (
            vec![report("writer-0", started, now - 30_000, vec![ok])],
            now - 30_000,
        ),
        (
            vec![
                report("writer-0", started, now - 15_000, vec![failing.clone()]),
                report("collector-0", started, now - 15_000, Vec::new()),
            ],
            now - 15_000,
        ),
        (
            vec![report("writer-0", started, now - 10_000, vec![failing])],
            now - 10_000,
        ),
        (
            vec![report("writer-0", now - 5_000, now - 4_000, Vec::new())],
            now - 4_000,
        ),
    ] {
        scratch
            .store
            .write_reports(&reports, received)
            .await
            .unwrap();
    }
    scratch.store.write_reports(&[], now).await.unwrap();

    let reports = scratch
        .store
        .platform_reports(now - 3_600_000, SearchLimits::default())
        .await
        .unwrap();
    let runs: Vec<(&str, i64, i64)> = reports
        .iter()
        .map(|report| (report.instance.as_str(), report.started, report.received))
        .collect();
    assert_eq!(
        runs,
        [
            ("writer-0", now - 5_000, now - 4_000),
            ("writer-0", started, now - 10_000),
            ("collector-0", started, now - 15_000),
        ]
    );
    assert_eq!(reports[1].roles, ["writer", "detector"]);
    assert_eq!(reports[1].counters, [("stored".to_owned(), 7)]);
    assert_eq!(reports[1].sent, now - 10_000);
    // Nothing older than what is asked for.
    let recent = scratch
        .store
        .platform_reports(now - 12_000, SearchLimits::default())
        .await
        .unwrap();
    assert_eq!(recent.len(), 2, "{recent:?} at {now}");

    let held = scratch
        .store
        .platform_conditions(now - 3_600_000, SearchLimits::default())
        .await
        .unwrap();
    let periods: Vec<(&str, &str, i64, i64)> = held
        .iter()
        .map(|held| {
            (
                held.status.as_str(),
                held.reason.as_str(),
                held.since,
                held.seen,
            )
        })
        .collect();
    assert_eq!(
        periods,
        [
            ("ok", "stored", started, now - 30_000),
            ("failing", "store_refused", now - 20_000, now - 10_000),
        ]
    );
    assert_eq!(
        (
            held[1].instance.as_str(),
            held[1].role.as_str(),
            held[1].kind.as_str()
        ),
        ("writer-0", "writer", "storing")
    );
    assert_eq!(held[1].message, "store_refused.");
    scratch.drop().await;
}

#[tokio::test]
async fn what_events_showed_is_added_up_and_keeps_its_first_and_last_event() {
    use goliath_search::Cursor;
    use goliath_store::{ClaimSeen, Graphed, LinkSeen};

    let Some(scratch) = Scratch::new("graph") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    // 2026-09-25T10:00:00Z, and events within that hour.
    let hour = 1_790_330_400_000;
    let at = |minute: i64, id: u8| Cursor {
        time: hour + minute * 60_000,
        id: [id; 16],
    };
    let run = |events: u64, first: Cursor, last: Cursor| Graphed {
        scope: String::new(),
        received: hour + 3_600_000,
        links: vec![LinkSeen {
            src: "user:name:corp\\adam".to_owned(),
            link: "logged_on_to".to_owned(),
            dst: "host:name:dc-1.corp.example".to_owned(),
            events,
            first,
            last,
        }],
        claims: vec![ClaimSeen {
            one: "user:sid:s-1-5-21-1-2-3-1104".to_owned(),
            other: "user:name:corp\\adam".to_owned(),
            rule: "user".to_owned(),
            events,
            first,
            last,
        }],
    };
    // Two runs of one hour, the later one holding the earlier event, and a
    // run of another scope, which is another row.
    let mut other = run(7, at(1, 7), at(2, 7));
    other.scope = "branch".to_owned();
    scratch
        .store
        .write_graph(&[
            run(2, at(20, 1), at(50, 2)),
            run(3, at(5, 3), at(30, 4)),
            other,
        ])
        .await
        .unwrap();
    // Nothing to write is no request.
    scratch.store.write_graph(&[]).await.unwrap();

    for table in ["graph_links", "graph_claims"] {
        let sum = |column: &str| {
            format!(
                "SELECT toUInt64({column}) FROM (SELECT sum(events) AS events, \
                     toUnixTimestamp64Milli(min(first_seen)) AS first_seen, \
                     toUnixTimestamp64Milli(max(last_seen)) AS last_seen, \
                     reinterpretAsUInt8(substring(min(first_event), 24, 1)) AS first_id, \
                     reinterpretAsUInt8(substring(max(last_event), 24, 1)) AS last_id \
                     FROM {table} WHERE scope = '')"
            )
        };
        assert_eq!(scratch.count(&sum("events")).await, 5, "{table}");
        assert_eq!(
            scratch.count(&sum("first_seen")).await,
            u64::try_from(at(5, 0).time).unwrap(),
            "{table}"
        );
        assert_eq!(
            scratch.count(&sum("last_seen")).await,
            u64::try_from(at(50, 0).time).unwrap(),
            "{table}"
        );
        // The events themselves: the earliest and the latest of both runs.
        assert_eq!(scratch.count(&sum("first_id")).await, 3, "{table}");
        assert_eq!(scratch.count(&sum("last_id")).await, 2, "{table}");
        // Merged, the rows of one key are one row.
        scratch
            .client
            .query(&format!("OPTIMIZE TABLE {table} FINAL"))
            .execute()
            .await
            .unwrap();
        assert_eq!(
            scratch.count(&format!("SELECT count() FROM {table}")).await,
            2,
            "{table}"
        );
        assert_eq!(scratch.count(&sum("events")).await, 5, "{table}");
    }
    // A walk from the other end reads the same rows.
    assert_eq!(
        scratch
            .count(
                "SELECT sum(events) FROM graph_links \
                 WHERE scope = '' AND dst = 'host:name:dc-1.corp.example'"
            )
            .await,
        5
    );

    scratch.drop().await;
}

#[tokio::test]
async fn links_are_kept_as_long_as_events_and_claims_a_year() {
    let Some(scratch) = Scratch::new("graph_kept") else {
        return;
    };
    scratch.store.migrate().await.unwrap();
    let week = std::num::NonZeroU16::new(7);
    scratch.store.set_retention(week).await.unwrap();
    assert_eq!(scratch.store.retention().await.unwrap(), week);
    assert_eq!(
        scratch
            .count(
                "SELECT count() FROM system.tables WHERE database = currentDatabase() \
                 AND name = 'graph_links' AND engine_full LIKE '%toIntervalDay(7)%'"
            )
            .await,
        1
    );
    assert_eq!(
        scratch
            .count(
                "SELECT count() FROM system.tables WHERE database = currentDatabase()                  AND name = 'graph_claims' AND engine_full LIKE '%toIntervalDay(365)%'"
            )
            .await,
        1
    );
    scratch.store.set_retention(None).await.unwrap();
    assert_eq!(scratch.store.retention().await.unwrap(), None);
    scratch.drop().await;
}
