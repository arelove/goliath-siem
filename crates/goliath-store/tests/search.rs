//! Searches against a real ClickHouse server, as in `clickhouse.rs`: set
//! `GOLIATH_CLICKHOUSE_URL` to run them.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]

use std::env;

use goliath_normalize::Normalizer;
use goliath_search::{Limits, Search};
use goliath_store::{Batch, Page, SearchLimits, Store};
use serde_json::{Value, json};

const DEFINITION: &str = r#"
name: test
version: 1
framing: lines
decoding: json
common:
  time: { from: at, as: timestamp }
  severity_id: { value: 1 }
  metadata.version: { value: "1.5.0" }
  metadata.product.name: { value: Test }
kinds:
  - name: launch
    when: { type: launch }
    class: { class_uid: 1007, activity_id: 1 }
    fields:
      process.cmd_line: cmd
      process.name: name
      process.pid: { from: pid, as: integer }
    unmapped: [extra]
  - name: login
    when: { type: login }
    class: { class_uid: 3002, activity_id: 1 }
    fields:
      user.name: who
      is_mfa: mfa
"#;

/// 25 launches a second apart from 10:00:00, curl on even seconds; one launch
/// whose pid does not convert; and three logins.
fn records() -> String {
    let mut lines = Vec::new();
    for second in 0..25 {
        let (cmd, name) = if second % 2 == 0 {
            (format!("CURL http://198.51.100.7/{second}"), "curl")
        } else {
            ("ls -la".to_owned(), "ls")
        };
        lines.push(json!({
            "type": "launch",
            "at": format!("2026-09-25T10:00:{second:02}Z"),
            "cmd": cmd, "name": name, "pid": second,
            "extra": { "tty": format!("pts{second}") },
        }));
    }
    lines.push(json!({
        "type": "launch", "at": "2026-09-25T10:01:00Z",
        "cmd": "bad pid", "name": "x", "pid": "not a pid",
    }));
    for (minute, who, mfa) in [(2, "alice", true), (3, "bob", false), (4, "Alice", true)] {
        lines.push(json!({
            "type": "login", "at": format!("2026-09-25T10:0{minute}:00Z"),
            "who": who, "mfa": mfa,
        }));
    }
    lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

async fn store(test: &str) -> Option<Store> {
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
    let database = format!("goliath_test_search_{test}_{}", std::process::id());
    let store = Store::new(&url, &database)
        .unwrap()
        .with_credentials(&user, &password);
    store.migrate().await.unwrap();
    let normalizer = Normalizer::from_yaml(DEFINITION).unwrap();
    let mut batch = Batch::received_at(&normalizer, 1_790_330_000_000);
    let mut outcomes = Vec::new();
    normalizer.normalize(records().as_bytes(), |outcome| outcomes.push(outcome));
    for outcome in outcomes {
        batch.push(outcome).unwrap();
    }
    // Twice: the second copy must not be found.
    store.write(&batch).await.unwrap();
    store.write(&batch).await.unwrap();
    Some(store)
}

async fn drop(store: Store) {
    // The store's own client cannot drop: searches are read-only, and it
    // has no other way in, which is the point.
    let url = env::var("GOLIATH_CLICKHOUSE_URL").unwrap();
    let user = env::var("GOLIATH_CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_owned());
    let password = env::var("GOLIATH_CLICKHOUSE_PASSWORD").unwrap_or_default();
    clickhouse::Client::default()
        .with_url(url)
        .with_user(user)
        .with_password(password)
        .query(&format!("DROP DATABASE IF EXISTS {}", store.database()))
        .execute()
        .await
        .unwrap();
}

async fn page(store: &Store, search: Value) -> Page {
    let mut search = search;
    search["from"] = json!("2026-09-25T00:00:00Z");
    search["to"] = json!("2026-09-26T00:00:00Z");
    let search: Search = serde_json::from_value(search).unwrap();
    store
        .search(
            &search.check(&Limits::default()).unwrap(),
            SearchLimits::default(),
        )
        .await
        .unwrap()
}

async fn count(store: &Store, search: Value) -> usize {
    page(store, search).await.events.len()
}

fn one(path: &str, op: &str, value: Value) -> Value {
    json!({ "classes": [1007], "filters": [{ "path": path, "op": op, "value": value }] })
}

#[tokio::test]
async fn filters_find_what_they_say_and_nothing_else() {
    let Some(store) = store("filters").await else {
        return;
    };
    // Text ignores case: CURL is found by curl.
    assert_eq!(
        count(&store, one("process.cmd_line", "contains", json!("curl"))).await,
        13
    );
    assert_eq!(
        count(&store, one("process.cmd_line", "starts_with", json!("Ls "))).await,
        12
    );
    assert_eq!(
        count(&store, one("process.cmd_line", "ends_with", json!("/24"))).await,
        1
    );
    assert_eq!(
        count(&store, one("process.name", "equals", json!("LS"))).await,
        12
    );
    assert_eq!(
        count(&store, one("process.name", "in", json!(["x", "Curl"]))).await,
        14
    );
    // "Not equal" includes events without the attribute.
    assert_eq!(
        count(&store, one("process.name", "not_equals", json!("ls"))).await,
        14
    );
    assert_eq!(count(&store, one("process.pid", "gt", json!(20))).await, 4);
    assert_eq!(
        count(&store, one("process.pid", "in", json!([0, 1, 99]))).await,
        2
    );
    assert_eq!(
        count(&store, one("process.pid", "missing", Value::Null)).await,
        1
    );
    assert_eq!(
        count(&store, one("process", "exists", Value::Null)).await,
        26
    );
    assert_eq!(
        count(&store, one("unmapped.tty", "equals", json!("PTS3"))).await,
        1
    );
    assert_eq!(
        count(&store, one("time", "gte", json!("2026-09-25T10:00:20Z"))).await,
        6
    );

    let logins = |filters: Value| json!({ "classes": [3002], "filters": filters });
    assert_eq!(count(&store, logins(json!([]))).await, 3);
    assert_eq!(
        count(
            &store,
            logins(json!([{ "path": "is_mfa", "op": "equals", "value": true }]))
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &store,
            logins(json!([{ "path": "user.name", "op": "equals", "value": "ALICE" }]))
        )
        .await,
        2
    );
    // No class named: every class.
    assert_eq!(count(&store, json!({ "limit": 1000 })).await, 29);

    // A value is only ever a value.
    let hostile = "'); DROP TABLE events; --";
    assert_eq!(
        count(&store, one("process.cmd_line", "contains", json!(hostile))).await,
        0
    );
    assert_eq!(count(&store, json!({ "limit": 1000 })).await, 29);
    drop(store).await;
}

#[tokio::test]
async fn pages_run_newest_first_without_gaps_or_repeats() {
    let Some(store) = store("paging").await else {
        return;
    };
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    let mut pages = 0;
    loop {
        let mut search = json!({ "classes": [1007], "limit": 10 });
        if let Some(cursor) = &after {
            search["after"] = json!(cursor);
        }
        let page = page(&store, search).await;
        pages += 1;
        seen.extend(page.events.iter().map(|found| found.at));
        match page.next {
            Some(next) => after = Some(next.to_string()),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(seen.len(), 26);
    assert!(seen.windows(2).all(|pair| pair[0] > pair[1]), "{seen:?}");
    drop(store).await;
}

#[tokio::test]
async fn an_event_is_found_again_with_its_issues() {
    let Some(store) = store("event").await else {
        return;
    };
    let page = page(&store, one("process.name", "equals", json!("x"))).await;
    let at = page.events[0].at;
    let stored = store
        .event(at, SearchLimits::default())
        .await
        .unwrap()
        .expect("the event is stored");
    assert_eq!(stored.found.kind, "launch");
    assert_eq!(stored.found.source, "test");
    assert_eq!(stored.source_version, 1);
    assert_eq!(stored.found.event["unmapped"]["pid"], "not a pid");
    assert_eq!(stored.issues.len(), 1);
    assert_eq!(stored.issues[0].0, "process.pid");

    let mut elsewhere = at;
    elsewhere.id[0] ^= 0xff;
    assert!(
        store
            .event(elsewhere, SearchLimits::default())
            .await
            .unwrap()
            .is_none()
    );
    drop(store).await;
}
