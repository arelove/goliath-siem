//! The queue of findings against a real ClickHouse server, as in
//! `clickhouse.rs`: set `GOLIATH_CLICKHOUSE_URL` to run them.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::env;

use goliath_normalize::Normalizer;
use goliath_search::{Limits, Search};
use goliath_store::{Batch, Place, Queue, SearchLimits, Store};
use serde_json::{Value, json};

const DEFINITION: &str = r#"
name: test
version: 1
framing: lines
decoding: json
common:
  time: { from: at, as: timestamp }
  metadata.version: { value: "1.5.0" }
  metadata.product.name: { value: Test }
kinds:
  - name: match
    when: { type: match }
    class: { class_uid: 2004, activity_id: 1 }
    fields:
      severity_id: { from: severity, as: integer }
      finding_info.title: title
  - name: launch
    when: { type: launch }
    class: { class_uid: 1007, activity_id: 1 }
    fields:
      severity_id: { from: severity, as: integer }
      process.name: name
"#;

/// Twelve findings a minute apart from 10:00, their severities running
/// 2, 3, 4 and again, the titles of every other one naming a beacon; and a
/// launch more severe than any, which is not a finding.
fn records() -> String {
    let mut lines = Vec::new();
    for minute in 0..12 {
        lines.push(json!({
            "type": "match",
            "at": format!("2026-09-25T10:{minute:02}:00Z"),
            "severity": 2 + minute % 3,
            "title": if minute % 2 == 0 { format!("Beacon {minute}") } else { format!("Scan {minute}") },
        }));
    }
    lines.push(json!({
        "type": "launch", "at": "2026-09-25T10:30:00Z", "severity": 5, "name": "sh",
    }));
    lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

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

async fn queue(store: &Store, search: Value, severities: &[u8], after: Option<Place>) -> Queue {
    let mut search = search;
    search["from"] = json!("2026-09-25T00:00:00Z");
    search["to"] = json!("2026-09-26T00:00:00Z");
    // Paths are checked against the class the queue holds.
    search["classes"] = json!([2004]);
    let search: Search = serde_json::from_value(search).unwrap();
    store
        .findings(
            &search.check(&Limits::default()).unwrap(),
            severities,
            after,
            SearchLimits::default(),
        )
        .await
        .unwrap()
}

fn order(queue: &Queue) -> Vec<(i64, i64)> {
    queue
        .findings
        .iter()
        .map(|found| (found.event["severity_id"].as_i64().unwrap(), found.at.time))
        .collect()
}

#[tokio::test]
async fn the_queue_holds_findings_only_the_most_severe_first_and_counts_them() {
    let normalizer = Normalizer::from_yaml(DEFINITION).unwrap();
    let mut batch = Batch::received_at(&normalizer, 1_790_330_000_000);
    let mut outcomes = Vec::new();
    normalizer.normalize(records().as_bytes(), |outcome| outcomes.push(outcome));
    for outcome in outcomes {
        batch.push(outcome).unwrap();
    }
    assert_eq!(batch.events(), 13, "every record is an event");
    let Some((url, user, password)) = server() else {
        return;
    };
    let database = format!("goliath_test_findings_{}", std::process::id());
    let store = Store::new(&url, &database)
        .unwrap()
        .with_credentials(&user, &password);
    store.migrate().await.unwrap();
    // Twice: the second copy must be neither shown nor counted.
    store.write(&batch).await.unwrap();
    store.write(&batch).await.unwrap();

    // Every finding and nothing else, in the queue's order.
    let all = queue(&store, json!({}), &[], None).await;
    let seen = order(&all);
    assert_eq!(seen.len(), 12);
    assert!(
        seen.windows(2).all(|pair| pair[0] > pair[1]),
        "the most severe first, then the newest: {seen:?}"
    );
    assert_eq!(seen[0].0, 4);
    assert!(all.findings.iter().all(|found| found.class_uid == 2004));
    assert_eq!(all.next, None, "a page that is not full is the last");
    let counts: Vec<(u8, u64)> = all
        .severities
        .iter()
        .map(|entry| (entry.severity_id, entry.count))
        .collect();
    assert_eq!(counts, [(4, 4), (3, 4), (2, 4)]);

    // Pages of five join into the same order without a gap or a repeat.
    let mut paged = Vec::new();
    let mut after = None;
    loop {
        let page = queue(&store, json!({ "limit": 5 }), &[], after).await;
        paged.extend(order(&page));
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(paged, seen);

    // The severities asked for bound the page, and the counts still say
    // what the others hold.
    let high = queue(&store, json!({}), &[4], None).await;
    assert_eq!(high.findings.len(), 4);
    assert_eq!(high.severities.len(), 3);

    // A filter bounds both.
    let beacons = queue(
        &store,
        json!({ "filters": [{ "path": "finding_info.title", "op": "starts_with", "value": "beacon" }] }),
        &[],
        None,
    )
    .await;
    assert_eq!(beacons.findings.len(), 6);
    assert_eq!(
        beacons
            .severities
            .iter()
            .map(|entry| entry.count)
            .sum::<u64>(),
        6
    );

    clickhouse::Client::default()
        .with_url(url)
        .with_user(user)
        .with_password(password)
        .query(&format!("DROP DATABASE IF EXISTS {database}"))
        .execute()
        .await
        .unwrap();
}
