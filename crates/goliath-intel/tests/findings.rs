//! The observables of events, by the schema's types, and hits as Detection
//! Findings.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_intel::{
    Allowlist, Allowlists, Assertion, Key, Kind, Matcher, MemoryStore, Store, finding, finding_uid,
    observables,
};
use goliath_ocsf::schema;
use serde_json::{Value, json};

fn found(event: &Value) -> Vec<(String, Kind, String)> {
    observables(event)
        .into_iter()
        .map(|observed| (observed.path, observed.kind, observed.value.into_owned()))
        .collect()
}

fn dns() -> Value {
    json!({
        "class_uid": 4003,
        "category_uid": 4,
        "activity_id": 2,
        "type_uid": 400_302,
        "time": 1_791_028_800_000_i64,
        "severity_id": 1,
        "metadata": { "version": "1.5.0" },
        "src_endpoint": { "ip": "10.1.2.3", "port": 53_211 },
        "dst_endpoint": { "ip": "10.0.0.53", "port": 53, "hostname": "dns01.corp.example" },
        "query": { "hostname": "C2.Bad.Example.com", "type": "A" },
        "answers": [
            { "rdata": "203.0.113.7", "type": "A" },
            { "rdata": "alias.example.net", "type": "CNAME" },
            { "rdata": "203.0.113.7", "type": "A" }
        ],
        "unmapped": { "ip": "198.51.100.1" }
    })
}

#[test]
fn observables_are_found_by_the_type_of_each_attribute() {
    assert_eq!(
        found(&dns()),
        [
            (
                "answers.0.rdata".to_owned(),
                Kind::Ip,
                "203.0.113.7".to_owned()
            ),
            (
                "dst_endpoint.hostname".to_owned(),
                Kind::Domain,
                "dns01.corp.example".to_owned()
            ),
            (
                "dst_endpoint.ip".to_owned(),
                Kind::Ip,
                "10.0.0.53".to_owned()
            ),
            (
                "query.hostname".to_owned(),
                Kind::Domain,
                "C2.Bad.Example.com".to_owned()
            ),
            (
                "src_endpoint.ip".to_owned(),
                Kind::Ip,
                "10.1.2.3".to_owned()
            ),
        ]
    );
}

#[test]
fn hashes_are_told_apart_by_their_algorithm_and_where_they_are() {
    let process = json!({
        "class_uid": 1007,
        "time": 1,
        "process": {
            "file": {
                "path": "C:\\Users\\adam\\a.exe",
                "name": "a.exe",
                "hashes": [
                    { "algorithm_id": 3, "value": "aa".repeat(32) },
                    { "algorithm_id": 1, "value": "bb".repeat(16) },
                    // No algorithm: told by its length.
                    { "value": "cc".repeat(20) },
                    // SHA-512 is no indicator kind.
                    { "algorithm_id": 4, "value": "dd".repeat(64) }
                ]
            },
            "parent_process": { "file": { "path": "C:\\Windows\\explorer.exe" } }
        }
    });
    assert_eq!(
        found(&process),
        [
            (
                "process.file.hashes.0.value".to_owned(),
                Kind::Sha256,
                "aa".repeat(32)
            ),
            (
                "process.file.hashes.1.value".to_owned(),
                Kind::Md5,
                "bb".repeat(16)
            ),
            (
                "process.file.hashes.2.value".to_owned(),
                Kind::Sha1,
                "cc".repeat(20)
            ),
            (
                "process.file.name".to_owned(),
                Kind::FileName,
                "a.exe".to_owned()
            ),
            (
                "process.file.path".to_owned(),
                Kind::FilePath,
                "C:\\Users\\adam\\a.exe".to_owned()
            ),
            (
                "process.parent_process.file.path".to_owned(),
                Kind::FilePath,
                "C:\\Windows\\explorer.exe".to_owned()
            ),
        ]
    );

    let tls = json!({
        "class_uid": 4001,
        "time": 1,
        "dst_endpoint": { "ip": "203.0.113.7", "autonomous_system": { "number": 64_496 } },
        "tls": {
            "sni": "bad.example.com",
            "ja3_hash": { "algorithm_id": 1, "value": "11".repeat(16) },
            "ja3s_hash": { "algorithm_id": 1, "value": "22".repeat(16) },
            "certificate": {
                "fingerprints": [{ "algorithm_id": 2, "value": "33".repeat(20) }]
            }
        }
    });
    assert_eq!(
        found(&tls),
        [
            (
                "dst_endpoint.autonomous_system.number".to_owned(),
                Kind::Asn,
                "64496".to_owned()
            ),
            (
                "dst_endpoint.ip".to_owned(),
                Kind::Ip,
                "203.0.113.7".to_owned()
            ),
            (
                "tls.certificate.fingerprints.0.value".to_owned(),
                Kind::CertificateHash,
                "33".repeat(20)
            ),
            ("tls.ja3_hash.value".to_owned(), Kind::Ja3, "11".repeat(16)),
            (
                "tls.ja3s_hash.value".to_owned(),
                Kind::Ja3s,
                "22".repeat(16)
            ),
            (
                "tls.sni".to_owned(),
                Kind::Domain,
                "bad.example.com".to_owned()
            ),
        ]
    );
}

#[test]
fn a_url_logged_as_host_and_path_is_put_together() {
    let request = |url: Value, port: u64| {
        json!({
            "class_uid": 4002,
            "time": 1,
            "dst_endpoint": { "port": port },
            "http_request": { "url": url }
        })
    };
    let urls = |event: &Value| -> Vec<String> {
        found(event)
            .into_iter()
            .filter(|(_, kind, _)| *kind == Kind::Url)
            .map(|(path, _, value)| format!("{path} {value}"))
            .collect()
    };
    // As Zeek and Suricata log a request: the host, and the path with its
    // query, on the connection's port.
    assert_eq!(
        urls(&request(
            json!({ "hostname": "Bad.Example.com", "path": "/gate.php?id=1" }),
            8080
        )),
        ["http_request.url http://Bad.Example.com:8080/gate.php?id=1"]
    );
    assert_eq!(
        urls(&request(
            json!({ "hostname": "2001:db8::1", "path": "a", "query_string": "x=1" }),
            80
        )),
        ["http_request.url http://[2001:db8::1]:80/a?x=1"]
    );
    // The object's own scheme and port come first.
    assert_eq!(
        urls(&request(
            json!({ "hostname": "bad.example.com", "path": "/", "scheme": "https", "port": 8443 }),
            80
        )),
        ["http_request.url https://bad.example.com:8443/"]
    );
    // A request through a proxy names the whole URL as its path.
    assert_eq!(
        urls(&request(
            json!({ "hostname": "proxy.corp.example", "path": "http://bad.example.com/a" }),
            3128
        )),
        ["http_request.url http://bad.example.com/a"]
    );
    // A whole URL is taken as it is, and no host gives none.
    assert_eq!(
        urls(&request(
            json!({ "hostname": "bad.example.com", "path": "/a", "url_string": "https://bad.example.com/a" }),
            443
        )),
        ["http_request.url.url_string https://bad.example.com/a"]
    );
    assert_eq!(urls(&request(json!({ "path": "/a" }), 80)), [] as [&str; 0]);

    // Put together on the default port, it meets the indicator as feeds
    // write it.
    let store = MemoryStore::new();
    store
        .replace_feed(
            "feed-a",
            "1",
            [(
                Key::new(Kind::Url, "http://bad.example.com/gate.php?id=1").expect("a key"),
                Assertion::new(80),
            )],
        )
        .expect("replaced");
    let matcher = Matcher::new(store, Allowlists::default());
    let event = request(
        json!({ "hostname": "bad.example.com", "path": "/gate.php?id=1" }),
        80,
    );
    let hits: usize = observables(&event)
        .iter()
        .map(|observed| {
            matcher
                .lookup(observed.kind, &observed.value, 1)
                .expect("looked up")
                .len()
        })
        .sum();
    assert_eq!(hits, 1);
}

#[test]
fn events_without_a_known_class_give_no_observables() {
    for event in [
        json!({ "class_uid": 999_999, "dst_endpoint": { "ip": "203.0.113.7" } }),
        json!({ "dst_endpoint": { "ip": "203.0.113.7" } }),
        json!("text"),
        // The attribute holds something other than its type.
        json!({ "class_uid": 4003, "dst_endpoint": "203.0.113.7", "answers": { "rdata": 5 } }),
    ] {
        assert_eq!(found(&event), []);
    }
}

/// Every event the shipped Sysmon definition gives in its fixture: the
/// network connection's addresses are found, and nothing under `unmapped`.
#[test]
fn the_events_of_a_shipped_definition_give_their_observables() {
    let outcomes: Vec<Value> = serde_json::from_str(include_str!(
        "../../goliath-normalize/sources/sysmon/kinds.expected.json"
    ))
    .expect("the fixture is JSON");
    let mut kinds = std::collections::BTreeSet::new();
    for outcome in &outcomes {
        for observed in observables(&outcome["event"]) {
            assert!(!observed.path.starts_with("unmapped"), "{}", observed.path);
            kinds.insert(observed.kind);
        }
    }
    assert!(kinds.contains(&Kind::Ip), "{kinds:?}");
    assert!(kinds.contains(&Kind::FilePath), "{kinds:?}");
}

fn matcher() -> Matcher<MemoryStore> {
    let store = MemoryStore::new();
    let key = |kind, value| Key::new(kind, value).expect("a key");
    store
        .replace_feed(
            "feed-a",
            "2026-10-03",
            [
                (
                    key(Kind::Domain, "c2.bad.example.com"),
                    Assertion::new(95)
                        .valid(None, Some(1_800_000_000))
                        .seen(Some(1_790_000_000), Some(1_791_000_000)),
                ),
                (key(Kind::Cidr, "10.0.0.0/8"), Assertion::new(40)),
            ],
        )
        .expect("replaced");
    store
        .replace_feed(
            "feed-b",
            "7",
            [(key(Kind::Domain, "c2.bad.example.com"), Assertion::new(60))],
        )
        .expect("replaced");
    let allowlists = Allowlists::new(&[Allowlist::from_yaml(
        "name: infrastructure\nversion: 3\nentries:\n  - { kind: cidr, value: 10.0.0.0/8, reason: Internal network }\n",
    )
    .expect("a list")])
    .expect("lists");
    Matcher::new(store, allowlists)
}

/// Every hit of every observable of `event`, as findings.
fn findings(event: &Value, event_id: &str, created: i64) -> Vec<Value> {
    let matcher = matcher();
    let at = event["time"].as_i64().expect("a time") / 1000;
    let mut findings = Vec::new();
    for observed in observables(event) {
        for hit in matcher
            .lookup(observed.kind, &observed.value, at)
            .expect("looked up")
        {
            findings.push(finding(event_id, event, &observed, &hit, created));
        }
    }
    findings
}

#[test]
fn a_hit_is_a_detection_finding_with_its_provenance() {
    let event = dns();
    let all = findings(
        &event,
        "7637f36857b0f35d4fdc9a844af102b2",
        1_791_028_805_000,
    );
    // The domain, and the two internal addresses in the network indicator.
    assert_eq!(all.len(), 3);
    let domain = all
        .iter()
        .find(|finding| finding["observables"][0]["name"] == "query.hostname")
        .expect("the domain's finding");

    assert_eq!(domain["class_uid"], 2004);
    assert_eq!(domain["type_uid"], 200_401);
    // The event's time, not the time it was made.
    assert_eq!(domain["time"], 1_791_028_800_000_i64);
    assert_eq!(
        domain["finding_info"]["created_time"],
        1_791_028_805_000_i64
    );
    assert_eq!(domain["status_id"], 1);
    assert_eq!(domain["is_alert"], true);
    // The highest confidence of its feeds: 95, High.
    assert_eq!(domain["confidence_score"], 95);
    assert_eq!(domain["confidence_id"], 3);
    assert_eq!(domain["severity_id"], 4);
    assert_eq!(
        domain["finding_info"]["title"],
        "Indicator match: domain c2.bad.example.com"
    );
    assert_eq!(
        domain["evidences"][0],
        json!({
            "uid": "7637f36857b0f35d4fdc9a844af102b2",
            "name": "query.hostname",
            "data": { "class_uid": 4003, "time": 1_791_028_800_000_i64, "value": "C2.Bad.Example.com" }
        })
    );
    assert_eq!(
        domain["observables"][0],
        json!({ "name": "query.hostname", "type_id": 1, "value": "C2.Bad.Example.com" })
    );
    assert_eq!(
        domain["osint"],
        json!([
            {
                "value": "c2.bad.example.com",
                "type_id": 2,
                "vendor_name": "feed-a",
                "uid": "2026-10-03",
                "confidence_id": 3,
                "created_time": 1_790_000_000_000_i64,
                "modified_time": 1_791_000_000_000_i64,
                "expiration_time": 1_800_000_000_000_i64
            },
            {
                "value": "c2.bad.example.com",
                "type_id": 2,
                "vendor_name": "feed-b",
                "uid": "7",
                "confidence_id": 2
            }
        ])
    );
    assert_eq!(domain["unmapped"]["assertions"][1]["confidence"], 60);
    assert_eq!(domain["unmapped"]["indicator_kind"], "domain");
    assert_eq!(domain["unmapped"]["indicator_value"], "c2.bad.example.com");
    assert_eq!(
        domain["finding_info"]["data_sources"],
        json!(["feed-a", "feed-b"])
    );
}

#[test]
fn a_suppressed_hit_is_a_finding_that_is_not_an_alert() {
    let event = dns();
    let all = findings(&event, "event", 1);
    let internal = all
        .iter()
        .find(|finding| finding["observables"][0]["name"] == "src_endpoint.ip")
        .expect("the address's finding");
    assert_eq!(internal["status_id"], 3);
    assert_eq!(internal["is_alert"], false);
    assert_eq!(internal["severity_id"], 1);
    assert_eq!(
        internal["status_detail"],
        "Allowlist infrastructure version 3, entry 10.0.0.0/8: Internal network"
    );
    assert_eq!(
        internal["unmapped"]["allowed"],
        json!({ "list": "infrastructure", "version": 3, "entry": "10.0.0.0/8", "reason": "Internal network" })
    );
    // The indicator is the network; the observable is the address.
    assert_eq!(internal["osint"][0]["value"], "10.0.0.0/8");
    assert_eq!(internal["observables"][0]["value"], "10.1.2.3");
    assert_eq!(internal["observables"][0]["type_id"], 2);
}

#[test]
fn a_finding_is_a_valid_event_of_its_class() {
    let event = dns();
    let class = schema::class(2004).expect("Detection Finding");
    for finding in findings(&event, "event", 1) {
        // Every member is an attribute of the class, and every member of its
        // objects an attribute of theirs.
        fn check(class: &schema::Class, path: &str, value: &Value) {
            if path == "unmapped" || path.starts_with("evidences.data") {
                return;
            }
            class
                .resolve(path)
                .unwrap_or_else(|error| panic!("{error}"));
            match value {
                Value::Object(members) => {
                    for (name, member) in members {
                        check(class, &format!("{path}.{name}"), member);
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        check(class, path, item);
                    }
                }
                _ => {}
            }
        }
        for (name, value) in finding.as_object().expect("an object") {
            check(class, name, value);
        }
        let typed: goliath_ocsf::Event = serde_json::from_value(finding).expect("an OCSF event");
        typed.validate().expect("a valid event");
    }
}

#[test]
fn a_finding_has_one_identifier_for_an_event_and_an_indicator() {
    let domain = Key::new(Kind::Domain, "c2.bad.example.com").expect("a key");
    let other = Key::new(Kind::Domain, "other.example.com").expect("a key");
    let uid = finding_uid("event-1", &domain);
    assert_eq!(uid.len(), 32);
    assert_eq!(uid, finding_uid("event-1", &domain));
    assert_ne!(uid, finding_uid("event-2", &domain));
    assert_ne!(uid, finding_uid("event-1", &other));

    let event = dns();
    let first = findings(&event, "event-1", 1);
    let again = findings(&event, "event-1", 2);
    assert_eq!(
        first[0]["finding_info"]["uid"],
        again[0]["finding_info"]["uid"]
    );
    assert_eq!(first[0]["metadata"]["uid"], first[0]["finding_info"]["uid"]);
}

/// The kinds of observable the events of each shipped source definition
/// give, from the definitions' own fixtures. A kind missing here is one no
/// indicator can match on that source.
#[test]
fn each_shipped_source_gives_the_kinds_its_events_hold() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../goliath-normalize/sources");
    let mut found = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(root).expect("the sources") {
        let directory = entry.expect("an entry").path();
        if !directory.is_dir() {
            continue;
        }
        let mut kinds = std::collections::BTreeSet::new();
        for file in std::fs::read_dir(&directory).expect("the fixtures") {
            let file = file.expect("an entry").path();
            let name = file
                .file_name()
                .expect("a name")
                .to_string_lossy()
                .into_owned();
            if !name.ends_with(".expected.json") || name.starts_with("malformed") {
                continue;
            }
            let outcomes: Vec<Value> =
                serde_json::from_str(&std::fs::read_to_string(&file).expect("the fixture reads"))
                    .expect("the fixture is JSON");
            for outcome in &outcomes {
                for observed in observables(&outcome["event"]) {
                    kinds.insert(observed.kind.as_str());
                }
            }
        }
        let name = directory
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        found.insert(name, kinds.into_iter().collect::<Vec<_>>().join(" "));
    }
    let expected = [
        ("auditd", "domain file-path ip user"),
        ("cloudtrail", "ip user"),
        ("entra", "ip user"),
        ("falco", "domain file-path user"),
        ("m365", "ip user"),
        ("okta", "ip user"),
        ("pcapdroid", "domain ip url"),
        (
            "suricata",
            "certificate-hash domain file-name ip ja3 sha256 url",
        ),
        ("sysmon", "domain file-path ip registry-key sha256 user"),
        (
            "sysmon-flat",
            "domain file-path ip registry-key sha256 user",
        ),
        ("windows-security", "domain file-path ip user"),
        ("zeek", "domain file-name ip url user"),
    ];
    let found: Vec<(&str, &str)> = found
        .iter()
        .map(|(name, kinds)| (name.as_str(), kinds.as_str()))
        .collect();
    assert_eq!(found, expected);
}
