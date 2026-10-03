//! Feed definitions, and what the publications of the shipped feeds and of
//! a STIX bundle become.

#![allow(clippy::expect_used, clippy::panic)]

use goliath_intel::{
    Allowlists, Assertion, FEEDS, Feed, IntelError, Key, Kind, Matcher, MemoryStore, Store,
};

/// 2026-10-03T12:00:00Z.
const FETCHED: i64 = 1_791_028_800;
const DAY: i64 = 86_400;

fn shipped(name: &str) -> Feed {
    let (_, yaml) = FEEDS
        .iter()
        .find(|(shipped, _)| *shipped == name)
        .expect("a shipped feed");
    Feed::from_yaml(yaml).expect("the definition loads")
}

fn find<'a>(indicators: &'a [(Key, Assertion)], kind: Kind, value: &str) -> &'a Assertion {
    let key = Key::new(kind, value).expect("a key");
    indicators
        .iter()
        .find(|(found, _)| *found == key)
        .map_or_else(|| panic!("no {key}"), |(_, assertion)| assertion)
}

#[test]
fn every_shipped_definition_loads_under_its_name() {
    for (name, yaml) in FEEDS {
        let feed = Feed::from_yaml(yaml).expect("the definition loads");
        assert_eq!(feed.name, *name);
        assert!(
            feed.url
                .as_deref()
                .is_some_and(|url| url.starts_with("https://")),
            "{name}"
        );
        assert!(feed.licence.is_some(), "{name}");
    }
}

#[test]
fn feodo_tracker_gives_addresses_that_hold_a_month_after_they_were_online() {
    let parsed = shipped("feodo-tracker")
        .parse(include_bytes!("data/feodo-tracker.csv"), FETCHED)
        .expect("parsed");
    assert_eq!(
        (parsed.indicators.len(), parsed.ignored, parsed.rejected),
        (3, 0, 0)
    );
    let assertion = find(&parsed.indicators, Kind::Ip, "203.0.113.7");
    assert_eq!(assertion.confidence, 90);
    // First seen 2022-06-04 21:24:53, last online 2026-03-07.
    assert_eq!(assertion.first_seen, Some(1_654_377_893));
    assert_eq!(assertion.last_seen, Some(1_772_841_600));
    assert_eq!(assertion.valid_until, Some(1_772_841_600 + 30 * DAY));
    assert_eq!(assertion.valid_from, None);
}

#[test]
fn urlhaus_gives_urls_from_columns_named_in_its_definition() {
    let parsed = shipped("urlhaus")
        .parse(include_bytes!("data/urlhaus.csv"), FETCHED)
        .expect("parsed");
    assert_eq!(parsed.indicators.len(), 2);
    let online = find(
        &parsed.indicators,
        Kind::Url,
        "http://203.0.113.7:8080/files/a.bin",
    );
    assert_eq!(online.confidence, 80);
    // Last online 2026-10-03 09:40:33.
    assert_eq!(online.valid_until, Some(1_791_020_433 + 14 * DAY));
    // The host is lowercased and the path is not; with no last online, the
    // day it was added counts.
    let offline = find(
        &parsed.indicators,
        Kind::Url,
        "https://files.example.net/dl/b.bin",
    );
    assert_eq!(offline.last_seen, None);
    assert_eq!(offline.valid_until, Some(1_790_928_000 + 14 * DAY));
}

#[test]
fn threatfox_gives_each_kind_with_its_own_confidence() {
    let parsed = shipped("threatfox")
        .parse(include_bytes!("data/threatfox.csv"), FETCHED)
        .expect("parsed");
    // The SHA3 row is of a kind the platform does not match.
    assert_eq!(
        (parsed.indicators.len(), parsed.ignored, parsed.rejected),
        (4, 1, 0)
    );
    // The port is dropped from the address.
    assert_eq!(
        find(&parsed.indicators, Kind::Ip, "203.0.113.7").confidence,
        75
    );
    let domain = find(&parsed.indicators, Kind::Domain, "c2.bad.example.com");
    assert_eq!(domain.confidence, 100);
    assert_eq!(domain.last_seen, Some(1_791_021_600));
    assert_eq!(
        find(
            &parsed.indicators,
            Kind::Url,
            "https://bad.example.com/gate"
        )
        .confidence,
        50
    );
    // A row without a confidence takes the feed's.
    assert_eq!(
        find(&parsed.indicators, Kind::Sha256, &"a".repeat(64)).confidence,
        50
    );
}

#[test]
fn sslbl_gives_certificate_fingerprints_from_unquoted_rows() {
    let parsed = shipped("sslbl")
        .parse(include_bytes!("data/sslbl.csv"), FETCHED)
        .expect("parsed");
    assert_eq!(parsed.indicators.len(), 2);
    let assertion = find(&parsed.indicators, Kind::CertificateHash, &"a".repeat(40));
    assert_eq!(assertion.first_seen, Some(1_791_008_828));
    assert_eq!(assertion.valid_until, Some(1_791_008_828 + 365 * DAY));
}

const STIX: &str = "name: partner\nconfidence: 60\nvalid_days: 90\nformat: stix\n";

#[test]
fn a_stix_bundle_gives_the_indicators_that_compare_for_equality() {
    let feed = Feed::from_yaml(STIX).expect("the definition loads");
    let parsed = feed
        .parse(include_bytes!("data/bundle.json"), FETCHED)
        .expect("parsed");
    // Ignored: the AND pattern, the revoked one, the Snort rule, and the
    // command line, which is no indicator kind.
    assert_eq!(
        (parsed.indicators.len(), parsed.ignored, parsed.rejected),
        (4, 4, 0)
    );
    let domain = find(&parsed.indicators, Kind::Domain, "bad.example.com");
    assert_eq!(domain.confidence, 85);
    // 2026-09-01 and 2026-12-01: its own validity, not the feed's 90 days.
    assert_eq!(domain.valid_from, Some(1_788_220_800));
    assert_eq!(domain.valid_until, Some(1_796_083_200));
    assert_eq!(domain.first_seen, Some(1_788_220_800));
    assert_eq!(domain.last_seen, Some(1_788_307_200));
    assert_eq!(
        find(&parsed.indicators, Kind::Ip, "203.0.113.7").confidence,
        85
    );
    // Without a confidence or an end of its own, the feed's.
    let hash = find(&parsed.indicators, Kind::Sha256, &"b".repeat(64));
    assert_eq!(hash.confidence, 60);
    assert_eq!(hash.valid_until, Some(1_788_220_800 + 90 * DAY));
    find(&parsed.indicators, Kind::Cidr, "198.51.100.0/24");
}

#[test]
fn a_feed_is_loaded_into_a_store_and_matched() {
    let store = MemoryStore::new();
    let loaded = shipped("threatfox")
        .load(
            &store,
            include_bytes!("data/threatfox.csv"),
            "2026-10-03T12:00:00Z",
            FETCHED,
        )
        .expect("loaded");
    assert_eq!((loaded.indicators, loaded.ignored), (4, 1));
    shipped("feodo-tracker")
        .load(
            &store,
            include_bytes!("data/feodo-tracker.csv"),
            "1",
            FETCHED,
        )
        .expect("loaded");

    let matcher = Matcher::new(store, Allowlists::default());
    let feeds = |at: i64| -> Vec<String> {
        matcher
            .lookup(Kind::Ip, "203.0.113.7", at)
            .expect("looked up")
            .into_iter()
            .flat_map(|hit| hit.assertions)
            .map(|assertion| format!("{} {}", assertion.feed, assertion.version))
            .collect()
    };
    // Feodo last saw it online in March; ThreatFox saw it today.
    assert_eq!(
        feeds(1_772_841_600),
        ["feodo-tracker 1", "threatfox 2026-10-03T12:00:00Z"]
    );
    assert_eq!(feeds(FETCHED), ["threatfox 2026-10-03T12:00:00Z"]);
    assert_eq!(feeds(FETCHED + 61 * DAY), [] as [&str; 0]);
}

#[test]
fn a_publication_that_is_not_the_feed_is_refused_and_the_store_kept() {
    let store = MemoryStore::new();
    let feed = shipped("feodo-tracker");
    feed.load(
        &store,
        include_bytes!("data/feodo-tracker.csv"),
        "1",
        FETCHED,
    )
    .expect("loaded");

    let half = "\"first_seen_utc\",\"dst_ip\",\"last_online\"\n\
        \"2026-01-01 00:00:00\",\"203.0.113.7\",\"2026-01-02\"\n\
        \"2026-01-01 00:00:00\",\"not an address\",\"2026-01-02\"\n";
    for (bytes, expected) in [
        (
            &b"<html>Service unavailable</html>"[..],
            "it has no column `dst_ip`",
        ),
        (b"# nothing today\n", "it has no column `dst_ip`"),
        (
            b"\"first_seen_utc\",\"dst_ip\",\"last_online\"\n",
            "it holds no indicator",
        ),
        (half.as_bytes(), "1 of 2 values cannot be of their kind"),
        (&[0xff, 0xfe][..], "it is not UTF-8"),
    ] {
        match feed.load(&store, bytes, "2", FETCHED) {
            Err(IntelError::Feed { feed, why }) => {
                assert_eq!(feed, "feodo-tracker");
                assert!(why.contains(expected), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }
    let stix = Feed::from_yaml(STIX).expect("the definition loads");
    for bytes in [&b"not json"[..], b"{\"type\": \"bundle\"}"] {
        assert!(matches!(
            stix.parse(bytes, FETCHED),
            Err(IntelError::Feed { .. })
        ));
    }

    // What was loaded before is still there, at its version.
    let kept = store
        .assertions(&Key::new(Kind::Ip, "203.0.113.7").expect("a key"))
        .expect("read");
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].version, "1");
}

#[test]
fn definitions_that_contradict_themselves_are_refused() {
    let csv = |body: &str| format!("name: a\nconfidence: 50\nformat: csv\n{body}");
    for (yaml, expected) in [
        (
            "name: a\nconfidence: 101\nformat: stix\n".to_owned(),
            "confidence is 0 to 100",
        ),
        (
            "name: a\nconfidence: 50\nrefresh_minutes: 0\nformat: stix\n".to_owned(),
            "refresh_minutes is at least 1",
        ),
        (csv(""), "the csv format needs `csv`"),
        (
            "name: a\nconfidence: 50\nformat: stix\ncsv: { value: v, kind: ip }\n".to_owned(),
            "`csv` is for the csv format",
        ),
        (csv("csv: { value: v }\n"), "`csv` needs `kind`"),
        (
            csv("csv: { value: v, kind: ip, kind_column: k, kinds: { a: ip } }\n"),
            "`csv` needs `kind`",
        ),
        (
            csv("csv: { value: v, kind_column: k }\n"),
            "`kinds` goes with",
        ),
        (
            csv("csv: { value: v, kind: ip, kinds: { a: ip } }\n"),
            "`kinds` goes with",
        ),
    ] {
        match Feed::from_yaml(&yaml) {
            Err(IntelError::Feed { why, .. }) => assert!(why.contains(expected), "{why}"),
            other => panic!("{yaml}: {other:?}"),
        }
    }
    for yaml in [
        "name: a\nformat: stix\n",
        "name: a\nconfidence: 50\nformat: xml\n",
        "name: a\nconfidence: 50\nformat: stix\nextra: 1\n",
    ] {
        assert!(matches!(Feed::from_yaml(yaml), Err(IntelError::Yaml(_))));
    }
}

#[test]
fn a_list_of_values_is_a_feed_of_one_column() {
    let feed = Feed::from_yaml(
        "name: list\nconfidence: 40\nformat: csv\ncsv: { columns: [value], value: value, kind: domain, comment: \";\" }\n",
    )
    .expect("the definition loads");
    let parsed = feed
        .parse(
            b"; a list\nbad.example.com\n\nworse.example.com \n",
            FETCHED,
        )
        .expect("parsed");
    assert_eq!(parsed.indicators.len(), 2);
    let assertion = find(&parsed.indicators, Kind::Domain, "worse.example.com");
    // No days of validity in the definition: it holds without end.
    assert_eq!((assertion.confidence, assertion.valid_until), (40, None));
}
