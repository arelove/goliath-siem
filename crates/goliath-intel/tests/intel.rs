//! Indicators in canonical form, feeds replaced whole, validity, and
//! allowlists that take precedence.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use goliath_intel::{
    Allowlist, Allowlists, Assertion, IntelError, Key, Kind, Matcher, MemoryStore, Store,
};

const NOW: i64 = 1_780_000_000;

fn key(kind: Kind, value: &str) -> Key {
    Key::new(kind, value).expect("a key")
}

fn allowlists(yaml: &[&str]) -> Allowlists {
    let lists: Vec<Allowlist> = yaml
        .iter()
        .map(|yaml| Allowlist::from_yaml(yaml).expect("a list"))
        .collect();
    Allowlists::new(&lists).expect("lists")
}

const INFRASTRUCTURE: &str = r#"
name: infrastructure
version: 3
entries:
  - { kind: ip, value: 8.8.8.8, reason: Public DNS resolver }
  - { kind: cidr, value: 10.0.0.0/8, reason: Internal network }
  - { kind: cidr, value: "2001:db8::/32", reason: Documentation range }
  - { kind: domain, value: "*.windowsupdate.com", reason: Windows Update }
  - { kind: domain, value: example.org, reason: Our own site }
"#;

#[test]
fn values_are_kept_in_one_spelling() {
    for (kind, given, canonical) in [
        (Kind::Ip, " 203.0.113.7 ", "203.0.113.7"),
        (Kind::Ip, "203[.]0[.]113[.]7", "203.0.113.7"),
        (Kind::Ip, "::ffff:203.0.113.7", "203.0.113.7"),
        (Kind::Ip, "2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        (Kind::Cidr, "203.0.113.77/24", "203.0.113.0/24"),
        (Kind::Cidr, "2001:db8:ffff::/32", "2001:db8::/32"),
        (Kind::Domain, "Bad.Example[.]COM.", "bad.example.com"),
        (
            Kind::Url,
            "hxxps://Bad.Example[.]com:8443/Path?Q=1#top",
            "https://bad.example.com:8443/Path?Q=1",
        ),
        // The port a scheme implies is dropped; another is kept.
        (
            Kind::Url,
            "http://Bad.Example.com:80/a",
            "http://bad.example.com/a",
        ),
        (
            Kind::Url,
            "https://bad.example.com:443",
            "https://bad.example.com",
        ),
        (
            Kind::Url,
            "http://bad.example.com:443/a",
            "http://bad.example.com:443/a",
        ),
        (
            Kind::Url,
            "http://203.0.113.7:8080/a",
            "http://203.0.113.7:8080/a",
        ),
        (Kind::Asn, "AS13335", "13335"),
        (Kind::Asn, "13335", "13335"),
        (
            Kind::Md5,
            "D41D8CD98F00B204E9800998ECF8427E",
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
        (Kind::Email, "Someone@Example.COM", "someone@example.com"),
        (
            Kind::NamedPipe,
            r"\\.\pipe\MSSE-1234-server",
            r"\\.\pipe\msse-1234-server",
        ),
    ] {
        let key = key(kind, given);
        assert_eq!(key.value(), canonical, "{kind} {given}");
        assert_eq!(key.kind(), kind);
    }
    // A network of one address is the address.
    let single = key(Kind::Cidr, "203.0.113.7/32");
    assert_eq!((single.kind(), single.value()), (Kind::Ip, "203.0.113.7"));
}

#[test]
fn values_that_cannot_be_of_their_kind_are_refused() {
    for (kind, given) in [
        (Kind::Ip, "203.0.113"),
        (Kind::Ip, ""),
        (Kind::Cidr, "203.0.113.0"),
        (Kind::Cidr, "203.0.113.0/33"),
        (Kind::Domain, "bad example.com"),
        (Kind::Domain, "https://bad.example.com/"),
        (Kind::Url, "bad.example.com/path"),
        (Kind::Asn, "ASN"),
        (Kind::Sha256, "d41d8cd98f00b204e9800998ecf8427e"),
        (Kind::Md5, "z41d8cd98f00b204e9800998ecf8427e"),
    ] {
        match Key::new(kind, given) {
            Err(IntelError::Value { .. }) => {}
            other => panic!("{kind} `{given}`: {other:?}"),
        }
    }
}

#[test]
fn kinds_have_names_and_tags_of_their_own() {
    let names: HashSet<&str> = Kind::ALL.iter().map(|kind| kind.as_str()).collect();
    let tags: HashSet<u8> = Kind::ALL.iter().map(|kind| kind.tag()).collect();
    assert_eq!(names.len(), Kind::ALL.len());
    assert_eq!(tags.len(), Kind::ALL.len());
    assert_eq!(
        key(Kind::Domain, "example.com").to_bytes(),
        [&[3u8][..], b"example.com"].concat()
    );
}

#[test]
fn a_hit_names_every_feed_that_asserts_the_indicator() {
    let store = MemoryStore::new();
    let domain = key(Kind::Domain, "bad.example.com");
    store
        .replace_feed(
            "feed-b",
            "7",
            [(
                domain.clone(),
                Assertion::new(60).seen(Some(100), Some(200)),
            )],
        )
        .expect("replaced");
    store
        .replace_feed(
            "feed-a",
            "2026-10-03",
            [
                (domain.clone(), Assertion::new(90)),
                (key(Kind::Sha256, &"ab".repeat(32)), Assertion::new(200)),
            ],
        )
        .expect("replaced");
    assert_eq!(store.len(), 2);

    let matcher = Matcher::new(store, Allowlists::default());
    let hits = matcher
        .lookup(Kind::Domain, "BAD.example.com.", NOW)
        .expect("looked up");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].indicator, domain);
    assert_eq!(hits[0].suppressed, None);
    assert_eq!(hits[0].confidence(), 90);
    let feeds: Vec<(&str, &str, u8)> = hits[0]
        .assertions
        .iter()
        .map(|assertion| {
            (
                assertion.feed.as_str(),
                assertion.version.as_str(),
                assertion.confidence,
            )
        })
        .collect();
    assert_eq!(feeds, [("feed-a", "2026-10-03", 90), ("feed-b", "7", 60)]);
    assert_eq!(hits[0].assertions[1].first_seen, Some(100));

    // Confidence is capped, and a name under the indicator is another name.
    let hash = matcher
        .lookup(Kind::Sha256, &"AB".repeat(32), NOW)
        .expect("looked up");
    assert_eq!(hash[0].confidence(), 100);
    assert_eq!(
        matcher
            .lookup(Kind::Domain, "www.bad.example.com", NOW)
            .expect("looked up"),
        []
    );
    // What an event holds need not be of its kind; it matches nothing.
    assert_eq!(matcher.lookup(Kind::Ip, "-", NOW).expect("looked up"), []);
}

#[test]
fn a_feed_is_replaced_whole_and_leaves_the_others() {
    let store = MemoryStore::new();
    let first = key(Kind::Ip, "203.0.113.7");
    let second = key(Kind::Ip, "203.0.113.8");
    store
        .replace_feed("feed-a", "1", [(first.clone(), Assertion::new(50))])
        .expect("replaced");
    store
        .replace_feed("feed-b", "1", [(first.clone(), Assertion::new(70))])
        .expect("replaced");
    let count = store
        .replace_feed(
            "feed-a",
            "2",
            [
                (second.clone(), Assertion::new(50)),
                // Named twice: the later assertion is kept.
                (second.clone(), Assertion::new(55)),
            ],
        )
        .expect("replaced");
    // Counted as given.
    assert_eq!(count, 2);

    let feeds = |key: &Key| -> Vec<(String, String, u8)> {
        store
            .assertions(key)
            .expect("read")
            .into_iter()
            .map(|assertion| (assertion.feed, assertion.version, assertion.confidence))
            .collect()
    };
    assert_eq!(feeds(&first), [("feed-b".to_owned(), "1".to_owned(), 70)]);
    assert_eq!(feeds(&second), [("feed-a".to_owned(), "2".to_owned(), 55)]);

    // A feed replaced with nothing asserts nothing.
    store.replace_feed("feed-b", "2", []).expect("replaced");
    assert_eq!(feeds(&first), []);
    assert_eq!(store.len(), 1);
}

#[test]
fn an_indicator_matches_only_while_it_holds() {
    let store = MemoryStore::new();
    store
        .replace_feed(
            "feed-a",
            "1",
            [
                (
                    key(Kind::Ip, "203.0.113.7"),
                    Assertion::new(50).valid(Some(1_000), Some(2_000)),
                ),
                (
                    key(Kind::Ip, "203.0.113.8"),
                    Assertion::new(50).valid(None, Some(2_000)),
                ),
            ],
        )
        .expect("replaced");
    let matcher = Matcher::new(store, Allowlists::default());
    let hits = |value: &str, at: i64| {
        matcher
            .lookup(Kind::Ip, value, at)
            .expect("looked up")
            .len()
    };
    assert_eq!(hits("203.0.113.7", 999), 0);
    assert_eq!(hits("203.0.113.7", 1_000), 1);
    assert_eq!(hits("203.0.113.7", 1_999), 1);
    assert_eq!(hits("203.0.113.7", 2_000), 0);
    assert_eq!(hits("203.0.113.8", 0), 1);
    assert_eq!(hits("203.0.113.8", 2_000), 0);
}

#[test]
fn an_address_matches_the_networks_that_hold_it() {
    let store = MemoryStore::new();
    store
        .replace_feed(
            "feed-a",
            "1",
            [
                (key(Kind::Cidr, "203.0.113.0/24"), Assertion::new(40)),
                (key(Kind::Cidr, "203.0.0.0/16"), Assertion::new(20)),
                (key(Kind::Ip, "203.0.113.7"), Assertion::new(90)),
                (key(Kind::Cidr, "2001:db8:1::/48"), Assertion::new(30)),
            ],
        )
        .expect("replaced");
    let matcher = Matcher::new(store, Allowlists::default());
    let indicators = |value: &str| -> Vec<String> {
        matcher
            .lookup(Kind::Ip, value, NOW)
            .expect("looked up")
            .into_iter()
            .map(|hit| hit.indicator.to_string())
            .collect()
    };
    // The address itself, then the longest prefix first.
    assert_eq!(
        indicators("203.0.113.7"),
        ["ip 203.0.113.7", "cidr 203.0.113.0/24", "cidr 203.0.0.0/16"]
    );
    assert_eq!(indicators("203.0.200.1"), ["cidr 203.0.0.0/16"]);
    assert_eq!(indicators("2001:db8:1::5"), ["cidr 2001:db8:1::/48"]);
    assert_eq!(indicators("198.51.100.1"), [] as [&str; 0]);
    assert_eq!(indicators("2001:db8:2::5"), [] as [&str; 0]);
}

#[test]
fn an_allowlist_suppresses_a_hit_and_says_which_entry_did() {
    let store = MemoryStore::new();
    store
        .replace_feed(
            "feed-a",
            "1",
            [
                (key(Kind::Ip, "8.8.8.8"), Assertion::new(100)),
                (key(Kind::Cidr, "10.1.0.0/16"), Assertion::new(100)),
                (key(Kind::Ip, "2001:db8::1"), Assertion::new(100)),
                (
                    key(Kind::Domain, "download.windowsupdate.com"),
                    Assertion::new(100),
                ),
                (key(Kind::Domain, "windowsupdate.com"), Assertion::new(100)),
                (
                    key(Kind::Domain, "notwindowsupdate.com"),
                    Assertion::new(100),
                ),
                (key(Kind::Domain, "www.example.org"), Assertion::new(100)),
                (key(Kind::Url, "https://example.org/a"), Assertion::new(100)),
                (
                    key(Kind::Url, "http://10.2.3.4:8080/a"),
                    Assertion::new(100),
                ),
                (
                    key(Kind::Url, "http://bad.example.com/a"),
                    Assertion::new(100),
                ),
            ],
        )
        .expect("replaced");
    let matcher = Matcher::new(store, allowlists(&[INFRASTRUCTURE]));
    let entry = |kind: Kind, value: &str| -> Option<String> {
        let hits = matcher.lookup(kind, value, NOW).expect("looked up");
        assert_eq!(hits.len(), 1, "{value}");
        hits[0].suppressed.as_ref().map(|allowed| {
            assert_eq!(allowed.list, "infrastructure");
            assert_eq!(allowed.version, 3);
            allowed.entry.clone()
        })
    };
    // However confident the feed, the entry wins, and the hit is returned.
    assert_eq!(entry(Kind::Ip, "8.8.8.8").as_deref(), Some("8.8.8.8"));
    // An allowed address is allowed in the network indicator that holds it.
    assert_eq!(entry(Kind::Ip, "10.1.2.3").as_deref(), Some("10.0.0.0/8"));
    assert_eq!(
        entry(Kind::Ip, "2001:db8::1").as_deref(),
        Some("2001:db8::/32")
    );
    // `*.name` allows the name and every name under it, and nothing that
    // only ends with the same letters.
    assert_eq!(
        entry(Kind::Domain, "download.windowsupdate.com").as_deref(),
        Some("*.windowsupdate.com")
    );
    assert_eq!(
        entry(Kind::Domain, "windowsupdate.com").as_deref(),
        Some("*.windowsupdate.com")
    );
    assert_eq!(entry(Kind::Domain, "notwindowsupdate.com"), None);
    // A plain domain allows itself alone.
    assert_eq!(entry(Kind::Domain, "www.example.org"), None);
    // A host that is allowed allows its URLs.
    assert_eq!(
        entry(Kind::Url, "https://EXAMPLE.org/a").as_deref(),
        Some("example.org")
    );
    assert_eq!(
        entry(Kind::Url, "http://10.2.3.4:8080/a").as_deref(),
        Some("10.0.0.0/8")
    );
    assert_eq!(entry(Kind::Url, "http://bad.example.com/a"), None);

    let reason = matcher.lookup(Kind::Ip, "8.8.8.8", NOW).expect("looked up")[0]
        .suppressed
        .clone()
        .expect("suppressed")
        .reason;
    assert_eq!(reason, "Public DNS resolver");
}

#[test]
fn allowlists_that_cannot_be_used_are_refused() {
    let list = |yaml: &str| Allowlist::from_yaml(yaml).expect("a list");
    let named = "name: a\nversion: 1\nentries: []\n";
    for (lists, expected) in [
        (vec![list(named), list(named)], "another list has this name"),
        (
            vec![list(
                "name: a\nversion: 1\nentries:\n  - { kind: ip, value: 8.8.8.8, reason: \" \" }\n",
            )],
            "`8.8.8.8` has no reason",
        ),
        (
            vec![list(
                "name: a\nversion: 1\nentries:\n  - { kind: ip, value: \"*.example.com\", reason: x }\n",
            )],
            "is not a ip",
        ),
    ] {
        match Allowlists::new(&lists) {
            Err(IntelError::Allowlist { list, why }) => {
                assert_eq!(list, "a");
                assert!(why.contains(expected), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }
    // An unknown member or kind is refused when the file is read.
    for yaml in [
        "name: a\nversion: 1\nentries: []\nextra: 1\n",
        "name: a\nversion: 1\nentries:\n  - { kind: colour, value: red, reason: x }\n",
        "name: a\nversion: 1\nentries:\n  - { kind: ip, value: 8.8.8.8 }\n",
    ] {
        assert!(matches!(
            Allowlist::from_yaml(yaml),
            Err(IntelError::Yaml(_))
        ));
    }
    assert_eq!(allowlists(&[INFRASTRUCTURE]).len(), 5);
}
