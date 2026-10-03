//! The store on disk: what the store in memory does, kept across a restart
//! and at a size that crosses its write chunks.

#![cfg(feature = "rocksdb")]
#![allow(clippy::expect_used)]

use goliath_intel::{Allowlists, Assertion, Key, Kind, Matcher, RocksStore, Store};

const NOW: i64 = 1_780_000_000;

fn key(kind: Kind, value: &str) -> Key {
    Key::new(kind, value).expect("a key")
}

fn open(directory: &tempfile::TempDir) -> RocksStore {
    RocksStore::open_with(directory.path(), 8 << 20).expect("opened")
}

fn feeds(store: &impl Store, key: &Key) -> Vec<(String, String, u8)> {
    store
        .assertions(key)
        .expect("read")
        .into_iter()
        .map(|assertion| (assertion.feed, assertion.version, assertion.confidence))
        .collect()
}

#[test]
fn feeds_are_replaced_whole_and_kept_across_a_restart() {
    let directory = tempfile::tempdir().expect("a directory");
    let first = key(Kind::Ip, "203.0.113.7");
    let second = key(Kind::Ip, "203.0.113.8");
    {
        let store = open(&directory);
        store
            .replace_feed(
                "feed-b",
                "7",
                [(
                    first.clone(),
                    Assertion::new(70)
                        .valid(Some(1_000), None)
                        .seen(Some(100), Some(200)),
                )],
            )
            .expect("replaced");
        store
            .replace_feed("feed-a", "1", [(first.clone(), Assertion::new(50))])
            .expect("replaced");
        // Ordered by feed, each with its own version.
        assert_eq!(
            feeds(&store, &first),
            [
                ("feed-a".to_owned(), "1".to_owned(), 50),
                ("feed-b".to_owned(), "7".to_owned(), 70)
            ]
        );
        let count = store
            .replace_feed(
                "feed-a",
                "2",
                [
                    (second.clone(), Assertion::new(50)),
                    (second.clone(), Assertion::new(55)),
                ],
            )
            .expect("replaced");
        assert_eq!(count, 2);
        assert_eq!(
            feeds(&store, &first),
            [("feed-b".to_owned(), "7".to_owned(), 70)]
        );
        assert_eq!(
            feeds(&store, &second),
            [("feed-a".to_owned(), "2".to_owned(), 55)]
        );
        // The same version given again replaces as any other.
        store
            .replace_feed("feed-a", "2", [(second.clone(), Assertion::new(60))])
            .expect("replaced");
    }

    let store = open(&directory);
    assert_eq!(
        store.feeds(),
        [
            ("feed-a".to_owned(), "2".to_owned(), 1),
            ("feed-b".to_owned(), "7".to_owned(), 1)
        ]
    );
    assert_eq!(
        feeds(&store, &second),
        [("feed-a".to_owned(), "2".to_owned(), 60)]
    );
    let kept = store.assertions(&first).expect("read");
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].valid_from, kept[0].valid_until),
        (Some(1_000), None)
    );
    assert_eq!(
        (kept[0].first_seen, kept[0].last_seen),
        (Some(100), Some(200))
    );

    // A feed replaced with nothing asserts nothing.
    store.replace_feed("feed-b", "8", []).expect("replaced");
    assert_eq!(feeds(&store, &first), []);
    assert!(store.replace_feed("", "1", []).is_err());
}

#[test]
fn a_feed_larger_than_a_write_is_found_whole_and_nothing_else_is() {
    let directory = tempfile::tempdir().expect("a directory");
    let store = open(&directory);
    let before = store.filter_bytes();
    let name = |index: u32| format!("host-{index}.example.com");
    let count = store
        .replace_feed(
            "feed-a",
            "1",
            (0..25_000u32).map(|index| (key(Kind::Domain, &name(index)), Assertion::new(50))),
        )
        .expect("replaced");
    assert_eq!(count, 25_000);
    // The filter grew for the feed: about 10 bits an indicator, twice over.
    assert!(store.filter_bytes() > before);
    assert!(store.filter_bytes() < 25_000 * 4);

    let matcher = Matcher::new(store, Allowlists::default());
    for index in (0..25_000).step_by(97) {
        let hits = matcher
            .lookup(Kind::Domain, &name(index).to_uppercase(), NOW)
            .expect("looked up");
        assert_eq!(hits.len(), 1, "{index}");
    }
    for index in 25_000..27_000 {
        assert_eq!(
            matcher
                .lookup(Kind::Domain, &name(index), NOW)
                .expect("looked up"),
            []
        );
    }
}

#[test]
fn networks_are_matched_and_kept_across_a_restart() {
    let directory = tempfile::tempdir().expect("a directory");
    let indicators = |store: RocksStore, value: &str| -> Vec<String> {
        Matcher::new(store, Allowlists::default())
            .lookup(Kind::Ip, value, NOW)
            .expect("looked up")
            .into_iter()
            .map(|hit| hit.indicator.to_string())
            .collect()
    };
    {
        let store = open(&directory);
        store
            .replace_feed(
                "feed-a",
                "1",
                [
                    (key(Kind::Cidr, "203.0.113.0/24"), Assertion::new(40)),
                    (key(Kind::Cidr, "2001:db8:1::/48"), Assertion::new(30)),
                    (key(Kind::Ip, "203.0.113.7"), Assertion::new(90)),
                ],
            )
            .expect("replaced");
        assert_eq!(
            indicators(store, "203.0.113.7"),
            ["ip 203.0.113.7", "cidr 203.0.113.0/24"]
        );
    }
    assert_eq!(
        indicators(open(&directory), "2001:db8:1::5"),
        ["cidr 2001:db8:1::/48"]
    );
    assert_eq!(
        indicators(open(&directory), "198.51.100.1"),
        [] as [&str; 0]
    );
}
