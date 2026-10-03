# goliath-intel

Threat intelligence for the [Goliath](https://github.com/arelove/goliath-siem)
security platform: indicators in one canonical spelling, what every feed
asserts of each, allowlists that take precedence, and the lookup an event's
observables go through.

- **Canonical keys.** `Bad.Example[.]COM.` in a feed and `bad.example.com` in
  an event are one key. Addresses, networks, domains, URLs, hashes, and
  fingerprints each have one spelling, and a value that cannot be of its kind
  is refused when a feed is loaded.
- **Provenance.** An indicator keeps the assertion of every feed that names
  it: the feed, its version, the confidence, and from when until when it
  holds. Feeds are never merged into one flat set.
- **Feeds are replaced whole.** A reader sees a feed as it was or as it is.
- **Networks.** An address matches itself and every network indicator that
  holds it, longest prefix first.
- **Allowlists win.** An entry suppresses a hit whatever the feeds say. The
  hit is still returned, with the entry that suppressed it, so that it is
  recorded. A network allows its addresses, `*.name` allows a domain and
  every name under it, and an allowed host allows its URLs.

## Feeds

A feed is a YAML file: where it is published, how its rows are read, the
confidence of its indicators, and for how long one holds after the feed last
saw it. Two formats are read: rows of separated values, which covers lists of
one value a line, and STIX 2.1 bundles, of which the indicators whose pattern
compares for equality are taken.

| Shipped definition | Feed | Indicators |
| --- | --- | --- |
| `feeds/feodo-tracker.yaml` | abuse.ch Feodo Tracker | Addresses of botnet command and control servers |
| `feeds/urlhaus.yaml` | abuse.ch URLhaus, recent | URLs distributing malware |
| `feeds/threatfox.yaml` | abuse.ch ThreatFox, recent | Addresses, domains, URLs, and file hashes, each with its own confidence |
| `feeds/sslbl.yaml` | abuse.ch SSLBL | SHA-1 fingerprints of certificates |

A publication that is not the feed is refused whole and the store keeps what
it had: an error page in place of the file, a format that changed, no
indicator at all, or more than one value in ten that cannot be of its kind.

`examples/intel_feed.rs` reads a downloaded publication with a definition
and says what it became, to check a definition against the feed as it is
today. This crate reads publications; fetching them on a schedule is the
detector's.

## Stores

Two stores hold indicators behind one trait:

- `MemoryStore`, for tests and small sets.
- `RocksStore`, behind the `rocksdb` feature, for sets too large for memory:
  RocksDB in the process, with a bloom filter in memory in front, so that a
  lookup of what no feed names does not reach the disk. A feed is replaced
  by writing a new generation beside the old and naming it current in one
  write, in bounded memory whatever the feed's size. Building it needs a C++
  compiler and libclang.

On one core of a laptop, with 10^7 indicators in `RocksStore`
(`examples/intel_lookup.rs`): a lookup that finds nothing takes about 0.4
microseconds, one that finds its indicator 4 to 6, loading runs at about a
million indicators a second, the filter takes 24 MiB and the store 580 MB,
and opening the full store takes 5 seconds. The 10^8 run is the exit
measurement of M4.

See [ADR-0008](../../docs/adr/0008-threat-intelligence-model.md),
[ADR-0020](../../docs/adr/0020-state-beyond-events.md), and
[ADR-0021](../../docs/adr/0021-enrichment-placement.md).

```rust
use goliath_intel::{Allowlists, Assertion, Key, Kind, Matcher, MemoryStore, Store};

let store = MemoryStore::new();
store.replace_feed(
    "example-feed",
    "2026-10-03",
    [(Key::new(Kind::Domain, "Bad.Example[.]com")?, Assertion::new(80))],
)?;
let matcher = Matcher::new(store, Allowlists::default());
let hits = matcher.lookup(Kind::Domain, "bad.example.com.", 1_780_000_000)?;
assert_eq!(hits[0].assertions[0].feed, "example-feed");
# Ok::<(), goliath_intel::IntelError>(())
```
