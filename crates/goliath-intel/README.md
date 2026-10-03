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

The store here is in memory. The store for 10^8 indicators, RocksDB behind
bloom filters, follows; see
[ADR-0008](../../docs/adr/0008-threat-intelligence-model.md),
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
