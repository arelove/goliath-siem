# The detector: matching indicators

The detector reads normalized events beside the writer, looks their values up
among the indicators of the configured feeds, and stores each match as a
Detection Finding beside the events. It never changes a stored event. The
decision is [ADR-0021](adr/0021-enrichment-placement.md); the indicator model
is [ADR-0008](adr/0008-threat-intelligence-model.md).

## Configuring it

Add `detector` to `roles`, and name the feeds:

```toml
roles = ["collector", "normalizer", "detector", "writer", "api"]
data = "/var/lib/goliath/data"

[detector]
allowlists = ["/etc/goliath/allow/infrastructure.yaml"]

# A shipped definition, fetched from the URL it names.
[[detector.feeds]]
definition = "urlhaus"

[[detector.feeds]]
definition = "threatfox"

# A definition of your own, with its publication put on disk by other means.
[[detector.feeds]]
definition = "/etc/goliath/feeds/partner.yaml"
file = "/var/lib/goliath/feeds/partner.json"
```

| Setting | Meaning |
| --- | --- |
| `state` | The directory of the indicator store; `intel` in `data` if left out |
| `allowlists` | YAML files of what is never reported |
| `context.definition` | The YAML file that says how an export of the site is read |
| `context.file` | The export: what the site knows of its networks, machines, or accounts |
| `threads` | Threads that match a batch at once; every core if left out |
| `cache_mebibytes` | The block cache of the indicator store; 1024 if left out |
| `look_back_days` | The days of stored events matched against indicators a feed adds; 7 if left out, and never with 0 |
| `look_back_every_hours` | The least time from one look back to the next; 24 if left out |
| `feeds.definition` | The name of a shipped definition, or the path of a YAML file |
| `feeds.url` | Where the publication is fetched from; the definition's own URL if left out |
| `feeds.file` | The file the publication is read from. With a file and no `url`, nothing is fetched |

The shipped definitions are abuse.ch Feodo Tracker, URLhaus, ThreatFox, and
SSLBL: `feodo-tracker`, `urlhaus`, `threatfox`, `sslbl`; and three reference
lists, below.

## Reference lists

Some lists worth matching are not feeds of a provider but files in a
repository that people curate. Three ship as definitions, all from
[mthcht/awesome-lists](https://github.com/mthcht/awesome-lists), which is
under the MIT licence:

| Definition | What it holds | Confidence |
|---|---|---|
| `loldrivers` | Hashes of drivers that are vulnerable or malicious, from the LOLDrivers project | 80 |
| `malicious-bootloaders` | Hashes of bootloaders that are malicious or let Secure Boot be passed | 80 |
| `tor-exit-nodes` | The addresses Tor's traffic leaves the network from | 40 |

- Each is pinned to a commit of the repository: its definition names the
  commit as `revision`, and fetches the file as it was then. A finding names
  that commit as the feed's version, so it says which list matched and
  which state of it.
- A pinned list does not change by itself. To take a newer one, copy the
  definition from `crates/goliath-intel/feeds`, set `revision` to the newer
  commit, and name the copy's path as `definition`. A release of Goliath
  moves the shipped pins.
- A match with a Tor exit node is not an attack: it says that the other end
  hides where it is. Leave the definition out where people have a use for
  Tor, or keep it and read its findings by their confidence.
- Other lists of that repository describe a value and do not accuse it.
  They are context, not indicators: see [lists used as
  context](#lists-used-as-context).

## How a feed is kept current

- A fetched feed is asked for every `refresh_minutes` of its definition. The
  server is told which publication the detector has, and answers that it is
  unchanged without sending it again.
- What is fetched is kept in `publications` in the store's directory. A
  restart within the feed's interval fetches nothing.
- A feed is fetched over HTTPS. HTTP is accepted from this host alone: a
  publication fetched in the clear could be replaced on the way.
- A feed given as a `file` is read at start and whenever the file changes. A
  site without internet access puts the file there by other means: write it
  under another name and rename it.
- At a start, no event is matched until every feed was looked at once: an
  event matched against a store still empty would not be matched again.
  Events wait in the topic meanwhile, and storage does not wait for them.
- A restart does not load again a publication the store already holds: it
  is known by when it was written and its length. Matching starts as soon
  as the store is open.
- A fetch that fails is tried again after five minutes. A publication that is
  not the feed, such as an error page or a changed format, is refused whole.
  Either way the store keeps what it had, and matching goes on.

## Context: what the site knows

A finding says that an event held an indicator. What makes it worth an
analyst's time is what no feed knows: whose machine it is, which network the
address is in, whether the account is privileged. The detector reads that
from files the site exports, and adds it to every finding. The decision is
[ADR-0022](adr/0022-context-snapshot.md).

```toml
[[detector.context]]
definition = "/etc/goliath/context/cmdb.yaml"
file = "/var/lib/goliath/context/cmdb.csv"

[[detector.context]]
definition = "/etc/goliath/context/networks.yaml"
file = "/var/lib/goliath/context/networks.csv"
```

A definition reads the export under its own column names, so the export is
used as the CMDB, the directory, or the IPAM writes it:

```yaml
name: cmdb
kind: asset
format: csv
identifiers:
  host: [hostname, fqdn]
  address: [ip_address]
fields:
  owner: owner_email
  org: business_unit
  criticality: tier
criticality: { gold: 4, silver: 3, bronze: 2 }
labels:
  pci_scope: pci
  information_system: system
```

- The kinds are `network`, `asset`, `identity`, `group`, and `list`. Each
  has a few typed fields, named as OCSF names them; anything else the site
  keeps is a label under the site's own name. The whole of a definition is
  in the [crate's README](../crates/goliath-enrich/README.md).
- The detector looks up the addresses, host names, user names, and email
  addresses of a matched event, and writes each record found into the
  finding's `enrichments`: the value, the kind of record, the source as
  `provider`, and the record's fields and labels as `data`, with when the
  export was written as `source_version`.
- An address is also found by the narrowest network that holds it. A value
  nothing knows gets no entry.
- Two sources that describe one thing give two entries. Nothing is merged,
  so the finding says who said what.
- An export is read at start and whenever the file changes. Write it under
  another name and rename it. An export that is not what its definition
  describes is refused whole, and the source stays as it was.
- A record may say from when and until when it holds. Context is looked up
  for the time of the event, so an account closed before the event is found
  with `ended` set, and that is often the finding.
- Events are not changed. Context is in findings only, at most 32 entries
  in each.

Not built yet: a scope for sites that use one address range twice, and the
snapshot on disk. The snapshot is in memory, which is enough for some
hundreds of thousands of records.

### Lists used as context

Some lists describe a value and do not accuse it: the domains of dynamic
DNS providers, public resolvers that answer DNS over HTTPS, the ranges of
VPN providers. Matched as indicators they would raise a finding for
ordinary traffic. A feed definition that says `use: context` is fetched,
pinned, and kept current as any feed, and its values go to the context: it
is added to the findings other feeds raise, and never raises one.

```toml
[[detector.feeds]]
definition = "dynamic-dns"
```

| Definition | What it holds | The row's label |
|---|---|---|
| `dynamic-dns` | Domains under which anyone can register a name | The provider |
| `dns-over-https` | Public resolvers that answer DNS over HTTPS | The kind of resolver |

- Both are from [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists)
  and pinned to a commit, which is the `source_version` of their entries.
- A host name is described by a list that names a domain above it, so
  `a.b.mooo.com` is found by `mooo.com`. An address is found by a range
  that holds it.
- A definition of your own takes `use: context`, and `label` in its `csv`
  for the column that says what a row is.
- Its values are addresses, ranges, and domains. Rows of other kinds are
  left out.

## Allowlists

```yaml
name: infrastructure
version: 3
entries:
  - { kind: ip, value: 8.8.8.8, reason: Public DNS resolver }
  - { kind: cidr, value: 10.0.0.0/8, reason: Internal network }
  - { kind: domain, value: "*.windowsupdate.com", reason: Windows Update }
```

An entry wins over every feed. The match is still stored, as a finding with
the status Suppressed and the entry that suppressed it, so that what was
suppressed can be reviewed. Every entry needs a reason.

## What to watch

On the metrics endpoint:

| Metric | Meaning |
| --- | --- |
| `goliath_feed_checked_timestamp_seconds{feed}` | When the feed was last known to be current. Alarm when it is older than a few of the feed's intervals: the feed is stale |
| `goliath_feed_refreshes_total{feed,result}` | Publications asked for: `loaded`, `unchanged` since it was loaded before a restart, `refused` as not the feed, or `failed` to be fetched |
| `goliath_feed_indicators{feed}` | Indicators the feed asserts. A sudden fall is a feed that changed |
| `goliath_context_written_timestamp_seconds{source}` | When the export last loaded was written. Alarm when it is older than twice the export's period: an export that stopped leaves context that is quietly old |
| `goliath_context_refreshes_total{source,result}` | Exports looked at after a change: `loaded`, or `refused` as not what the definition describes |
| `goliath_context_records{source}` | Records the source holds. A sudden fall is an export that lost rows |
| `goliath_finding_enrichments_total` | Entries of context added to findings |
| `goliath_indicator_hits_total{status}` | Matches `reported` and `suppressed` |
| `goliath_detected_events_total`, `goliath_detected_observables_total` | What the detector looked at |
| `goliath_reader_lag_records{topic="normalized",reader="detector"}` | Events the detector has yet to look at |
| `goliath_detector_skipped_records_total` | Events stored but not matched as they arrived. Above zero, the detector is too slow for the rate: give it threads or cores |
| `goliath_detector_unmatched_ranges` | Ranges of receipt time that wait to be matched from the store. Alarm when it stays above zero |
| `goliath_detector_rematched_events_total` | Events read back from the store and matched, for either reason |
| `goliath_detector_look_back_remaining_seconds` | Receipt time a look back has yet to read; zero when none runs |

A stale feed in Prometheus, for a feed fetched every 30 minutes:

```text
time() - goliath_feed_checked_timestamp_seconds{feed="urlhaus"} > 3 * 30 * 60
```

## The detector never slows storage

The detector reads the event topic as an observer: the normalizer and the
writer never wait for it. A detector that is stopped, or slower than the
events arrive, falls behind. Within the topic's bound it catches up and
misses nothing. Beyond it, it is moved forward past the oldest events, which
are stored like every other and were not matched; the count is
`goliath_detector_skipped_records_total`.

The detector then matches those events from the store:

- It notes the range of receipt time they lie in, in `unmatched.json` in the
  store's directory. A restart forgets none.
- When the writer is past the range, it reads the range back from ClickHouse
  and matches it. The findings are the ones it would have made as the events
  arrived, and an event matched twice gives one finding.
- This needs a `[store]` section in the configuration of the process that
  runs the detector. Without one the ranges are noted, and wait.
- A range waits for an event taken after it to be stored. With no events
  arriving, it waits until one does.

A detector that is too slow all the time never catches up this way either:
`goliath_detector_unmatched_ranges` stays above zero. Give it threads or
cores.

## Indicators that arrive late

An indicator often arrives after the event it describes: a domain reported
today was contacted last week. When a feed adds indicators, the detector
looks back over the stored events for them:

- It reads the events taken in the last `look_back_days` and reports only
  indicators added since the last look back. What was reported as the
  events arrived is not reported again.
- The finding is the one the event would have given, with the time and the
  receipt time of the event. Search for findings by when they were made, in
  `finding_info.created_time`, to see what a look back found.
- A look back reads every event of those days once. That costs the store
  one read of them and the detector the time to match them, so it begins at
  most every `look_back_every_hours`, and covers all that feeds added in
  between.
- A detector started for the first time finds every indicator new, and looks
  back for all of them.
- Events the detector was moved past are read first.
- It needs a `[store]` section, like the matching of what the detector
  missed.

At a rate where a look back takes longer than the time between two, lower
`look_back_days` or raise `look_back_every_hours`:
`goliath_detector_look_back_remaining_seconds` shows how far one has come.

## Finding the findings

A finding is an event of class 2004 from the source `goliath-intel`. It names
the feeds that assert the indicator in `osint`, and the event it was found
in, with the attribute that held the value, in `evidences`. Its time is the
event's, and it is kept as long as the event: retention counts from when the
event was taken.
