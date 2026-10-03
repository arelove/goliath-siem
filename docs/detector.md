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
| `threads` | Threads that match a batch at once; every core if left out |
| `cache_mebibytes` | The block cache of the indicator store; 1024 if left out |
| `feeds.definition` | The name of a shipped definition, or the path of a YAML file |
| `feeds.url` | Where the publication is fetched from; the definition's own URL if left out |
| `feeds.file` | The file the publication is read from. With a file and no `url`, nothing is fetched |

The shipped definitions are abuse.ch Feodo Tracker, URLhaus, ThreatFox, and
SSLBL: `feodo-tracker`, `urlhaus`, `threatfox`, `sslbl`.

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
- A fetch that fails is tried again after five minutes. A publication that is
  not the feed, such as an error page or a changed format, is refused whole.
  Either way the store keeps what it had, and matching goes on.

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
| `goliath_feed_refreshes_total{feed,result}` | Publications asked for: `loaded`, `refused` as not the feed, or `failed` to be fetched |
| `goliath_feed_indicators{feed}` | Indicators the feed asserts. A sudden fall is a feed that changed |
| `goliath_indicator_hits_total{status}` | Matches `reported` and `suppressed` |
| `goliath_detected_events_total`, `goliath_detected_observables_total` | What the detector looked at |
| `goliath_reader_lag_records{topic="normalized",reader="detector"}` | Events the detector has yet to look at |

A stale feed in Prometheus, for a feed fetched every 30 minutes:

```text
time() - goliath_feed_checked_timestamp_seconds{feed="urlhaus"} > 3 * 30 * 60
```

## Finding the findings

A finding is an event of class 2004 from the source `goliath-intel`. It names
the feeds that assert the indicator in `osint`, and the event it was found
in, with the attribute that held the value, in `evidences`. Its time is the
event's.
