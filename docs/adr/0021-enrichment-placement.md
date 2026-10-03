# 0021. Where indicators are matched and context is added

- **Status:** Accepted
- **Date:** 2026-10-03

## Context

M4 matches the indicators of [ADR-0008](0008-threat-intelligence-model.md)
against every event and adds the context that makes an alert actionable: whose
asset, which network, which curated list. Neither ADR-0008 nor
[ADR-0020](0020-state-beyond-events.md) says where in the pipeline that
happens, or what a match becomes. This record decides both, and replaces the
M4 exit criterion "no measurable reduction in throughput" with one that can
be measured.

The facts that shape it:

- The pipeline has four roles that carry events, `collector`, `receiver`,
  `normalizer`, and `writer`, and no `detector`. The roadmap adds the
  detector in M5.
- [architecture.md](../architecture.md) keeps the detector out of the write
  path: a slow rule or a crashed detector delays alerts and never stops
  events from being stored.
- A normalizer may run in a branch or a DMZ
  ([ADR-0006](0006-deployment-topology.md)). An indicator set of 10^8
  entries is several gigabytes, and feeds under commercial terms may not
  leave the central site.
- Stored events are rows of a `ReplacingMergeTree`. Adding a hit to a stored
  event later is a mutation, which rewrites parts.
- An indicator often arrives after the event it describes: a domain reported
  today was contacted last week. A match made only as events arrive never
  finds it.
- Normalized events carry no `observables` today. The attributes that hold
  addresses, names, and hashes are typed in the OCSF schema the platform
  already ships.
- The matching engine takes about 8 microseconds of a core for an event. A
  bloom filter test is tens of nanoseconds; a read from a local RocksDB block
  cache is a few microseconds; a read from disk is tens to hundreds.

## Decision

**Match indicators and add context in a `detector` role that reads the event
topic beside the writer; write each match as a finding of its own; never
rewrite a stored event.**

### The detector

- The `detector` role arrives in M4 with indicator matching alone. M5 adds
  the rule engine to the same role, so rules and indicators share one reader
  of the event topic, one finding model, and one place where context is
  added.
- It reads the event topic as its own group, as an observer. The writer does
  not wait for it, and it resumes from its own offset after a restart
  ([ADR-0015](0015-pipe-semantics.md)).
- It holds the indicator store of ADR-0020: RocksDB in the process, with a
  bloom filter for each indicator type in front.

### Observables

- The detector takes observables from the typed attributes of each event:
  addresses, host names, URLs, file hashes, email addresses, and the other
  types of ADR-0008. Which attributes of a class hold them is a table built
  from the OCSF schema, so it cannot drift from the event structure.
- They are not written into the stored event. A source that supplies its own
  `observables` keeps them.

### A match is a finding

- A match becomes an OCSF Detection Finding, class 2004:
  - `osint` holds one entry for each feed that asserted the indicator: its
    value and type, the feed and its version, the confidence, and the
    validity. This is the provenance ADR-0008 requires.
  - `evidences` names the event matched, by its identifier, time, and class,
    and the observable that matched.
  - `enrichments` holds the context added.
- The finding's identifier is derived from the event's identifier and the
  indicator. An event read twice after a restart gives the same finding, and
  the store keeps one.
- A match an allowlist suppresses is written the same way, with the status
  Suppressed and the allowlist entry that suppressed it. That is the record
  of suppressions ADR-0008 asks for, kept as events.
- Findings go to a `findings` topic. The writer reads it as it reads events
  and stores them in the same table, so a finding is searched like any event.
- A finding is taken when its event was: its receipt time is the event's.
  The two are then kept for the same time, and a finding made twice, as the
  event arrived and from the store, falls in the same partition and is
  stored once.

### Context

- Context comes from the snapshot of `goliath-enrich`: assets, users,
  networks, and the lists typed as context. It is added to findings, and in
  M5 to alerts, not to every event.
- Context for events in a search, such as the owner of an address in a result
  row, is left until the interface needs it. ClickHouse dictionaries built
  from the same snapshot can supply it without changing stored events.

### Indicators that arrive late

When a feed refresh adds indicators, a scheduled query looks for the new keys
alone in the stored events of the hot retention, and writes the same
findings. The stream match and this query together cover events before and
after the indicator arrived.

### Events the detector was moved past

An observer that falls further behind than the topic keeps is moved forward.
The events between are stored and were not matched.

- The detector notes the range of receipt time they lie in: from the last
  record it matched to the first it was moved to. The range is kept in a
  file beside the indicator store, so a restart forgets none.
- The range is widened by a minute at both ends. Records are not in the
  topic in the exact order they were taken, and the writer keeps several
  inserts in flight.
- When the store holds an event taken after the range, the writer is past
  it. The detector then reads the range back, a minute of receipt time at
  once, and matches those events as it matches arriving ones. The finding is
  the same, so an event matched twice is stored once.
- This needs the event store. A detector with no `[store]` counts and notes
  the ranges, and they wait.

### Exit criterion for M4

Measured on the rig with the detector reading a topic filled beforehand, so
that generating events takes no CPU from it. Runs are made at 10^6 and 10^8
indicators, with 45% IPv4 addresses, 30% domains, 15% URLs, and 10% SHA-256
hashes, and with a planted match in 0.1% and in 1% of events. Each figure is
the median of five runs whose spread is within 5% of it.

| Measure | Threshold |
| --- | --- |
| Events a second a core, warm | At least 90% of the same run with 10^3 indicators |
| Correctness | Every planted match found; no finding beyond them; every allowlisted match stored as Suppressed |
| Memory of the detector at 10^8 | At most 2 GiB resident |
| Disk at 10^8 | At most 8 GiB |
| Cold start | The warm rate reached within 60 seconds of a start with an empty page cache; the first minute's rate reported |
| Feed refresh | While 10^7 indicators are replaced, at least 80% of the warm rate; a new indicator matches within 30 seconds of the refresh |
| Write path | The writer's rate does not change when the detector is stopped or stalled |

The thresholds are budgets set before the first measurement. A budget the
measurement misses is reported with the measurement, and either the design or
the budget changes by a record like this one.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| In the normalizer, hits stored in the event | A hit is seen in the event itself | Feed lookups and refreshes join the write path; every normalizer, in a branch or a DMZ, needs the whole indicator set; a hit is fixed at ingestion | Refused |
| In the writer | One place; hits stored in the event | The write path again; rules in M5 cannot read the hits | Refused |
| A separate role that writes an enriched topic for the writer and the detector | Storage and rules both see hits | Every event is written to the pipe twice, and disk is the bottleneck of ingestion; storage waits for enrichment | Refused |
| At search time only | No cost at ingestion; feeds always current | No finding as events arrive; a join against 10^8 indicators in a query | Kept for indicators that arrive late, as a query over the new keys |
| In the detector, each match a finding | The write path untouched; indicators stay with the detector; M5's rules join the same role | A hit is not in the event; the interface joins a finding to its event | Chosen |

## Consequences

- The detector role and the finding model arrive one milestone early. M5
  adds rules, correlation, and the alert model on top of them.
- Every match is a finding. At a 1% match rate that is 1% more rows, and one
  address contacted ten thousand times is ten thousand findings; grouping
  them is the alert model of M5.
- The interface shows a finding with its event by a second lookup. The
  `evidences` entry carries the class and time of the event, which are the
  first two columns of the table's order, so the lookup reads one granule.
- The exit run needs a generator of indicators and of events with planted
  matches, added to `goliath-gen` and the rig.
- A finding names the feed version that matched. A later correction of the
  feed does not change findings already written; they say what was known
  when the event was read.

## When to revisit

If reading a range back is measured to be slower than events arrive, the
detector never catches up from the store: read by partition and class in
parallel, or give the detector cores. If the interface's lookups from
findings to events take more than 100 milliseconds at the 95th percentile,
store the matched event's summary in the finding. If searches by context on events are asked for before M6, decide the
ClickHouse dictionaries then. If a deployment must match in the branch,
before events reach the centre, a detector there with a feed subset is the
answer, not matching in the normalizer.
