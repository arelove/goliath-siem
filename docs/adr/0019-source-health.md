# 0019. Source health

- **Status:** Accepted
- **Date:** 2026-09-30

## Context

A source that stops sending is the failure a SIEM hides best: every search
over its events still answers, with nothing, and an investigation learns of
the gap when it needs the events most. A source that sends records the
platform cannot read is the same failure, one step later. M3.5 promises, for
each source, the last event seen, its rate against its own baseline, and its
dead letters, so that both are noticed first.

Four facts shape the design:

- Every stored event and dead letter carries its source and `received`, when
  the platform took it ([ADR-0013](0013-event-storage.md)). `received` is the
  platform's clock, so a source cannot move it.
- Answering from the stored rows costs too much. At the M3 rate, 100,000
  events a second, seven days of events are about 60 billion rows; counting
  them by source and hour reads every one, and search limits a query to far
  fewer ([ADR-0016](0016-event-search.md)).
- Sources are uneven. A domain controller writes thousands of events a
  minute, Okta a few, and Microsoft 365 delivers its audit log in batches,
  sometimes hours late. Most sources follow the working day. One fixed rate
  or silence threshold fits none of them.
- Roles may run in separate processes ([ADR-0006](0006-deployment-topology.md)).
  Only the store sees every source's events, whichever process wrote them.

## Decision

**Count events and dead letters by source and hour as they are stored, in
ClickHouse, and judge each source against the same hour of its previous
seven days.**

### Counting

Two tables hold, per source and hour of `received`, the events stored and
the time of the last, and per source, stage, and hour, the dead letters and
the time of the last. A materialized view fills each on every insert into
`events` or `dead_letters`, so no role does anything new and nothing is
counted twice by processes that share a store. They are summed and maxed as
ClickHouse merges them. They keep five weeks: the baseline needs eight days,
and the rest shows a trend at no cost worth measuring, a row per source and
hour.

An event delivered twice counts twice until ClickHouse merges its copies in
`events`; the counts, like the overview's, are for looking at, not for
audit. The counts start when the migration runs: stored events are not
counted again, and a source's baseline fills over its first week.

### Judging

For each source, at the time of the question:

- **Last event:** the latest `received` of its events.
- **Last hour:** its events in the last complete hour.
- **Baseline:** the median of its events in the same hour of each of the
  seven days before. The median ignores one unusual day, and the same hour
  follows the working day. Hours with no events count as zero. With fewer
  than three of those days since counting began, there is no baseline.
- **Dead letters:** in the last complete hour and the last day, by stage.

Its status is the first of these that holds:

| Status | When |
| --- | --- |
| `rejecting` | Dead letters in the last hour are at least 10, and at least 1% of its records |
| `waiting` | No event stored in five weeks |
| `silent` | No event for longer than its `silent_after_minutes`, 60 unless set |
| `low` | A baseline of at least 20 an hour, and the last hour below a quarter of it |
| `high` | A baseline of at least 20 an hour, and the last hour above four times it |
| `learning` | No baseline yet |
| `ok` | Otherwise |

A source whose every record fails has no events, so `rejecting` is judged
before `waiting` and `silent`, which would hide why. Below 20 an hour, a rate
is too small to compare; silence and dead letters still count. `silent_after_minutes` is per source, for sources that deliver
late or seldom, such as Microsoft 365.

### Serving

The API answers `GET /sources` with every source it knows: those in its
configuration, and those with counted events. The interface shows them as a
table, the ones needing attention first.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Query `events` by source and hour on each request | No new tables | Reads every event of eight days | Refused |
| Counters in each role's Prometheus metrics | Already there; alerting rules in Prometheus | Counts reset with a process and are split across processes; no history for a baseline without Prometheus, which the platform does not require | Kept for operators who run Prometheus; not the answer |
| A role that counts on a schedule and writes the counts | Counting logic in Rust | A new moving part, which lags and can stop | Refused: ClickHouse counts on insert |
| Mean of the last 24 hours as the baseline | Simple | A night looks like an outage and a morning like a flood | Refused |
| Same hour of the previous seven days, median | Follows the working day; one odd day does not move it | Needs a week to settle; a holiday reads as low | Chosen |
| Five-minute steps | Finer rates | Twelve times the rows; silence is judged from the last event anyway | Hours, until a user needs finer |

## Consequences

- Silence and unreadable records are visible from the API and the
  interface without Prometheus, and without reading events.
- Two tables and two views join the schema. A migration cannot be undone,
  and a later change to what is counted is a new view.
- A holiday, or a quiet weekend hour, can read as `low`. The status says how
  a source compares with itself, not that something is wrong; the numbers
  beside it say by how much.
- The status is computed when asked. Nothing alerts on it yet; alerts
  belong to detection.

## When to revisit

If a source's status is wrong for more than one day in seven on real data,
such as a weekly pattern read as `low` each weekend, compare with the same
hour one and two weeks before. If an operator needs an alert on silence
before detection can raise one, export the status as a metric.
