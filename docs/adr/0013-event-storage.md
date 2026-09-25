# 0013. Event storage layout

- **Status:** Accepted
- **Date:** 2026-09-25

## Context

[ADR-0002](0002-storage-stack.md) puts events in ClickHouse, and
[ADR-0003](0003-data-boundary.md) makes them immutable, delivered at least once
and deduplicated, and deleted only by TTL on whole partitions. What was left
open is how an OCSF event becomes a row.

OCSF 1.5.0 has 81 classes and 161 objects, and a single class such as Process
Activity reaches thousands of attribute paths through nested objects. Sources
add `unmapped` members of their own. Sigma rules and hunting queries filter on
arbitrary paths such as `process.parent_process.cmd_line`.

ClickHouse has had a native `JSON` column type since 25.3: each path is
stored as a column of its own, typed per value, up to a configurable number of
paths per part.

## Decision

Store every event in one `events` table: a few typed columns for sorting,
partitioning, and deduplication, and the whole OCSF event in one `JSON` column.

| Column | Purpose |
| --- | --- |
| `received` | When the platform took the record. Partition key and retention |
| `time` | The event's own time, or `received` when it has none that fits |
| `class_uid`, `category_uid`, `type_uid`, `activity_id`, `severity_id` | Classification, repeated from the event for the sorting key |
| `id` | The record's content identity from `goliath-normalize` |
| `source`, `source_version`, `kind` | Which definition produced the event, per ADR-0007 |
| `event` | The OCSF event as normalized, including `unmapped` |
| `issues` | Values that did not convert |

`ENGINE = ReplacingMergeTree`, `PARTITION BY toDate(received)`,
`ORDER BY (class_uid, time, id)`.

### Retention follows `received`, not `time`

`time` is written by the source. If partitions and TTL followed it, an attacker
who controls a log line could date an event years back and have it deleted on
the next merge, or date it far ahead to keep a partition alive. `received` is
the platform's own clock. Queries still filter on `time`, which the sorting key
covers within each class.

### Deduplication by content identity

Each event carries a 128-bit BLAKE3 hash of its source name and raw bytes.
The same record delivered twice gets the same `id`, the same `class_uid`, and
the same `time`, so ReplacingMergeTree keeps one row after merges, and a query
with `FINAL` sees one row at once. The hash is cryptographic because the input
is attacker-controlled: with a fast non-cryptographic hash, a crafted record
could collide with another and have it dropped as a duplicate.

Two limits are accepted. Deduplication works within a partition, so a copy
delivered after midnight UTC of the day the first arrived is kept twice. And
an event whose time did not convert takes `received` as its `time`, so its
copies differ in the key and are all kept. Both keep an extra row; neither
loses one.

### Migrations

The schema is a sequence of forward-only migrations compiled into the binary,
one statement each, applied by the binary at startup and recorded with a
checksum. ClickHouse has no transactional DDL, so a migration of several
statements could stop halfway; one statement cannot. Every statement is
repeatable (`IF NOT EXISTS`), so a migration that ran but was not recorded, or
that two processes start at once, does no harm. An applied migration whose text
changed, or a database migrated by a newer build, stops startup.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| One table, typed keys plus a `JSON` column | Any path queryable as a column; one schema for every class; new OCSF versions need no migration | Paths beyond the per-part limit share a slower fallback column; needs ClickHouse 25.3 or later | **Accepted** |
| One table per class with typed columns | Fastest scans, exact types | 81 tables of thousands of columns, a migration for every schema version, extensions need tables of their own | No |
| Flattened `Map(String, String)` | Works on any ClickHouse version | Every value a string, every path read reads the whole map | No |
| Event as a `String` of JSON | Simplest | Every filter parses every row | No |
| Partition and TTL by `time` | Natural for queries | Lets source content decide when evidence is deleted | No, see above |

## Consequences

- Any OCSF path, including `unmapped` members, is queryable without a schema
  change; the Sigma to ClickHouse compiler can target `event.<path>` directly.
- `max_dynamic_paths` is 1024 per part. A part whose events use more paths
  stores the rest in a shared column that is slower to read. The limit can be
  raised with a migration, and hot paths can be given explicit types when
  measurements call for it.
- ClickHouse 25.8 is the oldest supported server; CI tests against it and the
  newest release.
- Retention is deployment configuration, not schema: the store sets it as a
  TTL on `received` for events and dead letters alike, deleting whole days as
  partitions, and leaves it alone when it is already what was asked for.
- The distributed topology needs `ON CLUSTER` and replicated engines; that is
  a separate migration path, decided when the topology is built.

## When to revisit

- A measured workload shows filters on paths beyond `max_dynamic_paths` in a
  part, or on untyped paths, taking more than twice as long as on typed ones.
- Duplicates surviving deduplication exceed 0.1% of rows on a real source.
