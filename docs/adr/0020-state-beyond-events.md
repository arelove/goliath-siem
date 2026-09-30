# 0020. State beyond the event store

- **Status:** Proposed
- **Date:** 2026-09-30

## Context

From M4 on, the platform keeps state that is not events: indicators and their
provenance, entity and asset snapshots, the identity decisions of the entity
graph, the windows of stream correlation, cases, and playbook runs.
[ADR-0002](0002-storage-stack.md) maps these workloads to engines: indicator
lookup (W14) and correlation windows (W4) to embedded RocksDB, entities,
cases, playbooks, and access control (W5 to W10) to PostgreSQL.
[ADR-0008](0008-threat-intelligence-model.md) adds feed configuration,
indicator metadata, and allowlists to PostgreSQL. Neither engine runs yet;
only ClickHouse does. This record checks that map against what M4 to M6 need
now, and decides what ADR-0002 does not: when each engine arrives, and how
the hot path uses RocksDB.

Five facts shape it:

- The target is 1,000,000 events a second a cluster
  ([architecture.md](architecture.md)), and the matching engine alone takes
  about 8 microseconds of a core per event. A round trip to a database server
  on the same network is 100 to 500 microseconds, so one per event would
  cost more than everything else the event goes through.
  [ADR-0003](0003-data-boundary.md) already forbids a network call per event.
- Stream correlation, M5, updates state for most events: a count per user
  and window, a sequence waiting for its next step. At the M3 rate that is
  about 100,000 state writes a second, and ten times that at the target. A single PostgreSQL server commits tens of thousands of small
  transactions a second.
- Indicator sets reach 10^8 per node in M4's exit criterion and 10^9 in
  ADR-0008. Held in memory as a hash map of keys and provenance they need
  tens of gigabytes; on disk, compressed, with an in-memory filter in front,
  a few.
- Some state must change together and be undone: merging two identities in
  the graph and splitting them again, a case moving through its states, a
  playbook step recorded exactly once. That is what transactions are for,
  and it is written at human and alert rates, not event rates.
- A second database server is a second thing to install, back up, upgrade,
  and secure. M8's exit criterion is that a stranger runs the platform
  against their own logs within ten minutes.

RocksDB was built on this machine for the decision: `rocksdb` 0.25 compiles
on Rust 1.89 under Windows with LLVM's libclang in 1 minute 45 seconds from
clean, once per build directory.

## Decision

**Keep state an event passes through in RocksDB, embedded in the process
that reads it; keep state people and workflows change in PostgreSQL, from
M4.5, when the first such state exists; and run M4 without PostgreSQL.**

### By workload

| Workload | Milestone | Rate | Needs | Home |
| --- | --- | --- | --- | --- |
| Indicator lookup, with provenance | M4 | Every observable of every event | Local reads in microseconds; whole feeds replaced at once | RocksDB |
| Entity and asset snapshot | M4 | Every event | Local reads; refreshed in bulk | RocksDB |
| Stream correlation windows and sequences | M5 | Most events | Local writes at event rate; expiry; recovery consistent with the pipe | RocksDB |
| Scheduled correlation over history | M5 | Per schedule | Scans of stored events | ClickHouse, as SQL |
| Indicator hits, suppressions, alerts | M4, M5 | Per hit | Searchable with events | ClickHouse, as events |
| Feed configuration, allowlists | M4 | Per change | Reviewed, versioned, diffable | Files, as content beside rules |
| Identity decisions of the entity graph | M4.5 | Per merge or split | Transactions; reversible; audited | PostgreSQL |
| Cases, playbook runs, assignments | M6 | Per action | Transactions; state machines; exactly once | PostgreSQL |
| Users, roles, tenants | M6 | Per change | Strong consistency; row-level security | PostgreSQL |

### RocksDB, on the hot path

- **Provenance travels with the indicator.** The value of each key holds
  every feed that asserted it, with version, confidence, and validity, so a
  hit is reported with its provenance from the one read that found it.
  Nothing on the hot path asks another store.
- **Feeds are replaced, not edited.** A refresh builds sorted files away from
  the hot path and ingests them in one step, so a reader sees the old feed
  or the new one, never half of each. Expired indicators are dropped as
  files are compacted.
- **Correlation state commits with its position.** In M5, the state a batch
  of events changed and the pipe offset after it are written in one write
  batch, so a restarted detector resumes where its state says, with nothing
  counted twice ([ADR-0015](0015-pipe-semantics.md)). Checkpoints, hard
  links to immutable files, copy it without stopping.
- One database a process, a column family a kind of state, so the three
  workloads share one engine, one set of tuning, and one backup method.

### PostgreSQL, off the hot path

- It arrives with M4.5's identity decisions, the first state that must
  change transactionally and be undone, and carries M6's cases after them.
- No code path that runs per event reads it, as ADR-0003 says. What the hot
  path needs from it, such as an entity snapshot, is exported to RocksDB.

### M4 without it

ADR-0008 put feed configuration, indicator metadata, and allowlists in
PostgreSQL. Until PostgreSQL runs:

- Feeds and allowlists are files, loaded and checked at start like source
  definitions, and changed by review like rules. ADR-0008 already asks for
  allowlists "as first-class, versioned, auditable content alongside rules".
- Indicator metadata is the provenance in the RocksDB value.
- Every suppression by an allowlist is recorded as an event in ClickHouse,
  which is the audit ADR-0008 asks for.

An interface that edits feeds and allowlists, with its audit of who changed
what, moves them to PostgreSQL when it is built, and exports them to files or
to RocksDB for the hot path.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| PostgreSQL for indicators and correlation | One store; SQL; transactions | A network call per event; tens of thousands of commits a second against hundreds of thousands of writes | Refused |
| ClickHouse for correlation state | Already running | Built for large inserts and scans; a point update is a mutation, and small inserts become parts to merge | Refused for streams; kept for scheduled correlation |
| Valkey as shared hot state | Shared between nodes | A network call per event; state lost with memory unless persisted, then slower | Refused for the hot path; kept for what ADR-0002 gives it, deduplication, rate limits, and locks (W12) |
| In-memory maps only | Fastest reads | Tens of gigabytes at 10^8 indicators; state lost on restart, so correlation windows restart empty | Refused beyond small sets |
| Immutable sorted files (`fst`) for indicators | Pure Rust; compact; fastest reads | No updates between rebuilds; no answer for correlation state, so a second engine for M5 | Refused: one engine for all three |
| fjall, a pure-Rust LSM store | No C++ build | Younger; fewer years under production write loads | Revisit if the C++ build becomes a burden |
| redb, a pure-Rust B-tree store | No C++ build; simple | One writer; write amplification at event rates | Refused for correlation |
| RocksDB | Point reads in microseconds; bulk ingestion; write batches; checkpoints; expiry by compaction; used for stream state by Kafka Streams and Flink | A C++ build that needs libclang; tuning to learn | Chosen for the hot path |
| PostgreSQL now, for M4 configuration | ADR-0008 as written | A second server for what files hold as well, before anything needs a transaction | Deferred to M4.5 |

## Consequences

- M4 adds no server to install: the platform is still one binary and
  ClickHouse, with RocksDB inside the binary.
- Building the crates that use RocksDB needs a C++ compiler and libclang.
  They are separate crates, so the Sigma crates published on crates.io do not
  depend on it.
- RocksDB state is per node. Correlation on a key needs every event with that
  key on the same node, which M5 must provide by partitioning the pipe by key
  ([ADR-0015](0015-pipe-semantics.md) uses one partition a topic today).
- ADR-0002's map stands. ADR-0008's storage table holds from M4.5 on;
  until then its PostgreSQL rows are files and events, as above.

## When to revisit

If the C++ build costs contributors more than it saves, measure fjall
against RocksDB on the M4 indicator benchmark and the M5 correlation
benchmark, and switch if it is within 20% on both. If correlation on one node
cannot keep up and keys cannot be partitioned, revisit shared state.
