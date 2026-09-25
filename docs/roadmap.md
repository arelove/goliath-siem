# Roadmap

Delivery order follows the wedge strategy in
[architecture.md](architecture.md): ship the matching engine first as a
standalone, independently useful artifact, then grow the platform around parts
that already have users.

Milestones are sequenced by dependency, not by date. Each states an exit
criterion that is measurable, so "done" is not a judgement call.

## Current milestone

**M2 - Ingestion path.** In progress. The matching engine of M1 works end to
end against the whole SigmaHQ repository and is published; its 10-million-event
corpus run is still open. Normalization and storage exist; transport and the
roles that connect them are next.

## M0 - Foundations

Make the repository able to hold work.

| Deliverable | Detail |
| --- | --- |
| Cargo workspace | Crate layout, shared lints, MSRV policy |
| CI | Build, test, clippy, rustfmt, MSRV, link check on docs, prose policy |
| `goliath-ocsf` | OCSF event envelope, validation, serialization, observable types |
| Releases | Changelog and versioned releases through release pull requests |

**Exit criterion:** `cargo test` passes on Linux, macOS, and Windows in CI, and
an OCSF event round-trips through serialization with schema validation.

**Status:** done. Two planned items were dropped or moved:

- A license header check: Apache 2.0 does not require a header in every file,
  and the root `LICENSE` covers the repository.
- The test corpus: it moved to M1, where the exit criterion first needs one.

## M1 - Matching engine

The differentiator. Built standalone and publishable without the rest of the
platform existing.

| Deliverable | Detail |
| --- | --- |
| `goliath-sigma` | Sigma rule parsing into a typed AST, full modifier support |
| Field mapping | Sigma fields and log sources resolved to OCSF paths at load time, with case folding ([ADR-0012](adr/0012-sigma-field-mapping.md)) |
| Reference evaluator | One rule against one event, written for obvious correctness rather than speed |
| `goliath-match` | Predicate index, rule grouping, bloom prefiltering, bitmap evaluation |
| `goliath-sigma-clickhouse` | Sigma to ClickHouse SQL compilation for the scheduled path |
| Benchmark harness | Instruction counts under Callgrind, compared with the base of each pull request and gated in CI ([benchmarks.md](benchmarks.md)) |
| M1 corpus | Labelled OTRF Security-Datasets recordings converted to OCSF, replicated to 10 million events |

**Exit criterion:** 1,000 Sigma rules evaluated over a 10-million-event corpus
at a measured and published events/s per core, with results identical to
one-rule-at-a-time evaluation on the same corpus.

The M1 corpus is deliberately not the M3 generator. It is real telemetry,
replicated for volume, so it is good enough to check equivalence and measure
the engine against itself; it cannot stand in for the entity-model stream when
measuring the platform.

## M2 - Ingestion path

Get real events into real storage.

| Deliverable | Detail |
| --- | --- |
| `goliath-pipe` | Transport abstraction: in-process, local queue, Kafka, S3 ([ADR-0006](adr/0006-deployment-topology.md)) |
| `goliath-normalize` | Four-stage source definitions with dead-letter routing ([ADR-0007](adr/0007-source-and-parser-model.md)) |
| Source definitions | Sysmon, Linux auditd, Falco, Entra ID sign-in logs |
| ClickHouse schema | OCSF tables, sort keys, partitioning, TTL, skip indexes |
| Migrations | Forward-only, versioned, applied by the binary |

**Exit criterion:** events flow from a real source to a queryable ClickHouse
table in both single-process and fully distributed topologies, with the same
integration suite passing against both.

**Status:** started. `goliath-normalize` runs declarative source definitions
with dead-letter routing, checked against the OCSF schema, and its Sysmon
definition feeds the SigmaHQ regression run. `goliath-store` writes its events
and dead letters to ClickHouse under versioned migrations
([ADR-0013](adr/0013-event-storage.md)), tested in CI against real servers.
Transport, retention, and the other sources are next.

## M2.5 - Event search

A first slice of the M7 interface, pulled forward: stored events become
something a person can see and use as soon as they exist.

| Deliverable | Detail |
| --- | --- |
| Search API | The first service of the `api` role, in Rust per [ADR-0014](adr/0014-one-language-for-services.md): time range, class, and filters on any OCSF path checked against the schema, compiled to parameterized ClickHouse queries, read-only |
| Search view | The first TypeScript and React code of the `ui` role: a virtualized event table and an event detail with the full OCSF record |
| Demo path | One command that normalizes a Sysmon recording, stores it, and opens the view |

**Exit criterion:** a Sysmon event written to the source is visible in the
search view within five seconds, and a search over 10 million stored events
filtered by time, class, and one path returns in under one second.

The view is built as the base of the M7 investigation view, not as a
throwaway: its table, filters, and event detail are what M7 extends with
entity pivots and the timeline.

## M3 - Benchmark rig

Without this, nothing after it can be honestly measured.

| Deliverable | Detail |
| --- | --- |
| Entity-model generator | N users and M hosts, daily cycles, Zipf activity, same entity under different identifiers per source |
| Replay engine | Real datasets time-shifted to now, with a speed multiplier |
| Attack injector | Labelled chains at known offsets, producing ground truth |
| Metrics report | Events/s per core, latency percentiles, compression ratio, precision and recall |

**Exit criterion:** a single command produces a reproducible report covering
every metric listed in [architecture.md](architecture.md#benchmark-method),
and a 30-minute run sustains 100k events/s on one developer machine.

## M4 - Context

Enrichment that makes an alert actionable rather than a row.

| Deliverable | Detail |
| --- | --- |
| `goliath-intel` | STIX 2.1 model, feed connectors, bloom-prefiltered RocksDB lookup, allowlists, provenance ([ADR-0008](adr/0008-threat-intelligence-model.md)) |
| `goliath-attack` | Versioned framework loader, technique mapping, coverage versus capability ([ADR-0009](adr/0009-attack-knowledge-model.md)) |
| `goliath-enrich` | Entity and asset snapshot into local RocksDB, refresh scheduling |

**Exit criterion:** 10^8 indicators matched against the event stream with no
measurable reduction in throughput, and an ATT&CK Navigator layer exported that
distinguishes covered techniques from techniques lacking a data source.

## M5 - Detection service

| Deliverable | Detail |
| --- | --- |
| Streaming detector | The match engine as a role, with rule hot reload |
| Correlation in the stream | Sigma correlation rules (event count, value count, temporal, ordered temporal) evaluated as events arrive, with window state in RocksDB, not only as scheduled SQL |
| Backtesting | Any rule run over stored history before it is enabled: how often it would have fired, on which events, and how many alerts a day it would add |
| Scheduler | Windowed detections over ClickHouse, incremental materialized views |
| Alert model | Deduplication, grouping, severity, provenance to the source event |
| Detection content | An initial rule pack, each rule with true and false positive fixtures |

**Exit criterion:** p99 latency from ingestion to alert under 5 seconds on the
streaming path at target throughput, and every shipped rule passing its
fixtures in CI; a correlation rule fires in the stream on the same events as
its scheduled SQL form; a backtest of one rule over 30 days of stored events
finishes in under a minute.

## M6 - Response

| Deliverable | Detail |
| --- | --- |
| Case service | Cases, tasks, observables, state machine, audit with hash chaining |
| Playbook runtime | Declarative playbooks with durable state in PostgreSQL, human-in-the-loop approvals, built-in, WASM, and sidecar actions; engine chosen by ADR under the single-binary constraint ([ADR-0014](adr/0014-one-language-for-services.md)) |
| RBAC and tenancy | Row-level security, per-tenant quotas and backpressure |

**Exit criterion:** an alert becomes a case, a playbook executes with an
approval step, and every state transition appears in a tamper-evident audit
log.

## M7 - Interface

| Deliverable | Detail |
| --- | --- |
| Investigation view | Virtualized event tables, entity pivots, timeline |
| Case workspace | Triage queue, case detail, playbook status |
| Coverage dashboard | The landing view: for each ATT&CK technique, whether a rule covers it, whether the data that rule needs is being collected, and whether it fired in its last backtest; a technique with a rule but no data is shown as uncovered |
| Configuration | Source onboarding with dry-run plan preview |

**Exit criterion:** an analyst completes triage of an alert into a closed case
without leaving the interface.

## M8 - First public release

| Deliverable | Detail |
| --- | --- |
| Single-binary mode | Embedded substitutes, working system in under a minute |
| Installation paths | Docker Compose, Helm chart, plain binary |
| Documentation | Operator guide, source authoring guide, rule authoring guide |
| Published benchmarks | Full report with reproduction instructions |

**Exit criterion:** a person who has never seen the project runs it against
their own logs within ten minutes, following only the README.

## Sequencing notes

Three capabilities are what the platform is meant to be chosen for, beyond
speed and openness: backtesting a rule against history before it runs,
correlation evaluated in the stream rather than on a schedule, and coverage
that counts a technique as covered only when its data is collected. They are
placed in M5 and M7, but everything before them is built so they are cheap:
the engine is exact against a reference evaluator, stored events keep every
path queryable, and configuration is checked against the schema.

M1 is publishable on its own. The Sigma crates and the matching engine are
useful to anyone already running ClickHouse, which is how the project gets its
first users before a platform exists.

M3 precedes M4 and everything after deliberately. Building enrichment and
detection before the measurement rig means optimizing against intuition, and
every later performance claim would be unfounded.

M6 and M7 can overlap; neither blocks the other.
