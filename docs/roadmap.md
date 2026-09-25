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
| Scheduler | Windowed detections over ClickHouse, incremental materialized views |
| Alert model | Deduplication, grouping, severity, provenance to the source event |
| Detection content | An initial rule pack, each rule with true and false positive fixtures |

**Exit criterion:** p99 latency from ingestion to alert under 5 seconds on the
streaming path at target throughput, and every shipped rule passing its
fixtures in CI.

## M6 - Response

| Deliverable | Detail |
| --- | --- |
| Case service | Cases, tasks, observables, state machine, audit with hash chaining |
| Playbook runtime | Temporal workers, human-in-the-loop signals, action plugins |
| RBAC and tenancy | Row-level security, per-tenant quotas and backpressure |

**Exit criterion:** an alert becomes a case, a playbook executes with an
approval step, and every state transition appears in a tamper-evident audit
log.

## M7 - Interface

| Deliverable | Detail |
| --- | --- |
| Investigation view | Virtualized event tables, entity pivots, timeline |
| Case workspace | Triage queue, case detail, playbook status |
| Coverage dashboard | Framework coverage and collection capability |
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

M1 is publishable on its own. The Sigma crates and the matching engine are
useful to anyone already running ClickHouse, which is how the project gets its
first users before a platform exists.

M3 precedes M4 and everything after deliberately. Building enrichment and
detection before the measurement rig means optimizing against intuition, and
every later performance claim would be unfounded.

M6 and M7 can overlap; neither blocks the other.
