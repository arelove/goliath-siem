# 0005. Languages and process boundaries

- **Status:** Superseded in part by [ADR-0014](0014-one-language-for-services.md): services are Rust, playbooks declarative
- **Date:** 2026-09-21

## Context

At 1M events/s, hot path efficiency converts directly into the amount of
hardware every deployer must buy. Most of the system, however, is not on the
hot path.

## Decision

| Layer | Language | Rationale |
| --- | --- | --- |
| Match engine | **Rust** | CPU-bound, allocation-sensitive, needs control over memory layout and SIMD |
| Enrichment (embedded RocksDB) | **Rust** | Hot path; lives in the engine process |
| Collection, parsing, delivery | **Vector** (existing, Rust) | Do not rewrite what is written and battle-tested |
| Normalization to OCSF | **Rust** | Hot path; shares types with the engine |
| Control plane, API, orchestration | **Go** | Development speed, mature SDKs (Temporal, Kafka, ClickHouse) |
| Cases, IRP | **Go** | Not hot path, heavy on business logic |
| Playbooks (Temporal workers) | **Python** | Iteration speed, integration libraries |
| Detection content, entity resolution, UEBA, LLM layer | **Python** | Not hot path; ecosystem |
| Web interface | **TypeScript + React** | Virtualized rendering of large tables |

## Boundary rule

**Split by process, not by taste.** Each language owns its services and
communicates over Kafka or gRPC. Inside one service, one language.

**FFI and cgo between languages are forbidden.** Mixing runtimes inside a
process produces undebuggable crashes and breaks cross-platform builds. There
is exactly one exception: WASM plugins
([ADR-0004](0004-configuration-and-extensibility.md)), where the boundary is
specified and sandboxed.

## Published artifacts

Part of the code is useful outside this project and is published separately
from day one:

| Crate | Purpose |
| --- | --- |
| `goliath-ocsf` | OCSF types, validation, codecs |
| `goliath-sigma` | Sigma rule parsing into an AST |
| `goliath-sigma-clickhouse` | Sigma to ClickHouse SQL compilation |
| `goliath-match` | Predicate index, bitmap matching |

These four do not depend on the rest of the system. They provide early users
and real feedback before a platform exists.

## Consequences

- Four languages raise the barrier for contributors. Mitigated by making
  language boundaries coincide with top-level directories.
- Shared types (OCSF) are defined once and generated into Go, Python, and
  TypeScript from the schema so they cannot drift.

## When to revisit

Measurement shows the Go normalization service sustains the target throughput
with a 2x margin, making a move away from Rust worth the simplification.
