# 0002. Storage stack

- **Status:** Accepted
- **Date:** 2026-09-21
- **Amended:** 2026-09-25, playbook state no longer assumes Temporal
  ([ADR-0014](0014-one-language-for-services.md))

## Context

Storage had to be chosen for 1M events/s alongside transactional subsystems
(cases, RBAC, orchestration). The choice was driven by a map of workloads, not
by comparing benchmarks.

## Decision

Two server engines (ClickHouse, PostgreSQL), one cache (Valkey), one open
format (S3/Iceberg), and two embedded engines (RocksDB, DuckDB).

## Workload map

| # | Workload | Profile | Home |
| --- | --- | --- | --- |
| W1 | Event storage | Append-only, columnar scan | ClickHouse |
| W2 | Interactive search | High selectivity, low latency | ClickHouse |
| W3 | Detection execution | Windowed SQL plus streaming | ClickHouse and match engine |
| W4 | Correlation windows | Ephemeral, very high churn | RocksDB (embedded) |
| W5 | Entities and ontology | Mutable, joined | PostgreSQL |
| W6 | IRP cases | Transactional state machine | PostgreSQL |
| W7 | Playbook execution state | Durable workflow state | PostgreSQL |
| W8 | RBAC and tenancy | Strong consistency | PostgreSQL (row-level security) |
| W9 | Audit log | Append-only, tamper-evident | PostgreSQL plus hash chain |
| W10 | Graph traversal | 2-4 hops | PostgreSQL (recursive CTEs) |
| W11 | Vector search for LLM retrieval | HNSW | PostgreSQL (pgvector) |
| W12 | Dedup, rate limits, locks | Shared ephemeral state | Valkey |
| W13 | Cold archive | 12+ months, cheap | S3 plus Parquet/Iceberg |
| W14 | Per-event indicator lookup | 10⁶-10⁹ indicators at 1M/s | RocksDB (embedded) |

W1 and W6 are opposites: immutable petabyte scans against transactional updates
of small records. No single engine serves both well, which eliminates the
single-database option before any comparison.

PostgreSQL covers six workloads (W5-W11) in one engine. Volumes there are
millions of rows, not trillions. Splitting those across six specialized stores
is an operational tax paid by everyone who deploys the system.

## Options considered (columnar layer)

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| ClickHouse | 10-30x compression on logs, unmatched scan throughput, incremental materialized views, mature S3 tiering, proven on petabyte-scale logging | Weak joins, asynchronous mutations, manual resharding in the open-source build, Keeper to operate | **Accepted** |
| StarRocks | Better joins (cost-based optimizer, runtime filters), primary key model with real upserts, native Iceberg | Worse compression on logs, unproven at petabyte-scale logging, smaller community | Only serious alternative; revisit if joins become the bottleneck |
| Doris | Simpler to deploy | Weaker optimizer | No |
| Druid, Pinot | Sub-second streaming queries, rich indexing | JVM, many node types, tuned for user-facing analytics rather than logs | No - operational cost is not repaid |
| Elasticsearch, OpenSearch | Best free-text search available | JVM, 3-5x worse storage efficiency, much slower aggregations, shard management at 1M events/s | No as primary store |
| DuckDB | Excellent reader for Parquet and Iceberg on S3 | Single node, not a server, no concurrent writers | Not a storage tier - a tool |

### The cost of dropping Elasticsearch, stated plainly

We lose some free-text search quality. This is mitigated by bloom-filter skip
indexes on tokenized fields and by the ClickHouse full-text index, which is
maturing but is not an equal of a dedicated inverted index.

Acceptable, because the overwhelming majority of SIEM search is filtering on
structured fields rather than grepping free text. We state this in the README
rather than omitting it.

## The role of DuckDB

Not a storage tier. An embedded library in three places:

1. Querying the cold tier on S3 without standing up Trino or Spark.
2. **Detection CI** - running rules against sample data in seconds.
3. Edge pre-aggregation at collectors.

## What we deliberately exclude

**A graph database.** Bounded-depth traversals (2-4 hops) are served by
recursive CTEs. Neo4j lacks clustering in its community edition and Memgraph
ships under BSL; both create a licensing obstacle to enterprise adoption.

**A dedicated vector database.** The corpus (runbooks, prior cases, rule
documentation) is thousands of chunks. pgvector with HNSW covers it without an
additional component.

**Redis on the hot path.** At 1M events/s this would be a million network round
trips per second. Valkey serves shared state only, and is chosen over Redis for
its BSD license, which removes a legal obstacle to corporate deployment.

## Consequences

Every additional engine is a component the user must operate. For an
open-source project that is a direct deduction from installed base. Four
components is a deliberate ceiling.

## When to revisit

- Entity joins at query time become the measured bottleneck → evaluate StarRocks.
- Free-text search enters the top three user query patterns → evaluate a
  dedicated inverted index alongside, not instead of, ClickHouse.
