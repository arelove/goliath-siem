# 0001. Do not write our own database engine

- **Status:** Accepted
- **Date:** 2026-09-21

## Context

The target load is 1,000,000 events/second (~500 MB/s, ~43 TB/day raw). The
question was raised whether to write a storage engine in Rust that takes the
best of ClickHouse and StarRocks.

## Decision

Use existing storage engines. Build the world-class component one layer up, in
the rule matching engine.

## Why "a database with no drawbacks" is not a target

This is not about effort. Storage trade-offs follow from theory.

The **RUM conjecture** (Athanassoulis et al., EDBT 2016) states it generally:
any data structure pays three overheads — Read, Update, and Memory. Optimizing
two comes at the cost of the third.

Three specific consequences every engine author meets:

| Constraint | Mechanism | Consequence |
| --- | --- | --- |
| Storage order is singular | Data is physically laid out in exactly one order | Locality is optimal for one query class. This is why `ORDER BY` dominates ClickHouse performance — it is geometry, not a defect |
| Compression versus random access | Block compression requires decompressing a block to read one row | 10–30x compression and fast point lookups are not simultaneously achievable |
| Indexes versus write throughput | Every index is an additional write per insert | Elasticsearch's inverted index and its ingest cost are the same phenomenon |

So "no drawbacks" does not describe an achievable object. The useful question
is *where we deliberately place the cost so it does not fall on our queries*.

## Prior art: this has been built, twice

The proposal is not hypothetical. Two funded teams executed it.

| Project | Language | Repository size | Stars | Started |
| --- | --- | --- | --- | --- |
| [ClickHouse](https://github.com/ClickHouse/ClickHouse) | C++ | 12.3 GB | 50,000 | public 2016, development from 2009 |
| [StarRocks](https://github.com/StarRocks/starrocks) | Java + C++ | 825 MB | 12,100 | 2021 |
| [Databend](https://github.com/databendlabs/databend) | **Rust** | 385 MB | 9,400 | 2020 |
| [GreptimeDB](https://github.com/GreptimeTeam/greptimedb) | **Rust** | 117 MB | 6,700 | 2022 |

Repository size includes history and test data, so it is a rough proxy rather
than a line count. Two details matter more than the sizes:

**StarRocks did not start from zero.** It is a fork of Apache Doris by the
original Doris team from Baidu, where the project was called Palo and dates to
roughly 2013. The 2021 date is the fork, not the beginning.

**Databend is precisely this proposal, shipped.** A Rust, cloud-native,
S3-backed ClickHouse alternative, venture funded, six years in. GreptimeDB is
the same idea for observability data, four years in. Both are competent
engineering. Neither displaced ClickHouse.

## Correcting an earlier estimate

An earlier draft of this ADR put the cost at "decades of person-years." That
overstates it today. A modern Rust engine does not start from scratch:
[Apache DataFusion](https://github.com/apache/datafusion) supplies query
planning, optimization, and vectorized execution; Arrow supplies the in-memory
representation; Parquet supplies the format. GreptimeDB and InfluxDB 3.0 are
built this way.

The technical barrier is genuinely lower than that phrasing implied. The
decision does not rest on feasibility.

## What the decision rests on

**In databases the moat is not code, it is trust accumulated through public
failure.** Nobody commits a petabyte of security logs to an engine that has not
survived five years of losing data in front of other people. That trust is a
function of calendar time and installed base; writing better code does not
compress it. This, not performance, is where Databend and GreptimeDB met their
ceiling.

The adjacent layer has no incumbent at all:

| Layer | Market state | Our opportunity |
| --- | --- | --- |
| Event storage | Saturated | None — use what exists |
| Matching thousands of rules on a stream | No open solution exists | Yes — the core differentiator |
| Streaming entity resolution | Fragmentary | Yes |
| Detections with reproducible CI | Almost absent | Yes |
| Coherent SIEM + SOAR + IRP in open source | Nobody | Yes |

A new project in the matching layer earns trust immediately: there is no
incumbent to displace, and the blast radius of a bug is "an alert did not fire"
rather than "the audit trail is gone."

At 1M events/s with 3,000 rules, naive evaluation costs 3·10⁹ predicate checks
per second. Making that tractable needs a predicate index, a RETE-style
discrimination network, bloom-filter prefiltering, and SIMD string comparison.
That is a world-class problem with a realistic horizon.

## Fallback

If we hit a ClickHouse limit, extend it rather than replace it: a custom table
engine, UDFs, a compression codec tuned for OCSF events, a patch upstream. We
get the behaviour we need while keeping someone else's decade of reliability
testing.

DataFusion also keeps the door open. If security-shaped queries genuinely do
not fit, a narrow purpose-built engine on top of DataFusion is months of work,
not years. This is not a one-way door.

## When to revisit

A specific query misses its latency budget in both ClickHouse and StarRocks
after honest optimization of schema, sort keys, and projections.
