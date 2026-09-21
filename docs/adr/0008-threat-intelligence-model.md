# 0008. Threat intelligence and indicator model

- **Status:** Accepted
- **Date:** 2026-09-21

## Context

Indicator matching must run against every event at 1M events/s while the
indicator set reaches 10^9 entries across dozens of feeds with conflicting
quality. Retrofitting this is impossible, because it dictates both the hot path
shape and the event schema.

## Decision

Adopt **STIX 2.1** as the indicator vocabulary. Feeds are pluggable. Hot lookup
is embedded and bloom-prefiltered. Allowlists always win. Every hit carries
provenance.

## Vocabulary

We do not invent an indicator taxonomy. STIX 2.1 pattern types cover what
operators actually exchange:

| Class | Examples |
| --- | --- |
| Network | IPv4, IPv6, CIDR, domain, URL, autonomous system |
| File | MD5, SHA-1, SHA-256, imphash, ssdeep, file path, file name |
| Host | Registry key, mutex, named pipe, service name |
| Identity | Email address, username, certificate subject |
| Fingerprint | JA3, JA3S, JARM, TLS certificate hash |

Anything outside this set is a detection rule, not an indicator.

## Feeds

A feed is a pluggable connector, native or WASM
([ADR-0004](0004-configuration-and-extensibility.md)). Built-in support targets
MISP, AlienVault OTX, abuse.ch (URLhaus, ThreatFox, Feodo), CISA KEV, and
generic STIX 2.1 or CSV over HTTP.

Every feed declares a default confidence, a refresh interval, and a retention
policy. Feeds are never merged into one flat set: an indicator retains every
feed that asserted it.

## Storage and matching

Per [ADR-0003](0003-data-boundary.md), management state and hot lookup live in
different places:

| Concern | Home |
| --- | --- |
| Feed configuration, indicator metadata, audit, allowlists | PostgreSQL |
| Per-event lookup set | Embedded RocksDB plus in-memory bloom filters |
| Historical hits | ClickHouse, as ordinary events |

The hot path does this per event:

1. Extract observables from the normalized OCSF event. Which fields are
   observables is known statically from the schema, so this is not a search.
2. Test each observable against a type-partitioned bloom filter. At 10^9
   indicators this rejects the overwhelming majority in cache-resident memory.
3. Confirm survivors against RocksDB.

Cost is O(1) per observable per type, with no network call, satisfying the
constraint in [ADR-0003](0003-data-boundary.md). Bloom filter false positive
rate is a tuned budget: a false positive costs one local disk read, never a
false alert.

## Allowlists take precedence

An allowlist entry suppresses an indicator hit unconditionally, regardless of
feed confidence, and the suppression is recorded.

This exists because one bad feed entry, such as a public DNS resolver, a CDN
address, or a corporate proxy, floods the SOC with thousands of alerts and
destroys trust in the entire indicator pipeline within one shift. Allowlists
ship as first-class, versioned, auditable content alongside rules.

## Provenance is mandatory

Every hit records which feed asserted the indicator, at which feed version,
when it was first and last seen, and the confidence at match time. An analyst
who cannot answer why an alert fired treats it as noise, and an indicator hit
without provenance is not admissible in an incident report.

## Lifecycle

Indicators expire. Each carries a valid-from and valid-until, and confidence
decays on a per-feed schedule. An expired indicator stops matching but its
historical hits remain, because an event that matched last month still matched.

## Consequences

- Bloom filters are sized from the indicator count and must be rebuilt as feeds
  grow; memory per node becomes a capacity planning input.
- Feed refresh is a distinct failure domain: a stale feed must raise an alarm
  rather than silently matching against old data.
- The observable extraction map is generated from the OCSF schema, so it cannot
  drift from the event structure.

## When to revisit

Indicator volume passes 10^9 per node, or memory for bloom filters exceeds the
budget, in which case move to a shared lookup tier with a local cache and
accept a small per-event latency increase.
