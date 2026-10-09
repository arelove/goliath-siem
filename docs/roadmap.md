# Roadmap

Delivery order follows the wedge strategy in
[architecture.md](architecture.md): ship the matching engine first as a
standalone, independently useful artifact, then grow the platform around parts
that already have users.

Milestones are sequenced by dependency, not by date. Each states an exit
criterion that is measurable, so "done" is not a judgement call.

## Current milestone

**Two records before the interface grows**, the first on platform health;
see the end of M4. M3, M3.5, and M4 are built; each waits for its exit run:
M3's 30 minutes at 100,000 events/s, M3.5's live senders at that rate, and
M4's detector at 10^8 indicators. They are to be made together on a
separate machine rather than a laptop.

Review notes added on 2026-09-27 are implementation concerns, not revised ADRs
or claims that an exit criterion has passed.

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

**Status:** the engine is built and exact. On 2,046 SigmaHQ rules and
converted OTRF recordings it returns what the reference evaluator returns for
every event, at about 129,000 events/s on one core and over 2,000,000 on 32
threads ([sigma-coverage.md](sigma-coverage.md#the-engine-on-the-same-events)),
with instruction counts gated in CI. Open: the M1 corpus replicated to 10
million events, which the exit criterion names, and
`goliath-sigma-clickhouse`, which moves to M5 with the scheduler that needs
it.

The M1 corpus is deliberately not the M3 generator. It is real telemetry,
replicated for volume, so it is good enough to check equivalence and measure
the engine against itself; it cannot stand in for the entity-model stream when
measuring the platform.

**Review note (2026-09-27):** keep M1's formal exit open until the named
10-million-event run is published. Exact agreement on the smaller regression
corpus does not satisfy that volume criterion.

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

**Status:** the exit criterion is met. `goliath-normalize` runs declarative source definitions
with dead-letter routing, checked against the OCSF schema, and its Sysmon
definition feeds the SigmaHQ regression run. `goliath-store` writes its events
and dead letters to ClickHouse under versioned migrations
([ADR-0013](adr/0013-event-storage.md)), tested in CI against real servers,
with retention counted from receipt. `goliath-pipe` carries records between
roles in memory or in a durable disk log ([ADR-0015](adr/0015-pipe-semantics.md)),
and the `goliath` binary runs collector, normalizer, and writer in one process:
both halves of the exit criterion are met: with every role in one process over
the disk log, and with each role in its own container over Kafka, both tested
end to end in CI. Definitions ship for all four sources, and a minmax index
on `time` keeps searches narrow (M2.5). Not built yet: the S3 transport.

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

**Status:** done. Searches filtered by time, class, and one path return in 38
to 806 ms over 10 million stored events
([benchmarks.md](benchmarks.md#search)), after a minmax index on `time`. One
Sysmon event dropped into the inbox is searchable about 1.2 seconds later with
every role in one process, and 0.7 seconds later with the roles in separate
containers over Kafka; CI fails either stack past five seconds.
`scripts/demo.sh` starts the platform, fills it with a day of a fleet's
events with one intrusion among them, and opens the view on it.

## M3 - Benchmark rig

Without this, nothing after it can be honestly measured. Designed in
[ADR-0017](adr/0017-benchmark-rig.md).

| Deliverable | Detail |
| --- | --- |
| Entity-model generator | `goliath-gen`: N users and M hosts, daily cycles, Zipf activity, same entity under different identifiers per source, raw records in each source's own format, and the ground truth of which identifiers belong together |
| Replay engine | Real datasets time-shifted to now, with a speed multiplier |
| Attack injector | Labelled chains at known offsets, producing ground truth |
| Metrics report | Events/s per core, latency percentiles, compression ratio, precision and recall |
| Platform metrics | A Prometheus endpoint on every role: events in and out, ingestion lag, pipe depth, dead letters by source and stage, query time; the report reads them rather than guessing from outside |
| Capacity model | The cost of one event in each stage, measured on a machine that runs only the platform, and from it the machines a given rate needs; see [architecture.md](architecture.md#capacity-model) |

**Exit criterion:** a single command produces a reproducible report covering
every metric listed in [architecture.md](architecture.md#benchmark-method),
measured where the component exists and marked with the milestone that
brings it where it does not, and a 30-minute run sustains 100k events/s on one
developer machine, with the lag of every reader bounded.

**Review notes (2026-09-27):**

- The Sysmon and Entra formatters now have normalization and reproducibility
  tests. This is a subset of M3: auditd, Falco, replay, and attack injection
  are still missing. A driver or a successful 60-second run does not establish
  the 30-minute exit criterion.
- Define "bounded lag" with an allowed growth rate and maximum backlog before
  publishing a verdict. Draining after load stops proves eventual completion,
  not sustained throughput. Reader lag counts pipe payloads; one raw payload
  can contain 1,000 events. Raw and normalized lag have different units.
- Name the hardware and CPU accounting boundary. Platform process CPU excludes
  Kafka, ClickHouse, and the generator. Publish whole-machine consumption
  separately before making a cost-per-event claim. Separate startup, load,
  and drain in throughput calculations.
- The current pipe uses one partition per topic and manual assignment. More
  producer threads do not demonstrate horizontal scaling of consumers. Measure
  this bottleneck before choosing sharding or revising ADR-0015.
- Measured by a 5-minute probe at 100,000 records/s: 99,989 records/s were
  offered, and the platform stored about 40,000 events/s using 1.56 of 16
  cores and 559 MiB, receipt to stored p50 61 s. The single normalizer on one
  partition is the limit, not the machine. Parallel normalization within the
  reader is the first step, before partitions.
- Distinguish entity-resolution precision against synthetic identity truth
  from detection precision against real labelled telemetry. The blanket
  statement in architecture.md that precision cannot use synthetic data needs
  this qualification before the M4.5 evaluation is specified.

**Status (2026-09-28):** built, and waiting for the exit run.

- The rig, its report, platform metrics, and `goliath-gen` with Sysmon and
  Entra ID. The auditd and Falco formatters are still to write.
- Throughput, after parallel normalization, acknowledged and concurrent
  inserts, and parallel decoding in the writer: a 5-minute probe at 100,000
  records/s stored 99,300 events/s on 4.5 cores, receipt to stored p50 1.0 s
  and p99 4.8 s, with nothing lost; its verdict was not sustained by a margin,
  backlog growth of 1,153 records/s against 1,000 allowed. The 30-minute run
  is to be made on a separate machine. The generator used the same machine
  and its cores, so these numbers are a floor: the exit run puts the
  generator on one machine and the platform on another, sending over the
  local network, so that the platform's cores are its own and the capacity
  model is measured from them.
- Replay of real recordings for every shipped source, the OTRF Windows atomic
  datasets through a pinned download script and a flat Sysmon definition, and
  ground truth for the events a replayed recording becomes, matched by the
  identity the platform stores. Generated attack chains bound to the
  generator's entities are still to come.

## M3.5 - Collection

Files dropped in an inbox prove the path; companies send logs over the
network, from sources they already run.
Designed in [ADR-0018](adr/0018-collection.md).

| Deliverable | Detail |
| --- | --- |
| Network receivers | Syslog (RFC 5424 and 3164) over TCP with TLS, an HTTP ingest endpoint with per-source tokens, and OpenTelemetry logs over OTLP, each writing to the pipe with the same backpressure as the file collector |
| Source definitions | Windows Security events, AWS CloudTrail, Okta System Log, Microsoft 365 audit, Zeek, and Suricata EVE, each with fixtures of every kind and of malformed input |
| Source health | For each source: last event seen, rate against its own baseline, and dead letters, so a source that goes silent is noticed before an investigation needs it |

**Exit criterion:** each shipped source sends from a live sender to an event
visible in search within five seconds, and each receiver sustains the M3
rate on one machine without losing an acknowledged record.

**Status (2026-09-30):** built, and waiting for the exit run.

- The `receiver` role: HTTP ingest with a token per source, syslog over TCP
  with TLS on a port per source, and OTLP logs over HTTP, each acknowledging
  only what the pipe has taken. End-to-end tests send over each to
  ClickHouse.
- Source definitions for Windows Security, AWS CloudTrail, Okta, Microsoft
  365, Zeek, and Suricata EVE, with fixtures of every kind and of malformed
  input, beside Sysmon, auditd, Falco, and Entra ID. Where SigmaHQ has rules
  for a source, a mapping set loads them, checked by rules against the
  definition's fixtures: 122 of 145 Security log rules, 56 of 57 CloudTrail,
  23 of 23 Okta, 20 of 21 Microsoft 365, and 24 of 24 Zeek
  ([sigma-coverage.md](sigma-coverage.md)).
- Source health, designed in [ADR-0019](adr/0019-source-health.md):
  events and dead letters counted by source and hour on insert, each source
  judged against the same hour of its last seven days, at `/api/v1/sources`
  and in the interface.

Follow-ups found while building it, none in the exit criterion:

- Decodings for CEF and LEEF, and for text by regular expression or
  `key=value` pairs, so that appliances writing neither JSON nor syslog
  structured data can be read without a definition per format.
- Azure Monitor's activity, audit, and sign-in logs: 131 SigmaHQ rules, the
  largest set left without a mapping outside Windows.
- Product-independent mappings for Sigma's `dns`, `proxy`, and `firewall`
  categories, by OCSF class, so that one rule reads Zeek, Suricata, and any
  later source alike.
- A `when` that tests only that a field is present, so that a definition
  such as Zeek's can take every record of a log it has no kind for, as the
  Okta and Microsoft 365 definitions do by a field every record holds.
- Rule paths that reach members whose names contain dots, such as Zeek's
  `certificate.key_alg` kept under `unmapped`; today a mapping must name an
  OCSF attribute for them.
- Two SigmaHQ DCE/RPC rules pair `endpoint` and `operation` the other way
  round from Zeek, and cannot fire on its logs; to be reported upstream.

## M4 - Context

Enrichment that makes an alert actionable rather than a row.

| Deliverable | Detail |
| --- | --- |
| `goliath-intel` | STIX 2.1 model, feed connectors, bloom-prefiltered RocksDB lookup, allowlists, provenance ([ADR-0008](adr/0008-threat-intelligence-model.md)) |
| `goliath-attack` | Versioned framework loader, technique mapping, coverage versus capability ([ADR-0009](adr/0009-attack-knowledge-model.md)) |
| `goliath-enrich` | Entity and asset snapshot into local RocksDB, refresh scheduling: networks, assets, identities, groups, and context lists from a site's own exports, added to findings as enrichments ([ADR-0022](adr/0022-context-snapshot.md)) |
| Detector role | Reads the event topic beside the writer, matches indicators, and writes each match as a Detection Finding with its provenance; suppressed matches are stored too ([ADR-0021](adr/0021-enrichment-placement.md)) |
| Matching what the detector missed | The detector reads the event topic as an observer ([ADR-0015](adr/0015-pipe-semantics.md)), so it never slows the writer; one that falls behind the topic's bound is moved past events and counts them. Those events are stored: the detector notes their range of receipt time, reads it back from the store, and matches it, with the same findings |
| Indicators that arrive late | When a feed adds indicators, the detector looks back over the stored events of a configured number of days for the new ones alone, and writes the same findings ([ADR-0021](adr/0021-enrichment-placement.md)). It reads those events once a look back; a table of observed values, to read less, waits for a measurement that asks for it |
| Reference lists | An importer for curated community lists in CSV, starting with [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists) (MIT): vulnerable drivers, named pipes, services and scheduled tasks of known tools, suspicious TLDs and ASNs, VPN and proxy ranges, dynamic DNS domains, offensive tool keywords, user agents. Each list is pinned to a commit, typed as indicators, allowlist, or context, and keeps its source and licence as provenance, so an enrichment says which list and which version matched |

**Exit criterion:** the detector matches 10^8 indicators at no less than 90%
of the events a second a core it reaches with 10^3, within the memory, disk,
cold start, feed refresh, and correctness budgets of
[ADR-0021](adr/0021-enrichment-placement.md), and without changing the
writer's rate; and an ATT&CK Navigator layer is exported that distinguishes
covered techniques from techniques lacking a data source.

**Status (2026-10-10):** built, and waiting for the exit run.

- The detector role, matching what it missed from the store, the look back
  for indicators that arrive late, and reference lists pinned to a commit.
- Context ([ADR-0022](adr/0022-context-snapshot.md)): `goliath-enrich`
  reads a site's own exports of networks, assets, identities, and groups,
  and the detector writes what it finds of a matched event's values into
  the finding. Lists that describe and do not accuse are context, and
  raise nothing.
- Coverage against ATT&CK and its Navigator layer were built with M1's
  rules: 302 of 697 techniques of ATT&CK 19.2 have a rule that can fire on
  the data the shipped sources supply.
- The harnesses that measure the detector against ADR-0021's budgets, and
  a check of each on a laptop: the rate as indicators grow, a feed
  replaced during a run, and the writer's rate when the detector stops.
  The exit run itself, to 10^8 indicators, is to be made on a separate
  machine.

Left for later, each with the condition that brings it:

- The snapshot of context on disk. It is in memory until a measurement
  shows a site's records do not fit, as ADR-0022 says.
- A scope for events, so that two sites with one address range each get
  their own context. The records and the lookup have it; an event gets a
  scope when collection knows which site a source belongs to.
- Lists of names and keywords of offensive tools. They need matching by
  pattern, which is the rule engine's work in M5, not an indicator's.

### Two records before the interface grows

Built of ADR-0023 so far: the three probes on every process. Reports,
conditions, and the view of the platform follow.

After M4 and before any more of the interface is built, two decisions are
written down, each as ADR-0022 was: from how the systems in use do it, what
their users say of them, and cases the answer must serve.

| Record | What it decides |
| --- | --- |
| Platform health, [ADR-0023](adr/0023-platform-health.md) | How someone who runs the platform sees what is wrong with it: which roles run and where, which collector is silent, where a topic's backlog grows, which feed or export of context is old, and why. For one machine and for roles spread over hosts or a Kubernetes cluster, where a process that restarts is the normal case. [ADR-0019](adr/0019-source-health.md) decides the health of sources; this is the health of the platform that reads them. It comes first: whoever starts the platform needs it on the first day |
| The interface, [ADR-0024](adr/0024-interface.md) | What an analyst sees first, and the way from a finding to its event, its entities, and a decision. Which views exist and what each is for, before the list of M7 is built as written |

## M4.5 - Entity graph

An alert about a process is a row; an alert about a person, on a host, talking
to an address, is an investigation. The graph is what turns events into the
things analysts reason about.

| Deliverable | Detail |
| --- | --- |
| Entity model | Users, hosts, processes, files, addresses, and domains as typed objects with typed links (logged on to, ran, wrote, connected to), derived from OCSF observables, versioned like the schema |
| Resolution | One entity under the identifiers each source gives it, such as `CORP\adam`, `adam@corp.example`, and an Entra object id; every merge explainable by the rule and events that made it, and reversible; placement, streaming or at rest, decided by ADR |
| Graph store | Entities and links in ClickHouse beside the events, with first and last seen and the events behind each link |
| Graph API | Neighbours of an entity within a time window, and the path between two, under the same checked, parameterized discipline as search |

**Exit criterion:** on the M3 generator's stream, where each entity appears
under different identifiers per source, resolution reaches measured precision
and recall against the generator's ground truth, and every entity within two
links of an alert's subject is returned in under one second.

**Review notes (2026-09-27):**

- Resolve the storage boundary by ADR before implementing the graph. ADR-0003
  puts mutable entities in PostgreSQL; this milestone puts entities and links
  in ClickHouse while also requiring reversible merges. Immutable observed
  edges and mutable identity decisions need explicit, separate ownership.
- Static identifier lists do not establish IP ownership across time. Add
  validity intervals, DHCP collision cases, shared hosts, account reuse, and
  false-merge penalties to the evaluation before claiming resolution quality.
- Bound graph expansion by time, result size, and degree. Two links from a
  shared domain controller can include most of a company; "under one second"
  is not testable without dataset size and limits on returned neighbours.

## M5 - Detection service

| Deliverable | Detail |
| --- | --- |
| Streaming detector | The match engine in the detector role of M4, with rule hot reload |
| Correlation in the stream | Sigma correlation rules (event count, value count, temporal, ordered temporal) evaluated as events arrive, with window state in RocksDB, not only as scheduled SQL |
| Backtesting | Any rule run over stored history before it is enabled: how often it would have fired, on which events, and how many alerts a day it would add |
| `goliath-sigma-clickhouse` | Sigma to ClickHouse SQL compilation, moved from M1, checked against the reference evaluator on stored events |
| Scheduler | Windowed detections over ClickHouse, incremental materialized views |
| Alert model | Deduplication, grouping, severity, provenance to the source event |
| Detection content | An initial rule pack, each rule with true and false positive fixtures |

**Exit criterion:** p99 latency from ingestion to alert under 5 seconds on the
streaming path at target throughput, and every shipped rule passing its
fixtures in CI; a correlation rule fires in the stream on the same events as
its scheduled SQL form; a backtest of one rule over 30 days of stored events
finishes in under a minute.

**Review note (2026-09-27):** specify event time, allowed lateness, duplicate
handling, restart recovery, and rule-version boundaries before sharing
correlation semantics between streaming and SQL. The 30-day backtest target
also needs event volume, rule complexity, hardware, and concurrency limits.

## M5.5 - Open archive

Customer data stays with the customer: the first promise in
[architecture.md](architecture.md), and the one that makes leaving free.

| Deliverable | Detail |
| --- | --- |
| Archive writer | Events older than the hot window written as Parquet to an Iceberg table in the customer's bucket, partitioned by day and class, with the OCSF schema in the table metadata |
| Search over the archive | The same search structure over archived days, through ClickHouse's Iceberg support, marked as slower in the interface rather than refused |
| Retention per tier | Hot and archive retention set separately, with legal hold on a case's events |

**Exit criterion:** twelve months of events in a bucket are read by DuckDB or
Spark with no Goliath component running, and a search over one archived day
returns the same events it returned while hot.

## M6 - Response

| Deliverable | Detail |
| --- | --- |
| Case service | Cases, tasks, observables, state machine, audit with hash chaining |
| Playbook runtime | Declarative playbooks with durable state in PostgreSQL, human-in-the-loop approvals, built-in, WASM, and sidecar actions; engine chosen by ADR under the single-binary constraint ([ADR-0014](adr/0014-one-language-for-services.md)) |
| RBAC and tenancy | Row-level security, per-tenant quotas and backpressure |
| Identity | Sign-in through OIDC single sign-on, roles mapped from the identity provider's groups, and API tokens scoped per role |
| Analyst audit | Every search, event viewed, export, and change of configuration recorded with who and when, in the same tamper-evident log |

**Exit criterion:** an alert becomes a case, a playbook executes with an
approval step, and every state transition appears in a tamper-evident audit
log.

**Review note (2026-09-27):** basic identity, authorization, and tenant
isolation are prerequisites for network ingestion and shared deployments,
even if the full M6 service comes later. Keep pre-M6 deployments explicitly
single-tenant and trusted; add negative cross-tenant tests before changing
that boundary. Hash chaining detects edits only against a trusted anchor;
define external checkpoints to detect truncation and whole-log replacement.

## M7 - Interface

The views below are what [ADR-0024](adr/0024-interface.md) decides, in the
order it gives for building them.

| Deliverable | Detail |
| --- | --- |
| Shell and palette | One rail of views, one time range, detail in a panel beside its list, and the dark palette of [ADR-0024](adr/0024-interface.md) |
| Overview | The landing view: what needs a decision, whether data arrives, whether the platform is well; every part of every chart leads to its rows |
| Findings | The queue, worked by keyboard, with a panel that goes from what was found to who and what, what else, the event, and the decision |
| Investigation view | Virtualized event tables, entity pivots, timeline |
| Platform | Sources, roles, flows, feeds, and exports of context, as [ADR-0023](adr/0023-platform-health.md) judges them |
| Case workspace | Case detail, playbook status, and where a decision is kept |
| Coverage dashboard | For each ATT&CK technique, whether a rule covers it, whether the data that rule needs is being collected, and whether it fired in its last backtest; a technique with a rule but no data is shown as uncovered |
| Configuration | Source onboarding with dry-run plan preview |
| Analyst assistant | A question in plain language becomes a search, a graph query, or a draft rule in the same typed structures a person writes, checked against the schema and shown for review before it runs; never free SQL; works with a local model, so no event has to leave the deployment |

**Exit criterion:** an analyst completes triage of an alert into a closed case
without leaving the interface.

## M8 - First public release

| Deliverable | Detail |
| --- | --- |
| Single-binary mode | Embedded substitutes, working system in under a minute |
| Installation paths | Docker Compose, Helm chart, plain binary |
| Documentation | Operator guide, source authoring guide, rule authoring guide |
| Published benchmarks | Full report with reproduction instructions |
| Supply chain | Signed images and release binaries, an SBOM for each, and dependency audit in CI |

**Exit criterion:** a person who has never seen the project runs it against
their own logs within ten minutes, following only the README.

**Review note (2026-09-27):** maintain the published status independently of
this release milestone. Both root READMEs described ingestion and storage as
unbuilt despite the M2 and M2.5 completion evidence above; they were
reconciled when M3.5 was built (2026-09-30). Keep them current before using
the README as an onboarding acceptance test.

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

M3.5 comes before context and detection because nothing after it is useful to
a company that cannot send it logs, and M8's exit criterion, running against
one's own logs, cannot be met from an inbox directory.

M4.5 comes before M5 so that detections and alerts can name entities rather
than events, and before M7 so that the investigation view's pivots walk the
graph instead of repeating searches. The analyst assistant waits for both: it
is only as safe as the typed structures it writes into, and only as useful as
the entities it can name.
