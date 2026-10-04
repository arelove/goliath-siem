# Documentation

Goliath is an open security data platform: event ingestion, detection, response
orchestration, and incident handling in one system.

## Contents

| Document | Contents |
| --- | --- |
| [architecture.md](architecture.md) | Targets, data flow, component map, benchmark method, go-to-market |
| [roadmap.md](roadmap.md) | Delivery plan, milestones, current focus |
| [sigma-coverage.md](sigma-coverage.md) | How much of the SigmaHQ repository loads and fires on real attack events |
| [benchmarks.md](benchmarks.md) | How the engine's speed is measured, and how CI stops regressions |
| [benchmark-rig.md](benchmark-rig.md) | Running the benchmark rig against the whole platform, and how its report decides |
| [detector.md](detector.md) | The detector: feeds of indicators and how they are kept current, allowlists, findings, and what to watch |
| [lab.md](lab.md) | A lab on a home network: one machine runs the platform, and others send it their Sysmon and Security logs over HTTPS |
| [adr/](adr/) | Architecture decision records, one file per decision |

## Decisions

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](adr/0001-no-custom-database.md) | Do not write our own database engine | Accepted |
| [0002](adr/0002-storage-stack.md) | Storage stack: ClickHouse, PostgreSQL, Valkey, S3/Iceberg | Accepted |
| [0003](adr/0003-data-boundary.md) | Data boundary: immutable events versus mutable state | Accepted |
| [0004](adr/0004-configuration-and-extensibility.md) | Configuration compiles; extensions are WASM | Accepted |
| [0005](adr/0005-languages-and-process-boundaries.md) | Languages and process boundaries | Superseded in part by 0014 |
| [0006](adr/0006-deployment-topology.md) | Roles compose; topology is configuration | Accepted |
| [0007](adr/0007-source-and-parser-model.md) | Source and parser model | Accepted |
| [0008](adr/0008-threat-intelligence-model.md) | Threat intelligence and indicator model | Accepted |
| [0009](adr/0009-attack-knowledge-model.md) | MITRE ATT&CK knowledge model | Accepted |
| [0010](adr/0010-versioning-and-releases.md) | Versioning and releases | Accepted |
| [0011](adr/0011-untrusted-yaml.md) | Parse rule YAML as untrusted input | Accepted |
| [0012](adr/0012-sigma-field-mapping.md) | Sigma fields resolve to OCSF paths at load time | Accepted |
| [0013](adr/0013-event-storage.md) | Event storage layout | Accepted |
| [0014](adr/0014-one-language-for-services.md) | Rust for every platform service | Accepted |
| [0015](adr/0015-pipe-semantics.md) | Pipe semantics: ordered topics, consumer groups, at least once, bounded | Accepted |
| [0016](adr/0016-event-search.md) | Event search: a typed structure compiled to parameterized SQL | Accepted |
| [0017](adr/0017-benchmark-rig.md) | Benchmark rig: raw records from an entity model, ground truth, the platform's own metrics | Accepted |
| [0018](adr/0018-collection.md) | Collection over the network: HTTP ingest, syslog over TLS, and OTLP logs, acknowledged only once the pipe has taken them | Accepted |
| [0019](adr/0019-source-health.md) | Source health: events and dead letters counted by source and hour on insert, each source judged against the same hour of its last seven days | Accepted |
| [0020](adr/0020-state-beyond-events.md) | State beyond the event store: RocksDB embedded for what events pass through, PostgreSQL from M4.5 for what people and workflows change, M4 without it | Accepted |
| [0021](adr/0021-enrichment-placement.md) | Where indicators are matched and context is added: in a detector role beside the writer, each match a finding of its own, stored events never rewritten | Accepted |

## Writing an ADR

Copy [adr/0000-template.md](adr/0000-template.md) to the next number. Rules are
in [CONTRIBUTING.md](../CONTRIBUTING.md#architecture-decisions).
