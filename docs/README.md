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

## Writing an ADR

Copy [adr/0000-template.md](adr/0000-template.md) to the next number. Rules are
in [CONTRIBUTING.md](../CONTRIBUTING.md#architecture-decisions).
