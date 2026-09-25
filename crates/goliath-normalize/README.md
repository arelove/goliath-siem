# goliath-normalize

[![crates.io](https://img.shields.io/crates/v/goliath-normalize.svg)](https://crates.io/crates/goliath-normalize)
[![docs.rs](https://img.shields.io/docsrs/goliath-normalize)](https://docs.rs/goliath-normalize)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/arelove/goliath-siem/blob/main/LICENSE)

Declarative source definitions that turn raw log records into OCSF events, for
the [Goliath](https://github.com/arelove/goliath-siem) security platform.

A source definition is YAML written by someone who knows a log source, not
Rust. It says how a byte stream splits into records, how a record decodes,
which kind of record it is, and where each field goes in OCSF. Every
definition ships with fixtures of raw records and the exact outcomes they must
produce.

## Nothing is dropped

- A record that cannot become an event is a dead letter, with its raw bytes
  intact and the stage that failed, so it can be processed again once the
  definition is fixed.
- A value that does not convert is kept as written under `unmapped` and
  reported with the event. The event still reaches detection: one malformed
  field must not hide an event from every rule.
- Fields a definition does not map, in the objects it lists, are kept under
  `unmapped` by their own names.

## Shipped definitions

| Definition | Covers |
| --- | --- |
| `sources/sysmon.yaml` | Sysmon process creation, network connections, image loads, file creation, and registry value sets, as `evtx_dump` writes them |

The Sysmon definition feeds the SigmaHQ regression run in `goliath-match`, so
every one of its 357 cases also tests this crate on real recorded attacks.

## License

Copyright 2026 arelove. Licensed under the [Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE);
see [NOTICE](https://github.com/arelove/goliath-siem/blob/main/crates/goliath-normalize/NOTICE).
