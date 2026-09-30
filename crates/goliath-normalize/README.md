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
| `sources/m365.yaml` | The Microsoft 365 unified audit log, as the Office 365 Management Activity API delivers it, `[...]`, or one record per line: Entra ID sign-ins, account, password, and strong authentication changes, group membership, and directory roles as their OCSF classes, and every other operation of every workload, alerts included, as API Activity |
| `sources/okta.yaml` | The Okta System Log, as its API answers, `[...]`, or one event after another: sign-ins, account, password, and factor changes, group membership, and admin privileges as their OCSF classes, and every other event type as API Activity |
| `sources/sysmon.yaml` | Sysmon process creation, network connections, image loads, file creation, and registry value sets, as `evtx_dump` writes them |
| `sources/auditd.yaml` | Linux audit program executions on x86_64 and arm64, and logins, with the lines of each event gathered, as OCSF Process Activity and Authentication |
| `sources/entra.yaml` | Microsoft Entra ID interactive, non-interactive, and service principal sign-ins, as Azure Monitor diagnostic settings write them, as OCSF Authentication |
| `sources/cloudtrail.yaml` | AWS CloudTrail management events, as CloudTrail delivers them to S3, `{"Records": [...]}`, or one after another: console sign-ins as OCSF Authentication, and API calls as API Activity, read or other, with the caller, its session, and the request and response kept |
| `sources/falco.yaml` | Falco alerts on system calls and the Kubernetes audit log, as `json_output` writes them, as OCSF Detection Findings |
| `sources/windows-security.yaml` | The Windows Security log, as `evtx_dump` writes it, 49 event IDs chosen by what SigmaHQ rules ask for: logons, NTLM and Kerberos, process creation, accounts, computer accounts, rights, groups, scheduled tasks, services installed, object, registry, and share access, directory changes, and the log being cleared |

A definition for a source carried by syslog uses `framing: syslog`, which
reads messages framed by length or by line as RFC 6587 describes, and
`decoding: syslog`, which gives the RFC 5424 or RFC 3164 header as fields such
as `hostname` and `app_name` and the rest as `message`; `syslog-json` decodes
that rest as JSON.

The Sysmon definition feeds the SigmaHQ regression run in `goliath-match`, so
every one of its 357 cases also tests this crate on real recorded attacks.

## License

Copyright 2026 arelove. Licensed under the [Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE);
see [NOTICE](https://github.com/arelove/goliath-siem/blob/main/crates/goliath-normalize/NOTICE).
