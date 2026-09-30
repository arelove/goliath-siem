# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

## [0.2.14] - 2026-09-30


### Added

- A Zeek definition for ten logs

## [0.2.13] - 2026-09-30


### Added

- Times without an offset, read as UTC
- A Microsoft 365 unified audit log definition


### Fixed

- The new coercion last, so earlier ones keep their discriminants

## [0.2.12] - 2026-09-30


### Added

- An Okta System Log definition

## [0.2.11] - 2026-09-28


### Added

- Array elements by index in paths, and records that are arrays unwrapped

## [0.2.10] - 2026-09-28


### Added

- Unwrap a batch of records, and IP addresses checked as such
- Entra unwraps Event Hub batches
- An AWS CloudTrail definition, console sign-ins and API calls

## [0.2.9] - 2026-09-28


### Added

- Windows Security definition version 2, 48 event IDs
- Windows Security reads 4648, logons with explicit credentials

## [0.2.8] - 2026-09-28


### Added

- Integers from 0x hexadecimal text, and nil values a definition names
- A Windows Security definition, logons, Kerberos, processes, accounts, groups

## [0.2.7] - 2026-09-28


### Added

- A normalizer tells its definition's framing

## [0.2.6] - 2026-09-28


### Added

- Syslog framing and decodings, RFC 6587, 5424, and 3164

## [0.2.5] - 2026-09-27


### Added

- Sysmon as flat JSON lines, as NXLog and the OTRF datasets write it


### Style

- Format the flat Sysmon test

## [0.2.4] - 2026-09-27


### Added

- An envelope says when its record was taken

## [0.2.3] - 2026-09-26


### Added

- Read Linux audit logs, one record per event
- A Linux auditd definition, executions and logins

## [0.2.2] - 2026-09-26


### Added

- Translate source values to OCSF values through a table
- Source paths reach members whose names hold dots
- A Falco source definition, alerts as OCSF detection findings
- An Entra ID sign-in definition, as OCSF authentication

## [0.2.1] - 2026-09-25


### Added

- Encode outcomes for the pipe between roles

## [0.2.0] - 2026-09-25

### Added

- Give every event a content identity for deduplication

### Fixed

- Breaking: release the OCSF schema checks on definitions as the breaking change they are

## [0.1.1] - 2026-09-25

### Added

- Breaking: source definitions are checked against the OCSF schema when they
  load. This rejects definitions 0.1.0 accepted, so it should not have been a
  patch release; use 0.2.0.

## [0.1.0] - 2026-09-25


### Added

- Run declarative source definitions, starting with Sysmon
