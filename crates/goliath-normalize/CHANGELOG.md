# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

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
