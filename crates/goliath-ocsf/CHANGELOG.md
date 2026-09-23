# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

### Added

- OCSF 1.5.0 base event types, with class-specific attributes preserved
  verbatim and unknown enumeration values retained rather than rejected.
- Validation of the arithmetic invariants OCSF states but JSON Schema cannot
  express.
- Observable types and extraction, filtered to the scalar types indicator feeds
  carry.
