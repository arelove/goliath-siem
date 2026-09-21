# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is generated from commit history by the release automation described
in [ADR-0010](docs/adr/0010-versioning-and-releases.md). Do not edit it by
hand: to change what a release says, change the commit message before it
merges.

Per-crate changelogs live beside each crate in `crates/*/CHANGELOG.md`.

## [Unreleased]

### Added

- `goliath-ocsf`: OCSF 1.5.0 base event types, validation of the arithmetic
  invariants the schema states but JSON Schema cannot express, and observable
  extraction for indicator matching.
- `goliath-sigma`: Sigma condition expression language, parsed into a typed AST
  with source spans on every node and every error.

[Unreleased]: https://github.com/arelove/goliath-siem/commits/main
