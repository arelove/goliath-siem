# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

## [0.1.0] - 2026-09-25


### Added

- Add dotted paths into OCSF events
- Fold case with Unicode simple case folding
- Load field mappings and select them by log source
- Map Sigma Windows process creation fields to OCSF
- Add the resolved rule representation
- Apply Sigma value transformations as pySigma does
- Flatten nested conjunctions and disjunctions
- Resolve Sigma rules through a field mapping
- Resolve keywords that carry all or contains
- Map GrandParentImage for Windows process creation
- Map Sysmon file, image load, network, and registry rules
- Export the shipped Windows mapping set


### Changed

- Fold ASCII text without a per-character table lookup
- Visit path values without collecting them

### Added

- Add dotted paths into OCSF events
- Fold case with Unicode simple case folding
- Load field mappings and select them by log source
- Map Sigma Windows process creation fields to OCSF
