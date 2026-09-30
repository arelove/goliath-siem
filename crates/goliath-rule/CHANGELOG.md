# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

## [0.2.4] - 2026-09-30


### Added

- A Sigma mapping set for Okta, all 23 SigmaHQ rules load

## [0.2.3] - 2026-09-28


### Added

- A Sigma mapping set for AWS CloudTrail, 56 of 57 SigmaHQ rules load

## [0.2.2] - 2026-09-28


### Added

- The Security mapping reads the fields of 4648

## [0.2.1] - 2026-09-28


### Added

- Sigma rules for the Windows Security log resolve to OCSF
- The Security mapping covers the events of Windows Security definition version 2; 120 of 145 SigmaHQ Security rules load

## [0.2.0] - 2026-09-25


### Fixed

- Breaking: Release the OCSF schema checks on mappings as the breaking change they are

## [0.1.1] - 2026-09-25

### Added

- Breaking: mapping entries are checked against the OCSF schema when they load.
  This rejects mappings 0.1.0 accepted, so it should not have been a patch
  release; use 0.2.0.

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
