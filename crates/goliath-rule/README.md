# goliath-rule

[![crates.io](https://img.shields.io/crates/v/goliath-rule.svg)](https://crates.io/crates/goliath-rule)
[![docs.rs](https://img.shields.io/docsrs/goliath-rule)](https://docs.rs/goliath-rule)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/arelove/goliath-siem/blob/main/LICENSE)

Detection rules resolved to OCSF paths, in the one form that every execution
path of [Goliath](https://github.com/arelove/goliath-siem) consumes.

A rule language such as Sigma names fields the way a log source names them.
This crate holds the resolved form, which refers only to OCSF paths, so that
the streaming match engine and the ClickHouse backend cannot disagree about
what a rule means. The reasoning is in
[ADR-0012](https://github.com/arelove/goliath-siem/blob/main/docs/adr/0012-sigma-field-mapping.md).

## Scope

- Dotted paths into an OCSF event, traversing arrays.
- Case folding that defines case insensitive comparison: Unicode simple case
  folding, independent of locale.
- Field mappings from a rule language's field names to OCSF paths, selected
  by log source. The shipped set for Sigma on Windows is in
  [mappings/](mappings/).
- Resolution of parsed Sigma rules into that form: modifiers become wildcard
  patterns, transformations such as `base64offset` and `windash` become the
  variants pySigma produces, and anything that cannot be resolved exactly is
  refused.

## License

Copyright 2026 arelove. Licensed under the [Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE);
see [NOTICE](https://github.com/arelove/goliath-siem/blob/main/crates/goliath-rule/NOTICE).
