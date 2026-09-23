# goliath-rule

Detection rules resolved to OCSF paths, in the one form that every execution
path of [Goliath](https://github.com/arelove/goliath-siem) consumes.

A rule language such as Sigma names fields the way a log source names them.
This crate holds the resolved form, which refers only to OCSF paths, so that
the streaming match engine and the ClickHouse backend cannot disagree about
what a rule means. The reasoning is in
[ADR-0012](../../docs/adr/0012-sigma-field-mapping.md).

## Scope

- Dotted paths into an OCSF event, traversing arrays.
- Case folding that defines case insensitive comparison: Unicode simple case
  folding, independent of locale.
- Field mappings from a rule language's field names to OCSF paths, selected
  by log source. The shipped set for Sigma on Windows is in
  [mappings/](mappings/).

## License

[Apache License 2.0](../../LICENSE).
