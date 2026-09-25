# goliath-ocsf

[![crates.io](https://img.shields.io/crates/v/goliath-ocsf.svg)](https://crates.io/crates/goliath-ocsf)
[![docs.rs](https://img.shields.io/docsrs/goliath-ocsf)](https://docs.rs/goliath-ocsf)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/arelove/goliath-siem/blob/main/LICENSE)

OCSF (Open Cybersecurity Schema Framework) event types, validation, and
observable extraction.

This crate is the shared vocabulary of the
[Goliath](https://github.com/arelove/goliath-siem) security platform. It is
published separately because it is useful to anyone working with OCSF events in
Rust, with or without the rest of the platform.

Schema version targeted: **OCSF 1.5.0**.

## Scope

- Typed representation of the OCSF base event.
- Observable types and values, forward-compatible with schema additions.
- Validation of the invariants the schema states but JSON cannot express.
- Observable extraction, the input to per-event indicator matching.
- The schema itself, compiled in: every class and object of OCSF 1.5.0 and
  its extensions, so a path such as `process.file.path` can be checked
  against a class, and its type found, without a network or a parse.

## Schema tables

`src/schema/tables.rs` is generated from the export of the
[OCSF schema](https://github.com/ocsf/ocsf-schema), which is published under
the Apache License 2.0, and keeps only attribute names, types, and enumerated
values. To regenerate it for a new version:

```sh
curl -sSL https://schema.ocsf.io/1.5.0/export/schema -o ocsf.json
cargo run -p goliath-ocsf --example generate_schema -- ocsf.json > crates/goliath-ocsf/src/schema/tables.rs
```

## License

[Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
