# goliath-ocsf

OCSF (Open Cybersecurity Schema Framework) event types, validation, and
observable extraction.

This crate is the shared vocabulary of the
[Goliath](https://github.com/goliath-siem/goliath) security platform. It is
published separately because it is useful to anyone working with OCSF events in
Rust, with or without the rest of the platform.

Schema version targeted: **OCSF 1.5.0**.

## Scope

- Typed representation of the OCSF base event.
- Observable types and values, forward-compatible with schema additions.
- Validation of the invariants the schema states but JSON cannot express.
- Observable extraction, the input to per-event indicator matching.

## License

[Apache License 2.0](../../LICENSE).
