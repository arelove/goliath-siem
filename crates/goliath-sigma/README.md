# goliath-sigma

[![crates.io](https://img.shields.io/crates/v/goliath-sigma.svg)](https://crates.io/crates/goliath-sigma)
[![docs.rs](https://img.shields.io/docsrs/goliath-sigma)](https://docs.rs/goliath-sigma)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/arelove/goliath-siem/blob/main/LICENSE)

Parses [Sigma](https://github.com/SigmaHQ/sigma) detection rules into a typed,
inspectable AST.

Part of the [Goliath](https://github.com/arelove/goliath-siem) security
platform, published separately because it is useful to anyone working with
Sigma rules in Rust.

## Scope

- The condition expression language: boolean operators, grouping, and the
  `1 of` / `all of` quantifiers over identifier patterns.
- Rule metadata, log source, and detection definitions.
- Field modifiers.

## Non-goals

This crate does not evaluate rules and does not translate them to any query
language. Evaluation lives in `goliath-match`; backends are separate crates.

## Errors are precise

Every parse error carries a byte span into the source condition. Rule authoring
is increasingly done with assistance from tooling and language models, and both
depend on an error that names where and what, not just that something failed.

## License

[Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
