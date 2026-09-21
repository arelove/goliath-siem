# goliath-sigma

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

[Apache License 2.0](../../LICENSE).
