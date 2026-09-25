# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

## [0.1.0] - 2026-09-25


### Added

- Parse Sigma condition expressions into a typed AST
- Parse field modifiers
- Parse detection values and wildcard patterns
- Expose the hardened YAML loader


### Fixed

- Bound wildcard matching to linear backtracking
- Keep the text of values as written
- Keep underscore searches out of quantifiers as pySigma does
- Accept modifiers on keywords, as in '|all'

### Added

- Sigma condition expression language: tokenizer, recursive descent parser, and
  a typed AST carrying source spans on every node.
- Quantifiers `1 of` and `all of` over `them` or an identifier pattern.
- Errors carrying byte spans into the source condition.
- Field modifier parsing, preserving modifier order and refusing unknown
  names, stray regex flags, and conflicting combinations.
- Detection values: string patterns with wildcard and escape semantics,
  integers, floats, booleans, and null.
- Rule parsing: metadata, log source, and detection searches, loaded through
  hardened YAML settings that refuse duplicate keys, unsupported tags, alias
  expansion beyond a budget, and YAML 1.1 booleans such as `NO`.
- Rejection of conditions naming undefined searches, and of quantifier
  patterns that match no search.
- Rejection of values their modifiers cannot compare, such as `exists` without
  a boolean or `base64offset` without `contains`.
