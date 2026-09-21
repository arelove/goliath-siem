# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

### Added

- Sigma condition expression language: tokenizer, recursive descent parser, and
  a typed AST carrying source spans on every node.
- Quantifiers `1 of` and `all of` over `them` or an identifier pattern.
- Errors carrying byte spans into the source condition.
- Field modifier parsing, preserving modifier order and refusing unknown
  names, stray regex flags, and conflicting combinations.
