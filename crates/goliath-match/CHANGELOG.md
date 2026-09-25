# Changelog

All notable changes to this crate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Generated from commit history. See [RELEASING.md](../../RELEASING.md).

## [Unreleased]

## [0.1.1] - 2026-09-25

### Changed

- No change of its own. Its public API takes `goliath-rule` types, and that
  crate's 0.1.1 was a breaking release, so use 0.2.0, which depends on
  `goliath-rule` 0.2.

## [0.1.0] - 2026-09-25


### Added

- Add the reference evaluator
- Report Sigma repository coverage
- Run SigmaHQ regression events through the evaluator
- Convert every mapped Sysmon event in the regression run
- Add an engine that shares work across rules
- Compare and time the engine in the regression run
- Guarantee one engine can serve every thread
- Measure throughput on every core in the regression run
- Export the shipped Windows mapping set


### Changed

- Reuse working memory across events
- Evaluate non-string tests without allocating per test
- Prefer triggers on long literals, which occur less often
- Check class values without collecting them
- Write numbers into the reused text buffers
- Keep the value buffer across events
- Reuse one buffer for numbers tested by regex
- Wake regex rules only when their required text occurs


### Fixed

- Allow the compiled size of Unicode regex classes
