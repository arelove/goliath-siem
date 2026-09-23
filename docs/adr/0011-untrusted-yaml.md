# 0011. Parse rule YAML as untrusted input

- **Status:** Accepted
- **Date:** 2026-09-22

## Context

Detection rules arrive from community repositories, vendors, and threat intel
sharing. They are untrusted input to a process that sits on the security
team's most sensitive data. YAML is a large language with several features
that are dangerous or surprising in that position.

The previous de facto crate, `serde_yaml`, is deprecated. Its best-known
successor, `serde_yml`, carries
[RUSTSEC-2025-0068](https://rustsec.org/advisories/RUSTSEC-2025-0068.html).

## Decision

Use [`serde-saphyr`](https://crates.io/crates/serde-saphyr) with default
features off and only `deserialize` enabled, configured as follows:

| Option | Setting | Why |
| --- | --- | --- |
| `duplicate_keys` | `Error` (default) | A duplicate field in a selection silently drops a condition |
| `strict_booleans` | `true` | Otherwise `NO` and `off` become `false` |
| `reject_unsupported_tags` | `true` | Tags such as `!python/object` have no meaning in a rule |
| `budget` | on (default) | Bounds alias expansion and nesting |
| include, properties | compiled out | Neither may read files or the environment from a rule |

## Verified, not assumed

Each row was checked against the crate's actual behaviour before adoption, and
each is pinned by a test in `goliath-sigma`:

- a duplicate key is rejected with its line and column;
- with default settings `country: NO` deserializes to `false`, and with
  `strict_booleans` it stays the string `NO`;
- a ten-level alias expansion is rejected by the default budget;
- an unknown tag is rejected.

The boolean case is the one that justifies the ADR. It is not a parse error. It
is a rule that loads cleanly and compares a field against the wrong type,
forever.

## Options considered

| Option | Verdict |
| --- | --- |
| `serde_yaml` | Deprecated upstream |
| `serde_yml` | Open security advisory |
| `serde_norway` | No release since 2024 |
| `yaml-rust2` | Maintained, but no serde integration; we would reimplement deserialization |
| `serde-saphyr` | **Accepted**: maintained, `unsafe` forbidden, budgets, strict modes |

## When to revisit

`serde-saphyr` goes a year without a release, or gains an advisory.
