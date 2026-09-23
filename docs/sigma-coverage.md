# Sigma coverage

How much of the [SigmaHQ](https://github.com/SigmaHQ/sigma) rule repository
Goliath can load today, and what stops the rest. A rule counts as loaded when
it parses, resolves to OCSF paths through a shipped mapping set
([ADR-0012](adr/0012-sigma-field-mapping.md)), and compiles for the reference
evaluator.

Measured against SigmaHQ commit `16eb587` (2026-09-22) with the
`sigma-windows` mapping set, version 2.

## Summary

| Rule set | Rules | Parse failures | Loaded | Loaded where a mapping exists |
| --- | ---: | ---: | ---: | ---: |
| `rules` | 3,144 | 0 | 1,184 | 1,184 of 1,185 (99.9%) |
| `rules-emerging-threats` | 473 | 0 | 174 | 174 of 174 (100%) |
| `rules-threat-hunting` | 140 | 0 | 58 | 58 of 58 (100%) |

Every rule in all three sets parses. The rules that do not load are almost
entirely rules for log sources that have no mapping yet, which is expected: one
mapping entry exists so far, Windows process creation.

## What stops the rest

Log sources without a mapping, by number of rules in `rules`:

| Log source | Rules |
| --- | ---: |
| `registry_set`, Windows | 204 |
| `file_event`, Windows | 166 |
| `ps_script`, Windows | 163 |
| `security` service, Windows | 145 |
| `process_creation`, Linux | 122 |
| `image_load`, Windows | 100 |
| `process_creation`, macOS | 67 |
| `system` service, Windows | 63 |
| `cloudtrail`, AWS | 57 |
| `auditd`, Linux | 53 |
| `network_connection`, Windows | 51 |

This is the order in which mappings are worth writing: each row is the number
of rules one new mapping entry would make loadable.

Within Windows process creation, the one rule that does not load uses
`Provider_Name`, a field of the event log record rather than of the process,
which has no place in a process launch.

## Reproducing

```text
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
cargo run --release -p goliath-match --example sigma_coverage -- \
    sigma/rules crates/goliath-rule/mappings/sigma-windows.yaml
```

On Windows, the SigmaHQ checkout needs `git config core.longpaths true` first:
its regression data has paths longer than the default limit.

## Findings that changed the code

Running the whole repository found problems no hand-written test had:

- Keywords with a modifier, written `'|all':` with no field name, failed to
  parse in 12 rules. Supported since the fix in `goliath-sigma`.
- A regular expression using `\w{1,64}` exceeded a one megabyte compiled size
  limit, because `\w` is Unicode aware. The limit is now ten megabytes.
- `GrandParentImage` is used by rules although the Sigma taxonomy does not
  define it. It is now mapped.
