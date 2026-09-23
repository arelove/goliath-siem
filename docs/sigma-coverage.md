# Sigma coverage

How much of the [SigmaHQ](https://github.com/SigmaHQ/sigma) rule repository
Goliath can load today, and what stops the rest. A rule counts as loaded when
it parses, resolves to OCSF paths through a shipped mapping set
([ADR-0012](adr/0012-sigma-field-mapping.md)), and compiles for the reference
evaluator.

Measured against SigmaHQ commit `16eb587` (2026-09-22) with the
`sigma-windows` mapping set, version 3.

## Summary

| Rule set | Rules | Parse failures | Loaded | Loaded where a mapping exists |
| --- | ---: | ---: | ---: | ---: |
| `rules` | 3,144 | 0 | 1,705 | 1,705 of 1,706 (99.9%) |
| `rules-emerging-threats` | 473 | 0 | 251 | 251 of 251 (100%) |
| `rules-threat-hunting` | 140 | 0 | 90 | 90 of 90 (100%) |

Every rule in all three sets parses. The rules that do not load are almost
entirely rules for log sources that have no mapping yet. Mapped so far are the
five Windows log sources Sysmon produces most rules for: process creation, file
creation, image loads, network connections, and registry value sets.

### Fields kept as Sysmon wrote them

Some Sysmon fields map to `unmapped.<name>` rather than to an OCSF attribute
of similar meaning, because their values are Sysmon's text and rules compare
that text:

| Field | Sysmon writes | OCSF has | Rules using it |
| --- | --- | --- | ---: |
| `Details` (registry) | `DWORD (0x00000001)` | the value itself in `reg_value.data` | 312 |
| `Initiated` (network) | `true` | an enumeration, `connection_info.direction_id` | 49 |
| `Signed`, `SignatureStatus` (image load) | `true`, `Valid` | a structured `signature` object | 28 |

Mapping these properly needs value translation in the mapping format, not only
paths. Until then, the rules work on Sysmon data whose normalizer keeps the
original fields, and would not fire on another producer's OCSF events.

## What stops the rest

Log sources without a mapping, by number of rules in `rules`:

| Log source | Rules |
| --- | ---: |
| `ps_script`, Windows | 163 |
| `security` service, Windows | 145 |
| `process_creation`, Linux | 122 |
| `process_creation`, macOS | 67 |
| `system` service, Windows | 63 |
| `cloudtrail`, AWS | 57 |
| `auditd`, Linux | 53 |
| `auditlogs`, Azure | 44 |
| `activitylogs`, Azure | 35 |
| `ps_module`, Windows | 33 |
| `registry_event`, Windows | 32 |

This is the order in which mappings are worth writing: each row is the number
of rules one new mapping entry would make loadable.

Within Windows process creation, the one rule that does not load uses
`Provider_Name`, a field of the event log record rather than of the process,
which has no place in a process launch.

## Firing on real attacks

Loading a rule proves little: a loaded rule that never fires is worse than a
rule that refuses to load. SigmaHQ's `regression_data` holds, for many rules,
real Windows events recorded while the attack was performed, and the number of
times the rule must fire on them. Each case is run end to end: the events are
converted from Sysmon to OCSF, and the resolved rule is evaluated by the
reference evaluator.

| Outcome | Cases |
| --- | ---: |
| Regression cases in SigmaHQ | 460 |
| Run | 357 |
| Fired exactly as SigmaHQ expects | 357 |
| Failed | 0 |
| Skipped: no mapping for the rule's log source | 101 |
| Skipped: events refused by antivirus software | 1 |
| Skipped: malformed case description | 1 |

Every case whose rule loads passes. To confirm the check can fail at all, it
was run twice with a deliberate fault:

- case folding switched off in the evaluator: 129 of the 276 process creation
  cases failed;
- four fields of the newer mappings pointed at the wrong attribute
  (`TargetObject`, `ImageLoaded`, `TargetFilename`, `DestinationHostname`): 76
  of 357 cases failed.

What this does and does not show:

- It shows that parsing, modifier handling, resolution, and evaluation agree
  with SigmaHQ on real attack telemetry.
- It does not show on its own that the mapping chose the right OCSF
  attributes. The Sysmon to OCSF conversion used here is a stand-in for the
  Sysmon source definition of milestone M2, written by the same project as the
  mapping, so an attribute chosen wrongly in both would go unnoticed. The M2
  source definition, tested against its own fixtures, closes that gap.

Each event is also evaluated against every other loaded rule. 152 rules fire on
at least one other rule's attack. That is expected, since attacks share steps,
but the most frequent are the first candidates for review as overly broad:
"Non Interactive PowerShell Process Spawned" fires on 47 other rules' events.

## The engine on the same events

The regression run also compiles every loaded rule into the engine, which
shares work across rules, and checks that it returns exactly the rules the
reference evaluator returns for every converted event. Then it times both, each
for at least three seconds on one core.

| Measure | Value |
| --- | ---: |
| Rules | 2,046 |
| Events | 393 |
| Rule matches | 738 |
| Events where engine and reference disagree | 0 |
| Engine compile time | 87 ms |
| Reference evaluator | 305 events/s |
| Engine | 129,437 events/s |

Measured on an AMD Ryzen 9 9955HX, one core, Rust 1.96, release build; the
median of three runs.

How the engine got there from its first version, each step measured the same
way:

| Change | Events/s |
| --- | ---: |
| First version | about 38,000 |
| Working memory reused across events, ASCII folded without table lookups, paths read without collecting | about 88,000 |
| Non-string tests read values without allocating per test | about 102,000 |
| Triggers chosen by literal length: 30 rules evaluated per event instead of 41 | about 110,000 |
| No allocation at all per event once warmed up | about 114,000 |
| Regular expressions wait for the literals they require, found for 55 of the 82 distinct expressions | about 129,000 |

A switch of the literal automaton from its default to a full DFA was measured
too and rejected: no gain beyond noise, at twice the compile time.

Allocation was most of the first version's cost, and a change that brings it
back would slow the engine without failing a test that checks answers.
`crates/goliath-match/tests/allocations.rs` therefore counts allocations
while a warmed up engine evaluates events of every kind of test, and fails on
any. Unlike a timing, the count is exact, so CI can hold it.

How to read these numbers:

- The engine's rate is the figure that matters. The reference evaluator is
  deliberately naive, so the ratio between them says little.
- The events are recorded attacks, which wake far more rules than ordinary
  activity does. Benign traffic should evaluate faster; that is for the
  benchmark rig of milestone M3 to measure, not to assume.
- At this rate the 1,000,000 events/s target takes about 8 cores. A profile
  of this run puts about half of an event's time in the literal automata,
  whose cost per byte grows with their size (10,835 literals on the command
  line alone), and under a sixth in walking `serde_json` trees by path. So
  the next steps are to take suffix, prefix, and exact literals out of full
  scans, and to stop reporting one-character literals that occur in nearly
  every text, before changing how events are represented.

## Reproducing

```text
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
cargo run --release -p goliath-match --example sigma_coverage -- \
    sigma/rules crates/goliath-rule/mappings/sigma-windows.yaml
```

The regression run takes the checkout root instead of the rules directory:

```text
cargo run --release -p goliath-match --example sigma_regression -- \
    sigma crates/goliath-rule/mappings/sigma-windows.yaml
```

On Windows, the SigmaHQ checkout needs `git config core.longpaths true` first:
its regression data has paths longer than the default limit. Antivirus
software may also quarantine some recorded attack events; the run reports them
as skipped rather than failing.

## Findings that changed the code

Running the whole repository found problems no hand-written test had:

- Keywords with a modifier, written `'|all':` with no field name, failed to
  parse in 12 rules. Supported since the fix in `goliath-sigma`.
- A regular expression using `\w{1,64}` exceeded a one megabyte compiled size
  limit, because `\w` is Unicode aware. The limit is now ten megabytes.
- `GrandParentImage` is used by rules although the Sigma taxonomy does not
  define it. It is now mapped.
