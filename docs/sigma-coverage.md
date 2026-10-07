# Sigma coverage

How much of the [SigmaHQ](https://github.com/SigmaHQ/sigma) rule repository
Goliath can load today, and what stops the rest. A rule counts as loaded when
it parses, resolves to OCSF paths through a shipped mapping set
([ADR-0012](adr/0012-sigma-field-mapping.md)), and compiles for the reference
evaluator.

Measured against SigmaHQ commit `16eb587` (2026-09-22) with the
`sigma-windows` mapping set, version 5.

## Summary

| Rule set | Rules | Parse failures | Loaded | Loaded where a mapping exists |
| --- | ---: | ---: | ---: | ---: |
| `rules` | 3,144 | 0 | 1,827 | 1,827 of 1,851 (98.7%) |
| `rules-emerging-threats` | 473 | 0 | 266 | 266 of 270 (98.5%) |
| `rules-threat-hunting` | 140 | 0 | 92 | 92 of 93 (98.9%) |

Every rule in all three sets parses. The rules that do not load are almost
entirely rules for log sources that have no mapping yet. Mapped so far are the
five Windows log sources Sysmon produces most rules for: process creation, file
creation, image loads, network connections, and registry value sets; and the
Windows Security log.

### The Security log

Rules for the Security log select events by `EventID`, and one Windows field
lands on different OCSF attributes in different events, so the mapping lists
every attribute a field is written to, and its place under `unmapped`.

The `windows-security` definition reads 49 event IDs, chosen by what SigmaHQ's
rules ask for. 122 of the 145 rules in `rules` load. The 23 that do not name
fields of events it does not read yet, each used by three rules or fewer, such
as `TargetName` of 5379 (credentials read from the vault) and
`TemplateContent` of certificate services events.

Of the rules that load, about ten name only events the definition does not
read, all of them rare: 4611, 4616, 4649, 4674, 4692, 4706, 4794, 4800, 4825,
and 6423. They load and cannot fire until it does. A few more name several
events of which it reads some, such as 4658 beside 4656 and 4663, and fire on
those.

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

### AWS CloudTrail

The `sigma-aws` mapping set, version 1, maps CloudTrail rules to what the
`cloudtrail` source definition writes. 56 of the 57 CloudTrail rules in
`rules` load. The one that does not compares a field named `status`, which
CloudTrail does not write, so it could not fire on CloudTrail records in any
product.

Rules select calls by `eventSource` and `eventName`, and many compare the
request or the response, such as `requestParameters.bucketName`. The
definition keeps those objects whole under `unmapped` as CloudTrail wrote
them, so each such field is one line of the mapping. SigmaHQ has no
regression data for AWS; the fixtures of the definition are checked against
rules written the same way in `goliath-match`.

### Okta

The `sigma-okta` mapping set, version 1, maps Okta rules to what the `okta`
source definition writes. All 23 Okta rules in the three sets load. Rules
select events by `eventType`, and the definition gives every event its type
in `metadata.event_code`, including the hundreds of types without a kind of
their own, so none of them loads without being able to fire. Targets are
compared whatever their place in Okta's `target` array.

SigmaHQ's Okta rules compare `securityContext.isProxy` with `'true'`, quoted,
where Okta writes a JSON boolean. String tests read booleans as `true` or
`false`, as they read numbers as their decimal text, so these rules fire as
their authors meant.

### Microsoft 365

The `sigma-m365` mapping set, version 1, maps Microsoft 365 rules to what the
`m365` source definition writes from the unified audit log. 20 of the 21
rules in the three sets load.

Rules for the `audit` service name the audit log's own fields, such as
`Operation`, `Workload`, and `ResultStatus`. Where Microsoft writes a list of
names and values, as for an Exchange cmdlet's `Parameters` or a sign-in's
extended properties, a field is compared with every name and value of the
list: `RequestType: 'Cmsi:Cmsi'` holds when any extended property has that
value, a test slightly looser than one of the property of that name alone.

Rules for the `exchange`, `threat_management`, and `threat_detection`
services name `eventSource`, `eventName`, and `status`, which the audit log
does not write. They are read as the record's workload, its operation or, for
an alert of the Security & Compliance Center, the alert's name, and its
result, so that "Impossible travel activity" fires on the `AlertTriggered`
record of that alert. The one rule that does not load compares `Payload`,
which the mapping has no attribute for: no other rule names it, and the
audit log has no property of that name.

### Zeek

The `sigma-zeek` mapping set, version 1, maps Zeek rules to what the `zeek`
source definition writes from the json-streaming-logs package. All 24 Zeek
rules in the three sets load. Each log is selected by its name, and a
connection's endpoints, `id.orig_h` and the rest, are the OCSF source and
destination in every log.

Two of SigmaHQ's DCE/RPC rules, from the BZAR set, pair each interface with
a call the other way round from Zeek: `endpoint: JobAdd` and
`operation: atsvc`, where Zeek logs `endpoint` `atsvc` and `operation`
`JobAdd`. They load, and cannot fire on Zeek logs in any product; the
mapping reads the fields as Zeek names them rather than swapping them for
these rules.

## ATT&CK coverage

`goliath-attack` reads ATT&CK from the STIX bundles MITRE publishes and asks
two questions of each current technique: does a rule detect it, and can that
rule fire, which it can when it loads through a shipped mapping set whose log
source a shipped definition supplies
([ADR-0009](adr/0009-attack-knowledge-model.md)). Against Enterprise ATT&CK
19.2, the 3,144 rules of `rules`, and every shipped definition:

| Current techniques | Of 697 |
| --- | ---: |
| Detected: a rule that can fire | 302 |
| Blind: rules, none of which can fire | 88 |
| Collected: no rule, but data to detect it, as ATT&CK's detection strategies name it | 240 |
| Uncovered | 67 |

The blind techniques are those whose rules read log sources with no mapping
yet, such as ESXi, macOS, Linux, Azure, Kubernetes, Bitbucket, and web
servers. They are the next mappings to write, in the order
[What stops the rest](#what-stops-the-rest) gives by rule count. With Sysmon
alone, 264 techniques are detected and 126 blind. No SigmaHQ rule is tagged
with a revoked or deprecated technique.

Every definition declares the ATT&CK data components its records supply,
checked against ATT&CK in CI, so that the collected column follows the
sources configured. Reproduce with:

```text
cargo run --release -p goliath-attack --example attack_coverage --     enterprise-attack-19.2.json <sigma>/rules all layer.json
```

`layer.json` opens in the ATT&CK Navigator, coloured by verdict, each
technique listing its rules and those that cannot fire.

## What stops the rest

Log sources without a mapping, by number of rules in `rules`:

| Log source | Rules |
| --- | ---: |
| `ps_script`, Windows | 163 |
| `process_creation`, Linux | 122 |
| `process_creation`, macOS | 67 |
| `system` service, Windows | 63 |
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
normalized to OCSF by the Sysmon and Windows Security source definitions of
`goliath-normalize`, each reading its own provider's records, exactly as a
deployment would, and the resolved rule is evaluated by the reference
evaluator. All 395 events of the loaded cases normalize with no value that
fails to convert.

| Outcome | Cases |
| --- | ---: |
| Regression cases in SigmaHQ | 460 |
| Run | 359 |
| Fired exactly as SigmaHQ expects | 359 |
| Failed | 0 |
| Skipped: no mapping for the rule's log source | 99 |
| Skipped: events refused by antivirus software | 1 |
| Skipped: malformed case description | 1 |

Every case whose rule loads passes. Two of them are Security log cases, a
logon with explicit credentials (4648) and a scheduled task disabled (4701):
few, since SigmaHQ records most of its regression data with Sysmon, but real
Windows records read by the `windows-security` definition as they are. To confirm the check can fail at all, it
was run twice with a deliberate fault:

- case folding switched off in the evaluator: 129 of the 276 process creation
  cases failed;
- four fields of the newer mappings pointed at the wrong attribute
  (`TargetObject`, `ImageLoaded`, `TargetFilename`, `DestinationHostname`): 76
  of 357 cases failed.

What this does and does not show:

- It shows that normalization, parsing, modifier handling, resolution, and
  evaluation agree with SigmaHQ on real attack telemetry.
- It does not show on its own that the two chose the right OCSF attributes.
  The source definition and the mapping set are written by the same project,
  so an attribute chosen wrongly in both would go unnoticed. What is checked
  is that both use the schema correctly: each loads only if every path is an
  attribute of its OCSF 1.5.0 class, and every constant or conversion fits
  the attribute's type. That rules out a misspelled or invented attribute,
  though not a real one chosen for the wrong meaning.

Each event is also evaluated against every other loaded rule. 152 rules fire on
at least one other rule's attack. That is expected, since attacks share steps,
but the most frequent are the first candidates for review as overly broad:
"Non Interactive PowerShell Process Spawned" fires on 47 other rules' events.

## The engine on the same events

The regression run also compiles every loaded rule into the engine, which
shares work across rules, and checks that it returns exactly the rules the
reference evaluator returns for every converted event. Then it times both, each
for at least three seconds on one core.

With the Security mapping, 2,185 rules load, and the engine still agrees with
the reference evaluator on all 395 events; a single run then measured about
125,000 events/s on one core, in line with the table below, which was
measured with 2,046 rules.

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

### On every core

One engine is shared by every thread of a detector, each thread keeping its
own scratch, so nothing is locked or copied per event. The run measures that
too, for three seconds at each thread count:

| Threads | Events/s |
| ---: | ---: |
| 1 | about 125,000 |
| 16 | about 1,250,000 to 1,310,000 |
| 32 | about 2,050,000 to 2,230,000 |

The 9955HX has 16 cores and 32 hardware threads, so the machine the numbers
come from, a laptop, clears the 1,000,000 events/s target for detection with
all 2,046 rules. Two cautions go with that. The threads were not pinned to
cores, so counts between 2 and 8 moved by up to half between runs, depending
on where Windows placed them; the full machine was stable within 10%. And
this is detection alone, on events already parsed: ingestion, parsing, and
storage have their own cost, which milestone M3 measures end to end.

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

Measured and rejected, because a profile's promise is not a result:

| Change | Result |
| --- | --- |
| A full DFA instead of the default automaton | No gain beyond noise, twice the compile time, 77 MB for the command line alone |
| Suffix, prefix, and exact literals found by walking a trie from one end of the text, instead of the full scan | About 7% slower: nearly every field also has a few substring literals, so the scan stays and the walks come on top |
| One-byte substring literals, such as a space, tested directly instead of scanned for | Within noise: fewer reports from the automaton, but the rules they triggered are then evaluated on every event |

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
- A profile of this run puts about half of an event's time in the literal
  automata, at about 4 ns per byte of text whatever their size, and under a
  sixth in walking `serde_json` trees by path. The two changes above that
  aimed at the automata did not pay, so what remains is scanning fewer
  bytes: the command line is scanned twice, folded and as written, for the
  103 literals of case sensitive rules.

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
