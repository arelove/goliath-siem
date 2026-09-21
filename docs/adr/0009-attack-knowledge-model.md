# 0009. Adversary knowledge model

- **Status:** Accepted
- **Date:** 2026-09-21

## Context

MITRE ATT&CK is how this industry communicates. Rules, alerts, cases, and
coverage reports all reference it. But ATT&CK is one framework among several
(D3FEND, ATLAS, and various national frameworks), it releases breaking
versions, and hardcoding it would make every other framework a fork.

## Decision

Model a **generic adversary knowledge framework**, with ATT&CK as the first
implementation. Pin framework versions explicitly and treat upgrades as
migrations.

## Source of truth

ATT&CK content is ingested from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data),
the official STIX 2.1 bundles. We never transcribe technique lists by hand.

Objects modeled: tactic, technique, sub-technique, data source, data component,
mitigation, group, software, and campaign, with the relationships between them.

## Versions are pinned

A deployment pins a framework version. This is not optional bookkeeping:
ATT&CK deprecates and renumbers content between releases. Technique T1086,
PowerShell, became sub-technique T1059.001 under Command and Scripting
Interpreter; techniques merge, split, and retire.

Upgrading is an explicit migration that reports which rules reference content
that moved, and which references broke. Silent remapping is forbidden, because
it would quietly change what every coverage report claims.

## Where mappings attach

| Object | Mapping |
| --- | --- |
| Detection rule | One or more techniques, required at merge |
| Alert | Inherited from the rule that produced it |
| Case | The union over its alerts, as an attack narrative |
| Source definition | The data components it supplies |

That last row is what makes the model useful rather than decorative.

## Coverage versus capability

Two different questions are usually conflated, and separating them is the
feature operators actually want.

**Coverage:** do we have a rule for this technique?

**Capability:** do we collect the telemetry that rule needs?

Because source definitions declare the data components they supply
([ADR-0007](0007-source-and-parser-model.md)), we can answer both, and can
report the case that matters most: a rule exists for this technique, but no
configured source supplies the data it requires, so it can never fire.

No open-source tool reports this today. It is cheap for us because both halves
are already modeled.

Coverage is exportable as an ATT&CK Navigator layer, since that is the format
security teams already use in reviews and board reporting.

## Generic framework, first implementation

The storage model is framework-agnostic: a framework has versioned objects with
typed relationships, and mappings reference a framework, a version, and an
object identifier. ATT&CK Enterprise is the first loaded framework. ATT&CK ICS,
ATT&CK Mobile, D3FEND, and ATLAS load through the same path without code
changes.

This costs very little now and avoids a fork later when a deployment is
required to report against a framework we did not anticipate.

## Consequences

- Framework content is refreshed on a schedule and is a versioned artifact in
  its own right, not a static file in the repository.
- Every coverage number must state which framework version produced it, or it
  is not comparable across time.
- Rules referencing deprecated content are surfaced as technical debt rather
  than failing silently.

## When to revisit

A framework appears that does not fit the versioned-objects-with-relationships
shape, requiring a second storage model rather than another loader.
