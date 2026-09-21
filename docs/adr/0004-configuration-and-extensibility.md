# 0004. Configuration compiles; extensions are WASM

- **Status:** Accepted
- **Date:** 2026-09-21

## Context

The system must be configurable by its operators: which sources to collect,
how to parse them, how to map fields, what thresholds apply, how long to
retain. The obvious approach is to describe all of it in JSON and interpret it.
On a 1M events/s hot path that is wrong twice - on performance and on structure.

## Decision

1. Configuration is parsed once and **compiled into an execution plan**. Nothing
   interprets configuration per event.
2. Logic is expressed in **declarative DSLs** (Sigma for detections, CEL or VRL
   for expressions), not in configuration flags.
3. Arbitrary user logic is a **WASM plugin**, not a repository fork.
4. The surface format is **TOML or YAML**; validation is **JSON Schema**.

## Why not interpreted JSON

### Cost on the hot path

Walking a configuration tree per event at 1M events/s means millions of
allocations and cache misses per second. The correct order is: parse →
validate → **compile into an immutable plan** (predicate index, bitmaps,
transition tables) → swap the plan atomically by version. The hot path reads
only the compiled artifact.

### The inner platform effect

An infinitely configurable system becomes a bad programming language:
conditionals, loops, and variables expressed in YAML. The boundary rule:

- **Configuration expresses "what"** - which sources, which fields, which
  thresholds, which retention.
- **A DSL expresses "how we look"** - a Sigma rule, a CEL expression.
- **A plugin expresses "how we process"** - arbitrary sandboxed code.

A proposed configuration flag must answer: "what different value would two real
operators set here?" If there is no such value, it is code, not configuration.

### JSON is hostile to humans

No comments, no trailing commas, painful multi-line values. The surface format
is TOML for flat configuration and YAML for nested, under a strict schema.
JSON Schema remains the canonical validation layer regardless of surface
format: one schema yields validation, IDE completion, and generated
documentation.

## Extensibility through WASM

Operators need their own parsers, enrichers, and playbook actions. The options
are forking (unacceptable), an embedded scripting language (slow, unsafe), or
dynamic libraries (unsafe, ABI-fragile).

We use WASM via Wasmtime:

- sandboxed by default, capabilities denied by default;
- near-native speed;
- plugins authored in any language that compiles to WASM;
- memory and per-call execution time limits;
- precedent: Envoy filters, Redpanda data transforms.

Plugin boundaries: source parser, enricher, playbook action, alert exporter.
The match engine stays native.

## Configuration authored by language models

AI-assisted configuration works because the schema is strict and errors are
legible, not because the format is JSON. Every configurable object requires:

- a JSON Schema with field descriptions and enumerated values;
- validation before apply, naming the field path and the permitted values;
- at least three worked examples beside the schema;
- `--dry-run`, printing the compiled plan without applying it.

A schema meeting that bar is equally well filled in by a human, an IDE, or a
language model. There is no separate "AI mode" for configuration.

## Consequences

- Changing configuration requires recompiling a plan, so atomic hot swap with
  versioning and rollback is a first-class requirement, not an optimization.
- A plugin ABI boundary exists and must be versioned from the first release.
- Some flexibility is deliberately unreachable through configuration and
  requires a plugin. This is a conscious refusal to make everything tunable.

## When to revisit

WASM call overhead proves significant on the per-event path - measured at more
than 5% of processing time - in which case those specific extension points move
to native interfaces.
