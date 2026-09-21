# Contributing

## Language

Everything that ships in this repository is written in English: code,
comments, identifiers, commit messages, documentation, error strings, and log
messages.

The sole exception is localized documentation. Translated files carry a
language suffix (`README_ru.md`, `README_es.md`) and never replace the English
original.

## Prose style

These rules apply to everything shipped: code comments, documentation, commit
messages, changelog entries, error strings, and release notes. All three are
checked in CI.

**No emoji.** Several changelog and commit tools emit them by default and are
configured not to. This project asks security teams to run it in regulated
environments where its output is read during audit review and incident
reporting. Prose that reads as informal is discounted there.

**No em or en dashes.** Use a plain hyphen. Long dashes survive copy and paste
badly, render inconsistently in terminals, and are not reliably typeable on
every keyboard a contributor uses.

**English only**, with the exception stated above.

## Invariants

These are not style preferences. Breaking one of them has taken down systems of
this class before, so they are enforced at review.

### Data boundary

ClickHouse is the source of truth for events. PostgreSQL is the source of
truth for state. **Events are never updated. State is never bulk-scanned.**

Rejected at review:

- Any `ALTER ... UPDATE` against ClickHouse outside a migration.
- Case status, assignment, or comments stored in ClickHouse.
- A PostgreSQL query issued from code that runs per event.
- A full scan of the entity table serving a UI request.

See [ADR-0003](docs/adr/0003-data-boundary.md).

### Hot path

Code on the per-event path must not perform network calls, allocate per event
where a buffer can be reused, or parse configuration. Configuration is compiled
into an immutable plan once and swapped atomically.

See [ADR-0004](docs/adr/0004-configuration-and-extensibility.md).

### Process boundaries

One language per service. Services communicate over Kafka or gRPC. FFI and cgo
between languages inside a single process are forbidden; the only cross-language
boundary is WASM plugins, where the sandbox and ABI are specified.

See [ADR-0005](docs/adr/0005-languages-and-process-boundaries.md).

### Benchmark honesty

Throughput is measured on synthetic load. Precision and recall are measured on
labelled real telemetry. Mixing the two data streams in one measurement is a
methodological error and is rejected at review.

See [docs/architecture.md](docs/architecture.md).

## Architecture decisions

Significant decisions are recorded as ADRs in [docs/adr/](docs/adr/) using the
[MADR](https://adr.github.io/madr/) format.

- Copy [docs/adr/0000-template.md](docs/adr/0000-template.md) to the next number.
- An accepted ADR is immutable. Changed your mind? Write a new ADR that
  supersedes it, and set the old one's status to superseded.
- Every ADR carries a "When to revisit" section with a checkable condition.
  "If it turns out to be wrong" is not a condition; "if p99 exceeds 5 s at 1M
  events/s" is.
- A change that contradicts an ADR does not merge without amending that ADR in
  the same pull request.

## Detection rules

A rule does not merge without tests. Each rule ships with:

- at least one sample that must fire (true positive),
- at least one sample that must not fire (true negative),
- a MITRE ATT&CK technique mapping,
- a stated false-positive profile.

Tests run against DuckDB over sample data, so the full test suite completes in
seconds without any infrastructure.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary`, imperative mood, lowercase summary, no trailing period.

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`.

Scope is the crate or component: `match-engine`, `ocsf`, `docs`, `ci`.

Keep the subject sharp and self-contained. It is what reaches the changelog,
so it must read as a release note on its own.

Add a body only when the reason is not evident from the diff, and keep it to a
few lines. Long commit messages do not get read, which defeats the point of
writing them.

Exception: any change to per-event code paths includes benchmark numbers before
and after in the body.
