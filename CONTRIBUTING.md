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

## Tests that need a server

Most tests need nothing but cargo. The event store's tests need ClickHouse,
and the Kafka tests and the benchmark rig need a Kafka API; without them
those tests are skipped locally and run in CI. To run them on your machine,
with Docker:

```sh
docker compose -f compose.dev.yaml up -d --wait
. scripts/dev-env.sh
cargo test -p goliath-store -p goliath
cargo test -p goliath-pipe -p goliath --features kafka
docker compose -f compose.dev.yaml down -v
```

- `compose.dev.yaml` starts ClickHouse and Redpanda on 127.0.0.1 only. It is
  not the platform; that is `compose.yaml`. Both publish port 8123, so run
  one of them at a time.
- `scripts/dev-env.sh` reads the ClickHouse password from `.env` and sets the
  variables the tests read. Make `.env` from `.env.example` first.
- The last command deletes what the tests stored.

## Running the platform from the working tree

To see a change in the interface without building the image:

```sh
docker compose -f compose.dev.yaml up -d --wait
scripts/dev-run.sh
```

In PowerShell `bash` is the one of WSL, which has no `cargo`. Name Git's:

```powershell
& "C:\Program Files\Gitinash.exe" scripts/dev-run.sh
```

It builds the interface if its sources changed, and runs every role from
`cargo` against the ClickHouse of `compose.dev.yaml`, with
[deploy/dev.toml](deploy/dev.toml). Open <http://127.0.0.1:8080>; on the
loopback address it asks for no token. Drop Sysmon events into
`inbox/sysmon/`. Nothing is downloaded beyond the two images the compose
file names.

## Branches and pull requests

Nothing lands on `main` directly. Work happens on a branch and merges through a
pull request, so CI gates every change and the reasoning stays attached to it.

Branch names use the Conventional Commit type of the work, then a short
description:

```
feat/sigma-field-modifiers
fix/normalizer-dead-letter-ordering
docs/contribution-workflow
perf/match-engine-predicate-index
```

Keep a branch to one reviewable change. A branch that has grown two unrelated
changes is two branches.

Merge with a squash only when the branch's commits are noise; otherwise keep
them, because each one is a changelog candidate and a bisect point.

### Branch protection

`main` requires a pull request and a passing CI run. Configure this under
Settings, Branches, in the repository: require a pull request before merging,
and require the `test`, `lint`, and `prose` checks to pass.

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

Prefer many small commits over few large ones. One logical change per commit:
a commit that needs "and" in its subject is two commits. Small commits are
reviewable, revertable in isolation, and bisectable when something breaks.

Keep the subject sharp and self-contained. It is what reaches the changelog,
so it must read as a release note on its own.

Add a body only when the reason is not evident from the diff, and keep it to a
few lines. Long commit messages do not get read, which defeats the point of
writing them.

Exception: any change to per-event code paths includes benchmark numbers before
and after in the body.
