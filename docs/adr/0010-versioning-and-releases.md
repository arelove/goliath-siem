# 0010. Versioning and releases

- **Status:** Accepted
- **Date:** 2026-09-21

## Context

This workspace holds two kinds of artifact with different audiences.
[ADR-0005](0005-languages-and-process-boundaries.md) publishes `goliath-sigma`,
`goliath-ocsf`, and the matching engine to crates.io for people who will never
run the platform. The platform itself is deployed by operators who care about
one version number, not eleven.

Releasing by hand does not survive contact with a real contribution rate, and a
changelog written after the fact is written badly or not at all.

## Decision

**Published library crates version independently under Semantic Versioning.
Releases are produced by automation from Conventional Commits. The changelog is
generated, never hand-edited.**

## Independent versions, not a shared one

A shared workspace version is simpler to operate and wrong for our audience. A
fix in the case service would bump `goliath-sigma` to a new version containing
no change to `goliath-sigma`. Someone depending on it for Sigma parsing alone
would see a stream of releases that never affect them, and would stop trusting
version numbers to mean anything.

The cost is that a contributor must reason about which crates a change affects.
Automation derives that from the dependency graph, so the cost falls on the
tooling rather than the contributor.

## Conventional Commits drive the bump

[CONTRIBUTING.md](../../CONTRIBUTING.md#commits) already requires Conventional
Commits. The mapping is mechanical:

| Commit type | Version bump | Appears in changelog |
| --- | --- | --- |
| `feat` | minor | Added |
| `fix` | patch | Fixed |
| `perf` | patch | Changed |
| `refactor`, `build`, `chore`, `ci` | patch | no |
| `docs`, `test` | none | no |
| Any type with `!` or a `BREAKING CHANGE` footer | major | Changed, marked breaking |

Because the bump is derived, a commit message is not cosmetic. A fix landed as
`chore` ships without a changelog entry, and the person who needed it never
learns it exists.

## The changelog is generated

[CHANGELOG.md](../../CHANGELOG.md) follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and is produced from
commit history by the release automation. Hand edits are overwritten.

To change what a release says, change the commit message before it merges. This
is the reason commit bodies are reviewed rather than skimmed.

## Pre-1.0

Until `1.0.0`, a minor bump may contain breaking changes, as SemVer permits for
`0.x`. Breaking changes are still marked in the changelog, because the marking
is what readers act on, not the number.

Reaching `1.0.0` for a crate is a deliberate act: it asserts the public surface
is one we will keep. Nothing reaches `1.0.0` before its first outside user.

## No emoji

No emoji in commit messages, changelog entries, code, comments, documentation,
or release notes. Default changelog templates for several tools emit them and
are configured not to.

This is not decoration policy. This project asks security teams to run it in
regulated environments where output is read in audit review and incident
reports. Prose that reads as informal is discounted there, and a changelog is
evidence.

## Consequences

- A commit that is typed wrongly produces a wrong release, so commit type is
  checked at review.
- Release notes cannot be improved after the fact without rewriting history,
  which raises the cost of a careless commit message deliberately.
- Publishing to crates.io needs a token held as a repository secret, which is a
  credential to rotate and audit.

## When to revisit

Independent versions prove to confuse operators more than a shared version
would confuse library consumers, measured by questions raised about which
version they are running.
