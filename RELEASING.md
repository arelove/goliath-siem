# Releasing

Releases are automated. The policy behind this process is
[ADR-0010](docs/adr/0010-versioning-and-releases.md).

## What happens without anyone doing anything

1. A pull request merges to `main`.
2. `.github/workflows/release.yml` runs `release-plz release-pr`.
3. It reads the Conventional Commit types since the last release, decides which
   crates changed and by how much, bumps their versions, and regenerates their
   changelogs.
4. It opens or updates a pull request titled `chore: release`.

That pull request is the release. Nothing is published until it merges.

## What a human does

**Review the release pull request.** The diff shows the version bumps and the
exact changelog text that will ship. This is the last point at which a badly
worded commit message can be caught, because the changelog is generated from
commit history and cannot be edited afterwards without rewriting history.

**Merge it.** On merge, the `publish` job tags the release, creates the GitHub
release, and publishes the affected crates to crates.io.

## Version bumps are derived, not chosen

| Commit type | Bump | Changelog section |
| --- | --- | --- |
| `feat` | minor | Added |
| `fix` | patch | Fixed |
| `perf` | patch | Changed |
| `refactor`, `build`, `chore`, `ci` | patch | not listed |
| `docs`, `test` | none | not listed |
| Any type with `!` or a `BREAKING CHANGE` footer | major | Changed, marked breaking |

A fix landed as `chore` ships with no changelog entry, and the person who
needed it never learns it exists. Commit type is checked at review for this
reason.

## Crates version independently

A change to the platform must not bump `goliath-sigma` for someone who depends
on it only for Sigma parsing. Each crate carries its own version and its own
`CHANGELOG.md`; the root [CHANGELOG.md](CHANGELOG.md) aggregates.

## Required repository secrets

| Secret | Used for |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | Publishing to crates.io |

`GITHUB_TOKEN` is provided by Actions and needs no configuration.

Rotate `CARGO_REGISTRY_TOKEN` on the same schedule as any other deployment
credential.

## Releasing by hand

Do not. If automation is broken, fix the automation. A release produced by hand
skips the review step that catches a wrong version bump, and leaves the
changelog disagreeing with the tags.
