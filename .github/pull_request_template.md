## What changes

One or two sentences. The commit subjects carry the detail.

## Why

Only if it is not evident from the diff.

## Checks

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets` is clean
- [ ] Commit types are correct: they decide the version bump and the changelog
- [ ] An ADR is amended in this pull request if it contradicts one
- [ ] Benchmark numbers are in the commit body if a per-event path changed
- [ ] A detection rule, if added, ships a firing and a non-firing fixture
