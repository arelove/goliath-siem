# Benchmarks

Two different questions are answered by two different kinds of measurement:

| Question | Measured by | Where |
| --- | --- | --- |
| How fast is the engine on real rules and real attacks? | Wall clock, events per second on one core | [sigma-coverage.md](sigma-coverage.md#the-engine-on-the-same-events) |
| Did this change make the engine slower? | Instructions counted by Callgrind, compared with the base of the pull request | This document, and CI |
| Did this change make evaluation allocate again? | Allocations counted per event | `crates/goliath-match/tests/allocations.rs` |

## Why instruction counts in CI

A timing on a shared CI runner moves by tens of percent from run to run, with
the load of other tenants, the CPU model the job lands on, and its frequency.
A gate on timings either fails at random or has a limit too wide to catch
anything. Callgrind counts the instructions the program executes on a
simulated CPU, which is the same on every run of the same binary, so a
limit of 2% is meaningful.

Instruction counts are not time. They do not see cache misses, branch
mispredictions, or instruction level parallelism, so a change can lower the
count and still run slower, or the reverse. That is why the speed claim stays a
wall clock measurement on real data, and the instruction count only guards
against regressions between one commit and the next.

## What is measured

`crates/goliath-bench` generates a workload from a fixed seed: 2,000 Sigma
rules in the shapes of `SigmaHQ`'s Windows process creation rules, and 1,000
process launches. About one launch in ten is suspicious; four in ten of the rest
are ordinary uses of the binaries attackers also use, such as `rundll32.exe
shell32.dll,Control_RunDLL`, which wake rules that must then reject them. The rules are resolved through
the shipped mapping, like real ones. The workload is synthetic on purpose:
`SigmaHQ` is not vendored into this repository, and a guard needs the same
input on every run more than it needs realism.

| Benchmark | Measures |
| --- | --- |
| `engine::compile` | `Engine::new` on the 2,000 rules |
| `engine::evaluate` | `Engine::matches_into` on the 1,000 events, with a scratch already warmed up, as in a long running detector |

Building the workload and warming up happen in setup functions, which
Callgrind does not count.

## In CI

The `Benchmarks` workflow runs on every pull request:

1. It checks out the base commit of the pull request and records its counts.
2. It measures the pull request against them.
3. It fails if any count grew by more than 2%.

The baseline is measured afresh each time rather than committed. A committed
baseline goes stale as soon as the compiler, a dependency, or the runner
changes, and then every pull request is compared against numbers no current
build can produce.

The gate was checked with two throwaway pull requests before it was trusted:

| Change | `compile` | `evaluate` | Result |
| --- | ---: | ---: | --- |
| A comment only | -0.18% | -0.04% | Passed |
| ASCII folded through the Unicode table instead of the fast path | -0.18% | +14.5% | Failed |

Separate builds of the same code differ by up to 0.2%, a tenth of the limit.
A first attempt at the first check showed 0.00% for both changes: the base
and the change shared a target directory, and the change was never rebuilt.
The workflow now builds the base in a directory of its own, and a gate is
only trusted once it has been seen to fail.

When a slowdown is the right trade, say so in the pull request and raise the
limit for that one merge; the next pull request is then measured against the
new base.

## Running it locally

Linux only, because Valgrind is. Install Valgrind, and `gungraun-runner` of the
version of `gungraun` in `Cargo.lock`:

```text
sudo apt-get install valgrind
cargo install gungraun-runner --version <version in Cargo.lock> --locked
cargo bench -p goliath-bench --features callgrind --bench engine
```

To compare a change with `main`:

```text
git switch main
cargo bench -p goliath-bench --features callgrind --bench engine -- --save-baseline=main
git switch -
cargo bench -p goliath-bench --features callgrind --bench engine -- --baseline=main
```
