# Benchmarks

Two different questions are answered by two different kinds of measurement:

| Question | Measured by | Where |
| --- | --- | --- |
| How fast is the engine on real rules and real attacks? | Wall clock, events per second on one core and on every core | [sigma-coverage.md](sigma-coverage.md#the-engine-on-the-same-events) |
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

## The disk pipe

`goliath-pipe` has a throughput example, run by hand rather than in CI because
it measures the disk:

```text
cargo run --release -p goliath-pipe --example throughput
```

It sends 200,000 records of 400 bytes in batches of 1,000, syncing each batch
to disk, while one group reads and acknowledges them, on a single-threaded
runtime with a task that ticks every millisecond beside them. On the
reference laptop (NVMe, Windows 11):

| Version | Records/s | MB/s | Runtime free |
| --- | ---: | ---: | ---: |
| File I/O on the runtime's thread | 300,000 | 120 | 0% |
| File I/O on blocking threads | 310,000 | 124 | 99% |

The throughput barely moves, but the first version kept every other task on
the runtime waiting for the whole run: a network listener sharing it would
have accepted nothing. The rate is bound by one sync per batch, so larger
batches raise it.

## Search

The M2.5 exit criterion asks for a search over 10 million stored events,
filtered by time, class, and one path, to return in under one second. The
`search` benchmark stores them and times the searches the interface sends:

```text
GOLIATH_CLICKHOUSE_URL=http://127.0.0.1:8123 GOLIATH_CLICKHOUSE_USER=goliath \
GOLIATH_CLICKHOUSE_PASSWORD=... \
cargo run --release -p goliath-bench --features search --bin search
```

The events are a synthetic fleet of 2,000 Windows machines running Sysmon over
30 days, generated from a fixed seed: image loads, network connections,
process launches, file creation, and registry writes, in the proportions a
workstation fleet writes them. They go through the shipped Sysmon definition
and `Store::write`, the path the writer role takes, into a database of their
own, which a second run reuses. Each search runs five times; rows read are
the server's own count for the last run.

On the reference laptop (Ryzen 9 9955HX, 32 GB, Windows 11), against
ClickHouse 25.8 in Docker Desktop, the 10 million events were stored at about
62,000 events/s, and the searches took:

| Search | Median, sorting key only | Rows read | Median, with the time index | Rows read |
| --- | ---: | ---: | ---: | ---: |
| Last hour, every class | 444 ms | 2,415,700 | 38 ms | 41,808 |
| Last 24 hours, launches, command line contains | 156 ms | 499,712 | 68 ms | 155,648 |
| Last 24 hours, every class, one host | 532 ms | 2,718,225 | 92 ms | 511,822 |
| Last 7 days, connections, destination port | 319 ms | 1,385,207 | 213 ms | 994,032 |
| Last 30 days, launches, one user | 740 ms | 4,251,648 | 806 ms | 4,251,648 |

The sorting key is `(class_uid, time, id)`, and parts are partitioned by the
day an event was received, not by its time. A search over every class could
only narrow `time` within each class, in every part, so the last hour read a
quarter of the table. A minmax index on `time`, one entry per granule, skips
every granule outside the window instead.

The index alone made it worse, at first: with `FINAL`, ClickHouse widens what
a skip index selected to every granule whose key range overlaps it, and
granules that straddle two classes overlap most of the table. The last hour
then read 13 million rows. That widening guards against a skipped granule
holding another copy of a selected row, which cannot happen here: copies of
an event share its `time`, so the index selects every copy of what it selects.
Searches turn it off with `use_skip_indexes_if_final_exact_mode = 0`.

The last search covers the whole recording, so no index on `time` can help
it; it is bound by reading one path of every launch. An index on the paths
searched most is the next step when a search like it has to be faster.
