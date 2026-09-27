# Running the benchmark rig

The rig measures the raw Kafka topic through normalization and storage. It
uses the `Fleet` Sysmon workload first; the entity-model generator is in
`goliath-gen` and its mixed stream will need a raw topic for each source.
Collection, detection, and entity resolution are outside this measurement.

Build both binaries with Kafka enabled:

```sh
cargo build --release -p goliath --features kafka
cargo build --release -p goliath-bench --features rig --bin rig
```

Start Kafka or Redpanda and ClickHouse 25.8 or later, then run:

```sh
GOLIATH_CLICKHOUSE_URL=http://127.0.0.1:8123 \
GOLIATH_CLICKHOUSE_USER=goliath \
GOLIATH_CLICKHOUSE_PASSWORD=... \
GOLIATH_KAFKA_BROKERS=127.0.0.1:9092 \
cargo run --release -p goliath-bench --features rig --bin rig -- --profile ci
```

`ci` offers 5,000 records/s for 60 seconds. `laptop` offers 100,000 records/s
for 30 minutes. `GOLIATH_BIN` selects the platform executable, defaulting to
`target/release/goliath` (`goliath.exe` on Windows). Defaults for the servers
are the addresses above, user `default`, and an empty password. Set the
variables in the shell environment on Windows before running the command.

Each run creates `bench/out/rig<unix-seconds>/`, Kafka topics with prefix
`rig<unix-seconds>-`, and database `goliath_rig_<unix-seconds>`. The directory
must not exist. Port 9465 must be free. Concurrent local runs are unsupported.
The rig retains the database and topics for inspection; remove only that
run's namespace after inspecting its report.

The directory contains the platform configuration without its password,
`platform.log`, machine and worker settings in `machine.json`, raw samples in
`samples.jsonl`, and the report module's output. `failure.txt` invalidates a
run even if a partial report can be written. The report implementation is
supplied separately as `goliath_bench::report` using `Run` and `Sample`.

The first sample has elapsed time zero and captures startup CPU usage for
subtraction. Samples follow every five seconds during load and drain. CPU and
memory belong to the platform child only: Kafka, ClickHouse, and the generator
are excluded, so this is not whole-machine efficiency. `Run.duration` is the
offered load window; samples beyond it belong to drain and must not make a
missed target look sustained. The writer gets at most two minutes to catch up.
Dead letters count as stored outcomes; the report must evaluate them separately.
`goliath_normalized_records_total` counts raw pipe payloads, so 300,000 events
in this driver produce 300 increments. Use `goliath_outcomes_total` for
normalized event counts, filtering out dead letters as appropriate. Lag is
sampled periodically by the platform; drain also waits for both reader gauges
to reach zero so the final snapshot does not retain a stale backlog.

Workers have seeds `42 + worker_index` and share one global batch schedule.
Each Kafka payload holds 1,000 JSON lines and one receipt stamp. Counted bytes
are the original JSON lines, including newlines, before stamping or compression.
Worker count and live UTC timestamps affect the workload; this is reproducible
configuration, not byte-identical replay. Each sender waits for acknowledgement
before counting a batch. A timeout can have unknown acceptance and invalidates
the run. Backpressure can reduce offered throughput; the rig never extends the
load window to hide it.

The driver calls `report::write(&run, &clickhouse, &output_directory).await`.
The ClickHouse client selects the isolated database. Report code should bound
its server requests and preserve unavailable measurements explicitly.

## Driver validation on 2026-09-27

The `ci` workload was run against local Redpanda and ClickHouse 25.8.33.6:
300,000 events sent, 198,692,360 raw bytes, 300,000 stored outcomes, and both
reader gauges zero after drain. An earlier run was also checked directly in
ClickHouse: 300,000 events after deduplication and zero dead letters.

With the report module in place, the same `ci` profile was run again on an
AMD Ryzen 9 9955HX (16 cores, 32 GB, Windows 11), Redpanda and ClickHouse
25.8.33.6 in Docker Desktop:

| Measure | Value |
| --- | ---: |
| Verdict | sustained |
| Offered | 4,998 records/s |
| Stored during load | 4,948 outcomes/s |
| Platform cores used | 0.14 |
| Outcomes per second of platform CPU | 36,415 |
| Platform peak memory | 31 MiB |
| Receipt to stored, p50 / p95 / p99 | 668 / 1,250 / 2,085 ms |
| Source bytes per stored byte | 8.4x |
| Stored after the drain | 300,000 of 300,000 |

This is one minute at a twentieth of the M3 target, with the platform
mostly idle; it validates the rig end to end, not the 30-minute laptop
criterion.

## How the report decides

`goliath_bench::report` computes from the samples alone, apart from two
bounded ClickHouse queries for what the run's database holds:

- The first sample is the baseline; the load window runs to `Run.duration`,
  and the drain after it never counts towards a sustained rate.
- The backlog is counted in records: the raw reader's lag, in payloads, is
  multiplied by the run's average records per payload, and the writer's lag
  added.
- A rate is sustained when at least 95% of it was offered and, over the second
  half of the load window, the backlog grew by at most 1% of the rate per
  second and never held more than ten seconds of it. A rate the driver could
  not offer is reported as such, not charged to the platform.
- Receipt-to-stored percentiles are interpolated within the histogram's
  buckets, for the load window and for the whole run.
- Compression is the source bytes sent per compressed byte stored.
- Every metric of the benchmark method that needs a later component is listed
  with the milestone that brings it.
