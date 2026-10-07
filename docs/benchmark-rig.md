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

`ci` offers 5,000 records/s for 60 seconds. `probe` offers 100,000 records/s
for 5 minutes, to see whether the laptop rate holds before committing to
`laptop`, which offers it for 30 minutes.

At 100,000 records/s the rig sends about 66 MB of source data a second.
Kafka keeps what it has delivered for as long as its retention says, seven
days by default, so on a development machine shorten it first, for example
`rpk cluster config set log_retention_ms 600000`, or a 30-minute run needs
several hundred gigabytes of free disk.

Memory needs a bound too. Redpanda takes as much as it is allowed, and at
this rate it reached 6.4 GiB in the first minutes of a probe; start it with
a limit, for example:

```sh
docker run -d --name goliath-redpanda -p 9092:9092 redpandadata/redpanda:v26.2.3 \
  redpanda start --mode dev-container --smp 1 --memory 2G --reserve-memory 0M \
  --overprovisioned --kafka-addr PLAINTEXT://0.0.0.0:9092 \
  --advertise-kafka-addr PLAINTEXT://127.0.0.1:9092
```

On Windows and macOS, Docker runs in a virtual machine that keeps what it
has taken; cap it as well, in `%UserProfile%\.wslconfig` for WSL. Whatever
the servers do, the rig stops a run, and says so, once more than 90% of the
machine's memory is in use.

Retention must never be shorter than the time a record can wait unread. The
rig bounds that wait: each topic holds at most 20 seconds of the offered rate
for its reader, and senders wait beyond it, so a platform that falls behind
shows as a rate the driver could not offer rather than as records Kafka
deleted. A first 5-minute probe, run with two minutes of retention and no
such bound, lost 13 million of 30 million records that way; its throughput
is in the roadmap's M3 notes, its totals are not evidence of anything. `GOLIATH_BIN` selects the platform executable, defaulting to
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

## Replaying real datasets

Stream B of ADR-0017 is real telemetry, replayed as if it were happening now.
`replay` reads a recording in its source's own format, moves every record's
times so that the first is the moment it starts, keeps the gaps between them
divided by `--speed`, and writes what has come due into a collector's inbox
every quarter second. Clocks are defined for `sysmon`, `sysmon-flat`,
`entra`, `falco`, and `auditd`.

```sh
cargo run --release -p goliath-bench --bin replay -- \
    --source sysmon-flat --recording bench/datasets/otrf/SDWIN-190301125905/sysmon.jsonl \
    --out inbox/sysmon-flat --speed 10 --times 3
```

The first real datasets are the Windows atomic datasets of the [OTRF Security
Datasets](https://github.com/OTRF/Security-Datasets), MIT licensed: each is one
technique recorded on a lab network, with its ATT&CK mapping. They are
recordings of real attack tools, and security software may quarantine them, so
they are downloaded by a script, never committed, into `bench/datasets/`,
which git ignores. Run the script on a machine meant for it, not a workstation
whose antivirus you would rather not argue with:

```sh
python3 scripts/datasets.py                         # all 100 Windows atomic datasets
python3 scripts/datasets.py --only SDWIN-190301125905
```

The script is pinned to one commit of the datasets. It writes each dataset's
Sysmon events to `sysmon.jsonl`, flat JSON lines that the `sysmon-flat`
definition reads, its other channels to `other.jsonl`, and a `label.json`
naming the dataset, its techniques, licence, and commit.

### Injecting labelled attacks

A labelled recording replayed beside generated activity is an injected
attack whose every event is known. With `--labels`, replay writes one line of
ground truth per event its records become, carrying the identity the
source's normalizer gives the record, which is the identity the platform
stores it under, when it was released, and the members of `--label`:

```sh
cargo run --release -p goliath-bench --bin replay -- \
    --source sysmon-flat --recording bench/datasets/otrf/SDWIN-190301125905/sysmon.jsonl \
    --out inbox/sysmon-flat --labels bench/out/labels.jsonl \
    --label bench/datasets/otrf/SDWIN-190301125905/label.json
```

A test holds a record's identity alone to its identity in a file of records,
so labels find the events the platform stores. Precision and recall against
them wait for detections, in M5. Generated attack chains bound to the
generator's entities, the scenario files ADR-0017 describes, are still to
come; real recordings cover the injector until then.

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

## Measuring the detector

The detector has budgets of its own, in
[ADR-0021](adr/0021-enrichment-placement.md): a rate that does not fall as
the indicator set grows, every planted match found and no other, and limits
on memory and disk. A second binary measures against them, and needs neither
ClickHouse nor Docker:

```sh
cargo build --release -p goliath
cargo run --release -p goliath-bench --features intel --bin intel -- \
    --indicators 1000 --events 1000000 --out bench/out/intel-1k
cargo run --release -p goliath-bench --features intel --bin intel -- \
    --indicators 1000000 --events 1000000 --out bench/out/intel-1m \
    --baseline bench/out/intel-1k/report.json
```

One run does this:

1. It writes feeds of generated indicators, at most `--feed-size` in each
   (ten million unless told otherwise), and an allowlist that names some of
   them. The indicators are those of `goliath_gen::intel`, in the mix of the
   criterion, and ordinary telemetry never holds one.
2. It fills the event topic on disk with `--events` normalized events. A
   share of them, `--planted` (0.01 unless told otherwise), hold one
   indicator each; one planted event in fifty holds an allowlisted one. The
   topic is full before the platform starts, so generating and normalizing
   take no core from what is measured.
3. It starts `goliath` with the detector role alone and `--threads` matching
   threads (1 unless told otherwise), and reads the platform's metrics, its
   processor time, and its resident memory once a second, until every event
   is matched.
4. It reads the findings topic and compares what was found with what was
   planted.

| Line of the report | What it is |
|---|---|
| feeds in the store after | Seconds from the start of the platform until every feed was loaded, or found unchanged |
| events a second | Events matched, over the time from the first one matched to the last |
| events a second, median | The median of the rates of the whole seconds |
| events a CPU second | Events matched for each second of processor time the platform used: the rate for each core, and what a baseline is compared by |
| events a second, first min. | The rate of the first minute of matching, which the cold start budget is about |
| correctness | Every planted indicator has its findings, as an alert or as suppressed, no other indicator has one, and the detector was moved past no event |
| memory | The most resident memory seen, against 2 GiB |
| disk | The size of the indicator store, against 8 GiB |
| rate | With `--baseline`: events a CPU second as a share of the baseline's, against 90% |

The memory and disk budgets are those of 10^8 indicators, so a smaller run
that passes them shows only that it is not yet over. The run exits with a
failure when a line fails, and writes all of it to `report.json` in its
directory.

A check of the harness on a laptop on 2026-10-08, with one matching thread
and a million events:

| Indicators | Events a second | Events a CPU second | Memory | Disk | Planted matches |
|---|---|---|---|---|---|
| 10^3 | 78,456 | 100,866 | 0.02 GiB | under 0.01 GiB | 10,000 of 10,000, no other |
| 10^6 | 82,537 | 101,750 | 0.28 GiB | 0.08 GiB | 10,000 of 10,000, no other |

That is one run of each, not the median of five the criterion asks for, and
it does not reach 10^8; the exit measurement of M4 is made on other
hardware. The harness does not yet measure a feed refresh under load, nor
the writer's rate with the detector stopped.

A million events take about a gigabyte in the run's directory, and 10^8
indicators about four more for the feeds. Delete the directory when the
report is read.
