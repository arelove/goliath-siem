# 0017. Benchmark rig

- **Status:** Accepted
- **Date:** 2026-09-27

## Context

Every performance claim so far measures one part on its own: the match engine
on converted SigmaHQ events ([sigma-coverage.md](../sigma-coverage.md)),
search over events stored by a benchmark
([benchmarks.md](../benchmarks.md#search)). None measures the platform: records
arriving at a rate, normalized, stored, and searchable, for long enough that
queues, merges, and memory settle. M3 builds the rig that does, and its exit
criterion is a reproducible report and 100,000 events/s sustained for 30
minutes on one developer machine.

[architecture.md](../architecture.md#benchmark-method) sets the method: a
synthetic volume stream driven by an entity model, where the same entity
appears under different identifiers per source, kept apart from real labelled
datasets used for fidelity; an injector that interleaves labelled attack
chains at known offsets; and a list of metrics published with every release.

Four facts shape the design:

- The metrics list includes latency from ingestion to alert, precision and
  recall, and memory per indicator count. Alerts arrive in M5 and indicators in
  M4; M3 cannot measure them.
- The entity graph (M4.5) is judged by precision and recall of resolution
  against ground truth, which only a generator that knows which identifiers
  belong together can provide.
- The platform has no network receiver until M3.5. Its entry point today is
  the raw topic of the pipe ([ADR-0015](0015-pipe-semantics.md)), which the
  collector writes and the normalizer reads, on disk or on Kafka.
- Security software on the machines the rig runs on quarantines some attack
  text as files on disk; a demo recording has already tripped it once.

## Decision

**The rig generates raw source records from an entity model, writes ground
truth beside them, drives the platform at its raw topic, reads the
platform's own metrics, and reports every metric the built components can
produce, naming the ones that wait for later milestones.**

### Generator

- A new crate, `goliath-gen`, generates records in each source's own format,
  as its shipped definition reads them: Sysmon as `evtx_dump` writes it, Entra
  ID sign-ins, Linux auditd, and Falco. Normalization is part of what is
  measured, and generating OCSF directly would skip it.
- An organization is generated from a seed: users, Windows workstations,
  Linux servers, and the links between them, such as a user's own
  workstation and the servers they administer.
- Each entity carries the identifiers each source would give it. A user is
  `CORP\jdoe` to Sysmon, `jane.doe@corp.example` and an object id to Entra ID,
  and uid 1042 or `jdoe` to auditd. A workstation is a NetBIOS name, a fully
  qualified name, and an address that changes from day to day.
- Activity follows the entity model: each user's volume is drawn from a Zipf
  distribution, workstations follow the working day in their user's time zone
  with quiet weekends, and servers run around the clock.
- Everything follows from the seed and the simulated start time, so two runs
  produce the same records.

### Ground truth

- Beside the stream, the generator writes `entities.jsonl`, one line per
  entity with every identifier it was emitted under, and `labels.jsonl`, one
  line per injected record with its chain, step, and ATT&CK technique.
- Records are matched to labels by the identity the normalizer computes from
  the raw bytes, so labels survive normalization and deduplication.

### Injector

- Attack chains are scenario files: steps with a source, a record template,
  an entity role such as "the victim's workstation", and a delay from the
  previous step. The injector binds roles to generated entities and places
  each chain at a known offset.
- Scenarios describe what an attack does, not working attack text: payloads
  are encoded harmless strings, and techniques whose command lines antivirus
  software quarantines, such as credential dumping, are represented by the
  events around them rather than the command itself.

### Replay

- Real datasets of stream B are replayed from their recordings, shifted so
  the first record is now, gaps kept and scaled by a speed multiplier.
- They are downloaded by a script into a directory the repository ignores,
  never vendored: their licenses vary, and security software quarantines
  some of them.

### Driving and measuring

- The rig writes records to the raw topic, as the collector does, on the disk
  pipe for one process and on Kafka for separate roles, at a target rate held
  by a token bucket. Network receivers become a second entry point in M3.5.
- Every role serves Prometheus metrics: records in and out per stage, batch
  sizes, lag of each reader behind its topic, dead letters by source and
  stage, and the time from a record's receipt to its event being stored. The
  rig scrapes them; it does not infer the platform's state from outside.
- A rate is sustained when the lag of every reader stays bounded over the
  run, not when the generator managed to write it.
- Compression per source is measured by a short run of that source alone
  into a scratch database, since ClickHouse compresses parts, not sources.

### Report

- One command runs a profile, such as `laptop` or `ci`, and writes
  `report.md` and `report.json`: the machine (CPU model, cores, memory, OS),
  the commit, versions, configuration, and each metric.
- Metrics that need a component not built yet are listed with the milestone
  that brings them, not left out and not estimated. The M3 exit criterion
  reads accordingly: the report covers every metric of the benchmark method,
  measured where a component exists and marked where it does not.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Generate OCSF events | Simpler; no per-source formats | Skips normalization, the most expensive stage per record; identifiers arrive already reconciled | Rejected |
| Generate raw source records | Measures the whole path; identifiers differ as they do in real sources | A formatter per source | Chosen |
| Drive through files in the inbox | Exercises the collector | The collector is not the product's ingestion path at scale; file handling dominates at 100,000 events/s | Rejected |
| Drive the raw topic | The same entry for both topologies; the collector's own role is only framing | Skips collection until M3.5 | Chosen |
| Measure from outside, by polling ClickHouse | No change to the roles | Cannot see lag, per-stage rates, or where time goes | Rejected |
| Prometheus metrics in every role | Operators need them anyway (M3 lists them); exact per stage | An endpoint and instrumentation in each role | Chosen |
| An existing generator, such as a log flooder or Loghub replay | Nothing to build | No entity model, no identifiers shared across sources, no ground truth | Rejected for stream A; Loghub stays in stream B |

## Consequences

- The entity graph gets its evaluation data before it is built: M4.5 can be
  developed against `entities.jsonl` from its first commit.
- `goliath-gen` duplicates part of `goliath-bench`'s `Fleet`, which the demo
  uses; the demo moves to the generator once it covers Sysmon, and `Fleet`
  is removed.
- Every role gains an HTTP endpoint for metrics, which is also what operators
  need, and a dependency on a metrics library.
- A report can show gaps. That is deliberate: a report that hides what it
  cannot measure would be the kind of claim the method exists to prevent.
- Four source formatters must track their definitions; each formatter's
  output is normalized in its tests with no issues, so drift fails CI.

## When to revisit

- A network receiver sustains a higher rate than the raw topic on the same
  machine: drive through receivers instead.
- A second organization shape, such as a cloud-only company without
  workstations, is needed for a claim: add profiles of organizations rather
  than parameters.
- Generating records costs more than a fifth of a core per 100,000 events/s:
  the generator is then measuring itself, and should run on another machine.
