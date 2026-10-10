# goliath

The [Goliath](https://github.com/arelove/goliath-siem) security platform as
one binary. A process runs the roles its configuration lists, connected by
durable topics (see [ADR-0006](../../docs/adr/0006-deployment-topology.md)
and [ADR-0015](../../docs/adr/0015-pipe-semantics.md)):

```text
inbox --collector--> raw-<source> --normalizer--> normalized --writer--> ClickHouse
```

Every hop acknowledges only after handing on durably, so a crash repeats work
and never loses a record; storage drops the repeats by event identity.

The topics are files in the `data` directory when every role is in one
process. With a `[kafka]` section they are in Kafka or Redpanda instead, and
each role can run in a process, container, or host of its own; the binary
needs the `kafka` feature for that, which the container image has. See
`deploy/distributed/` for one configuration per role.

## Try it

```sh
docker run -d -p 8123:8123 -e CLICKHOUSE_USER=goliath -e CLICKHOUSE_PASSWORD=goliath clickhouse/clickhouse-server
cp crates/goliath/goliath.example.toml goliath.toml
cargo run --release -p goliath -- check --config goliath.toml
GOLIATH_CLICKHOUSE_PASSWORD=goliath cargo run --release -p goliath -- run --config goliath.toml
```

Then drop Sysmon events, as `evtx_dump -o json` writes them, into
`inbox/sysmon/` (write under a `.tmp` name and rename), and query them:

```sql
SELECT time, event.process.cmd_line FROM goliath.events WHERE class_uid = 1007
```

## Roles

| Role | Does | Acknowledges after |
| --- | --- | --- |
| `collector` | Takes finished files from each source's inbox | The file is in the raw topic |
| `normalizer` | Turns raw records into OCSF events and dead letters | The outcomes are in the normalized topic |
| `writer` | Batches outcomes into ClickHouse, retrying while it is unavailable | The batch is stored |
| `graph` | Reads what normalized events show of the things they name, beside the writer: links between things and claims that two identifiers are one, added up ([ADR-0025](../../docs/adr/0025-entity-graph.md)) | The rows are in the graph topic |
| `api` | Serves searches over the stored events over HTTP, under `/api/v1` | Reads only |

## Entities

With the `graph` role and a `[store]`, identifiers are resolved into
entities at the start and then every 15 minutes
([ADR-0025](../../docs/adr/0025-entity-graph.md)): the claims the store
holds are read, `goliath-graph` decides which identifiers are one entity,
and the answer is written as a new version beside the last. Links and
claims are never rewritten, so a run that goes wrong changes nothing a
reader sees, and a decision that was wrong is gone at the next run.

```toml
[graph]
# What people decided about identity, reviewed as rules are.
decisions = ["identity.yaml"]
resolve_every_minutes = 15
# An identifier seen with more strong identifiers of one form than this is
# shared, and joins nothing.
shared_over = 3
# How many days of what was stored before the role first ran are read into
# the graph: everything if left out, nothing with 0.
read_back_days = 30
```

The role reads the stream. Two kinds of events are stored and were not in
it, and both are read from the store, an hour of receipt time at once:

- what was stored before the role first ran, so that turning it on fills
  the graph from the history the store holds;
- what the role was moved past when it fell further behind than the topic
  keeps.

The ranges still to read are noted in `graph/unread.json` in the data
directory, so a restart goes on where it was. A range is read once the
writer is past it: when a later event is stored, or after ten minutes.
`goliath_graph_unread_ranges` says how many wait, and
`goliath_graph_read_back_events_total` how many events were read.

A decisions file says that two identifiers are the same, or are not,
whatever events show, each with a reason; its shape is in the
[README of `goliath-graph`](../goliath-graph/README.md). It is read again
at every run. A file that cannot be used fails the run, and the condition
`resolving` says which decision is wrong.

## Search

With the `api` role, events are searched by OCSF path, checked against the
schema before any query runs ([ADR-0016](../../docs/adr/0016-event-search.md)):

```sh
curl -s localhost:8080/api/v1/search -H 'content-type: application/json' -d '{
  "from": "2026-09-24T00:00:00Z", "to": "2026-09-25T00:00:00Z", "classes": [1007],
  "filters": [{ "path": "process.cmd_line", "op": "contains", "value": "powershell" }]
}'
```

A page holds up to 1,000 events, newest first; its `next` goes into the next
search's `after`. `GET /api/v1/events/{at}` returns one event with its
normalization issues, and `/api/v1/schema/classes/{uid}/paths` lists what a
search can name. The API listens on loopback unless `[api]` names a
`token_file`, whose token every request then carries as a bearer token.

`POST /api/v1/findings` is the queue of findings
([ADR-0024](../../docs/adr/0024-interface.md)): a search of the findings
alone, the most severe first and then the newest.

```sh
curl -s localhost:8080/api/v1/findings -H 'content-type: application/json' -d '{
  "from": "2026-09-24T00:00:00Z", "to": "2026-09-25T00:00:00Z", "severities": [4, 5]
}'
```

It takes a search's `filters` and `limit`, and no `classes`. `severities`
bounds the page and not the counts: the answer's `severities` says how many
findings of each severity the range and the filters leave, so that an
interface can say what choosing another would show. `next` goes into the
next request's `after`.

## Metrics

With `[metrics]` set, every process serves Prometheus metrics at `/metrics`
on its own address, for whichever roles it runs:

| Metric | What it counts |
| --- | --- |
| `goliath_collected_files_total`, `goliath_collected_bytes_total` | Files the collector sent, by source |
| `goliath_rejected_files_total` | Files set aside as too large, by source |
| `goliath_normalized_records_total` | Raw records normalized, by source |
| `goliath_outcomes_total` | Events and dead letters made of them, by source |
| `goliath_dead_letters_total` | Dead letters by source and the stage that refused them |
| `goliath_stored_outcomes_total` | Outcomes the writer stored and acknowledged |
| `goliath_reader_lag_records` | Records in a topic its reader has not acknowledged, by topic and reader; a rate is sustained while this stays bounded |
| `goliath_receipt_to_stored_seconds` | Time from the collector taking a record to its outcome being stored |
| `goliath_store_flush_seconds` | Time to write one batch to ClickHouse |
| `goliath_searches_total`, `goliath_search_seconds` | Searches answered, refused, or failed, and their time |

The endpoint takes no token: it holds counts and durations, never an event.
Listen only on an address the monitoring system reaches.

## Probes

The same address answers three questions about the process, for Kubernetes
or a load balancer ([ADR-0023](../../docs/adr/0023-platform-health.md)):

| Path | Says yes when |
| --- | --- |
| `/health/live` | The process answers. A store or a pipe that is down does not make it say no: a restart mends neither |
| `/health/startup` | Every role was started, and a detector looked at each of its feeds once |
| `/health/ready` | It started, and is not shutting down |

Yes is `200` with `{"status":"ok"}`. No is `503`, with what is waited for:

```json
{"status":"starting","waiting_for":["feeds"]}
```

```yaml
startupProbe:
  httpGet: { path: /health/startup, port: 9464 }
  periodSeconds: 5
  failureThreshold: 120
livenessProbe:
  httpGet: { path: /health/live, port: 9464 }
readinessProbe:
  httpGet: { path: /health/ready, port: 9464 }
```

## Reports

Every process that reaches the pipe says of itself every 15 seconds: its
name, its roles, its version, when it started, and the condition of each
thing it does. The report goes to the `health` topic, and the writer keeps
it in the store, the newest of each process for a day and each time a
condition's status held for five weeks.

```toml
# What this process is called; its host's name, or its pod's, if left out.
instance = "writer-eu-1"
```

A condition is a question, an answer, and why:

```json
{"role": "writer", "type": "storing", "status": "failing",
 "reason": "store_refused", "since": 1791586220000,
 "message": "The store refused the last batch, which is held and tried again: ..."}
```

| Role | Condition | Degraded when | Failing when |
| --- | --- | --- | --- |
| writer | `storing`, `storing_findings` for what the detector found, and `storing_graph` for what the graph role read | The store took longer than 10 seconds for a batch | The store refused the last batch |
| writer, normalizer, detector, graph | `keeping_up:<topic>`, one for each topic it reads | The backlog grew through the last ten minutes, and is 1,000 records or more | Not told yet |
| graph | `resolving`: whether identifiers were resolved into entities at the last run | Never | The store did not answer, or a decisions file cannot be used; the last mapping stands |
| normalizer | `normalizing:<source>` | More than 1% of the source's records in the last hour became dead letters | More than half did |
| detector | `feeds_current:<feed>` | The feed is older than twice its refresh, or was not fetched since the process started | No publication of it was ever loaded |

A source with fewer than 100 records in the hour is not judged by its dead
letters.

A report also counts what each reader has still to read, as
`backlog:<topic>:<reader>`.

`GET /api/v1/platform` judges the platform from the reports:

- A process is `reporting` while its newest report is younger than a
  minute. Gone for an hour, it leaves the answer, unless its role is then
  short of processes.
- A role is as bad as the worst condition of the processes that report.
  It is failing when none reports, and degraded when fewer report than ran
  at once within the last day, or when it started more than three times in
  ten minutes. It is judged by how many report and not by which: a pod
  that comes back under another name is the same role.
- The platform is as bad as its worst role, with that role's reason, such
  as `writer:store_refused`.
- `flows` are the topics with their readers and what each has still to
  read, the longest backlog first.
- `changes` are the last 50 times a condition's status held, the newest
  first: what changed, and when.
- With the store not answering, the answer says so itself, as
  `store_unreachable`: no report can be read then.

```json
{"now": 1791586241867, "store": "answers",
 "platform": {"status": "failing", "reason": "writer:store_refused",
  "message": "The store refused the last batch, which is held and tried again: ...",
  "roles": [{"role": "writer", "status": "failing", "reporting": 1, "expected": 1,
             "starts": 0, "instances": [{"instance": "writer-eu-1", "reporting": true}]}],
  "changes": [{"instance": "writer-eu-1", "role": "writer", "kind": "storing",
               "status": "failing", "since": 1791586220000}]}}
```

The other conditions of [ADR-0023](../../docs/adr/0023-platform-health.md)
follow. A report that cannot be sent is given up, and the next says more: a
process never waits or stops over its own health.

## License

Copyright 2026 arelove. Licensed under the
[Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
