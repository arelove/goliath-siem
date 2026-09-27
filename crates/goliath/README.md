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
| `api` | Serves searches over the stored events over HTTP, under `/api/v1` | Reads only |

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

## License

Copyright 2026 arelove. Licensed under the
[Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
