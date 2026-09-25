# goliath

The [Goliath](https://github.com/arelove/goliath-siem) security platform as
one binary. A process runs the roles its configuration lists, connected by
durable topics in its data directory (see
[ADR-0006](../../docs/adr/0006-deployment-topology.md) and
[ADR-0015](../../docs/adr/0015-pipe-semantics.md)):

```text
inbox --collector--> raw-<source> --normalizer--> normalized --writer--> ClickHouse
```

Every hop acknowledges only after handing on durably, so a crash repeats work
and never loses a record; storage drops the repeats by event identity.

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

## License

Copyright 2026 arelove. Licensed under the
[Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
