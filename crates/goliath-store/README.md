# goliath-store

Storage of normalized OCSF events in ClickHouse, for the
[Goliath](https://github.com/arelove/goliath-siem) security platform.

- Events go to one `events` table: typed columns for classification, time,
  and identity, and the whole OCSF event in a `JSON` column, so any path is a
  column of its own in a query.
- Records that could not become events go to `dead_letters` with their raw
  bytes, to be processed again once their source definition is fixed.
- A record delivered twice is stored once, by its content identity.
- The schema is a sequence of forward-only migrations the store applies
  itself; an edited migration stops startup.

The layout and the reasons for it are in
[ADR-0013](https://github.com/arelove/goliath-siem/blob/main/docs/adr/0013-event-storage.md).
Requires ClickHouse 25.8 or later.

## Testing

The integration tests need a server:

```sh
docker run -d -p 8123:8123 -e CLICKHOUSE_USER=goliath -e CLICKHOUSE_PASSWORD=goliath clickhouse/clickhouse-server
GOLIATH_CLICKHOUSE_URL=http://localhost:8123 GOLIATH_CLICKHOUSE_USER=goliath GOLIATH_CLICKHOUSE_PASSWORD=goliath cargo test -p goliath-store
```

Without `GOLIATH_CLICKHOUSE_URL` they pass without running. CI sets
`GOLIATH_REQUIRE_CLICKHOUSE`, which makes a missing server a failure.

## License

Copyright 2026 arelove. Licensed under the
[Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
