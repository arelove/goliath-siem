# 0016. Event search

- **Status:** Accepted
- **Date:** 2026-09-26

## Context

M2 stores normalized events in ClickHouse ([ADR-0013](0013-event-storage.md)).
M2.5 makes them visible: an analyst picks a time range, a class, and
conditions on any OCSF attribute, and reads the events that match. The exit
criterion is a search over 10 million events, filtered by time, class, and one
attribute, answered in under one second.

Four things must be settled before the first line of the `api` role
([ADR-0006](0006-deployment-topology.md)) and the `ui` role
([ADR-0014](0014-one-language-for-services.md)):

- what a search is, so that the interface, the API, and later saved searches
  and detections agree on it;
- how it becomes SQL without letting a request write SQL;
- how results page through millions of rows;
- who may search.

Attributes are named by OCSF paths, such as `process.cmd_line`, which the
schema compiled into `goliath-ocsf` can check. Events hold what normalization
could not map under `unmapped`, which has no schema.

## Decision

**A search is a typed structure, checked against the OCSF schema, and
compiled to one parameterized ClickHouse query. It is not text.**

```json
{
  "from": "2026-09-25T00:00:00Z",
  "to": "2026-09-26T00:00:00Z",
  "classes": [1007],
  "filters": [
    { "path": "process.cmd_line", "op": "contains", "value": "curl" },
    { "path": "actor.user.name", "op": "in", "value": ["root", "admin"] }
  ],
  "limit": 100
}
```

### What a search may say

- **Time range.** Required, half open, on the event's `time`. Its span is
  capped, by default at 31 days, so that no request scans all history.
- **Classes.** Optional `class_uid`s. A path must be an attribute of every
  class named, or, with none named, of at least one class.
- **Filters.** All must hold. Paths are checked with `Class::resolve`; a path
  under `unmapped` is accepted as free-form. A path inside an array, such as
  `observables.value`, is refused for now, with an error saying so.
- **Operators**, checked against the attribute's type:
  - on text: `equals`, `not_equals`, `contains`, `starts_with`,
    `ends_with`, `in`; all compare **without regard to case**, as Sigma does,
    because the same analyst writes both;
  - on numbers and times: `equals`, `not_equals`, `in`, `gt`, `gte`, `lt`,
    `lte`; an enumerated attribute accepts only its defined values;
  - on anything: `exists`, `missing`.
- **Limit.** At most 1,000 events a page.

A text syntax for analysts, like `process.cmd_line:*curl*`, is sugar for this
structure, parsed into it, and comes later. Saved searches, and detections
built from searches, store the structure.

### From search to SQL

- Values are never written into SQL. Each becomes a ClickHouse query
  parameter, typed by the attribute.
- Paths cannot be parameters, so they are written into SQL only after they
  pass the schema. Each segment is quoted; a segment under `unmapped`
  containing a backtick, a backslash, or a control character is refused.
- An attribute is read as a typed subcolumn of the `event` column, such as
  `event.process.cmd_line.:String`, so that a value of another type does not
  match instead of failing the query.
- The query reads with `FINAL`, so that an event delivered twice appears once.
- Every query runs with `readonly = 2`, a time limit, and a limit on rows
  read, whatever user the service connects as. Deployments should give the
  `api` role its own read-only ClickHouse user as well.

### Paging

Results come newest first, ordered by `(time, id)`. A page ends with a cursor
naming its last `(time, id)`, and the next page asks for rows before it:
keyset paging, which costs the same on page 1,000 as on page 1, and does not
skip or repeat events when new ones arrive. There is no offset.

### Service and interface

- The `api` role serves JSON over HTTP under `/api/v1`: a search, one event by
  its id with its normalization issues, and the schema's classes and
  attributes, for the interface to complete paths.
- The `ui` role is a TypeScript and React application built with Vite, and
  served as static files by the `api` role on the same origin, so that no
  cross-origin access is ever enabled.
- **Access.** The service listens on loopback by default. Listening on any
  other address requires a bearer token, read from a secret file and compared
  in constant time. Users, roles, and tenancy replace the token when the
  control plane arrives; the search structure does not change for them.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Typed structure compiled to parameterized SQL | Checkable against the schema before running; no injection surface; one form for interface, API, saved searches, and detections | Analysts want to type queries | **Yes**; text syntax parses into it later |
| A query language first, like KQL or SPL | What analysts know | A parser and its security surface before any user; the interface builds structures anyway | Later, as sugar |
| Let requests send SQL, run as a read-only user | Most power at once | Read-only still reads everything and can exhaust the server; no schema check; SQL becomes the contract | No |
| Offset paging | Simple | Cost grows with the page number; events shift under the reader as new ones arrive | No |
| Search through Sigma rules | Reuses the engine | Sigma describes detections, not ad hoc questions, and has no time range or paging | No |
| A separate web server for the interface | Independent deployment | Cross-origin requests and a second service to secure for no gain | No |

## Consequences

- The schema check that protects definitions and mappings now protects
  searches: a misspelled attribute is an error before any query runs, not an
  empty result.
- Case-insensitive text comparison costs more than exact comparison; the
  benchmark in the exit criterion measures it rather than assuming it.
- Queries on `time` cannot prune partitions, which follow `received`
  ([ADR-0013](0013-event-storage.md)). A min-max index on `time` restores
  most of that, and is added with the benchmark that shows it matters.
- Paths inside arrays, joins between events, and aggregations are not
  searches yet. Each needs its own design when a user needs it.

## When to revisit

- The 10-million-event search misses one second with the indexes this record
  anticipates: revisit the table layout or the use of `FINAL`.
- Analysts need a condition the structure cannot say, such as any of two
  filters, three times in a quarter: add grouping to the structure, not SQL.
