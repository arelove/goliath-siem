-- What one thing was seen to do to another, counted by the hour. See
-- docs/adr/0025-entity-graph.md.
--
-- The ends are identifiers as the events gave them, such as
-- `user:sid:s-1-5-21-...` and `host:name:ws-7.corp.example`, and never an
-- entity: which identifiers are one entity is decided apart and applied
-- when the graph is read, so that a merge rewrites no row here.
--
-- Rows of one scope, ends, kind of link, and hour are added up when parts
-- merge. Until then, and across the days they were received on, a reader
-- adds them up itself. `events` counts an event again if it is delivered
-- again; the first and the last event do not change by that.
--
-- `first_event` and `last_event` say where those events are: eight bytes
-- of the event's time, in milliseconds and big-endian so that bytes order
-- as times do, then its identifier. A search finds the rest by the ends
-- and the hour.
--
-- `hour` is of the event's own time, which its source wrote. The day the
-- rows were received decides partition and retention, as for events.
--
-- A walk reads the neighbours of one end. The sorting key serves the end
-- that acted, and the projection the other.
CREATE TABLE IF NOT EXISTS graph_links
(
    received_day Date,
    scope LowCardinality(String),
    src String,
    link LowCardinality(String),
    dst String,
    hour DateTime('UTC'),
    events SimpleAggregateFunction(sum, UInt64),
    first_seen SimpleAggregateFunction(min, DateTime64(3, 'UTC')),
    last_seen SimpleAggregateFunction(max, DateTime64(3, 'UTC')),
    first_event SimpleAggregateFunction(min, FixedString(24)),
    last_event SimpleAggregateFunction(max, FixedString(24)),
    PROJECTION by_dst
    (
        SELECT *
        ORDER BY (scope, dst, link, src, hour)
    )
)
ENGINE = AggregatingMergeTree
PARTITION BY received_day
ORDER BY (scope, src, link, dst, hour)
SETTINGS ttl_only_drop_parts = 1, deduplicate_merge_projection_mode = 'rebuild'
