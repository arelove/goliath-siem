-- Two identifiers seen as one thing, counted by the day. See
-- docs/adr/0025-entity-graph.md.
--
-- `one` is the strongest identifier of the object that gave both, and
-- `rule` what read them as one. A claim is evidence and not a decision:
-- resolution reads these rows, and nothing here says that two identifiers
-- are one entity.
--
-- Rows of one scope, pair, rule, and day are added up when parts merge,
-- as the rows of links are, and the first and the last event are written
-- as there.
--
-- Claims are kept a year whatever the events are kept: an identity
-- outlasts the events that showed it.
CREATE TABLE IF NOT EXISTS graph_claims
(
    day Date,
    scope LowCardinality(String),
    one String,
    other String,
    rule LowCardinality(String),
    events SimpleAggregateFunction(sum, UInt64),
    first_seen SimpleAggregateFunction(min, DateTime64(3, 'UTC')),
    last_seen SimpleAggregateFunction(max, DateTime64(3, 'UTC')),
    first_event SimpleAggregateFunction(min, FixedString(24)),
    last_event SimpleAggregateFunction(max, FixedString(24)),
    PROJECTION by_other
    (
        SELECT *
        ORDER BY (scope, other, one, rule, day)
    )
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (scope, one, other, rule, day)
TTL day + toIntervalDay(365)
SETTINGS deduplicate_merge_projection_mode = 'rebuild'
