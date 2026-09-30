-- Events stored, by source and hour of `received`, and when the last was,
-- for source health. Filled by the view of migration 8 and summed as parts
-- merge; read with GROUP BY, since parts not yet merged hold partial rows.
-- Five weeks are kept: the baseline reads eight days. See
-- docs/adr/0019-source-health.md.
CREATE TABLE IF NOT EXISTS source_hours
(
    source LowCardinality(String),
    hour DateTime('UTC'),
    events SimpleAggregateFunction(sum, UInt64),
    last_received SimpleAggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (source, hour)
TTL hour + toIntervalDay(35)
