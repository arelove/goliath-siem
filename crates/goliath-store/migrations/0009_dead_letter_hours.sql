-- Dead letters, by source, stage, and hour of `received`, and when the last
-- was, as `source_hours` counts events.
CREATE TABLE IF NOT EXISTS dead_letter_hours
(
    source LowCardinality(String),
    stage LowCardinality(String),
    hour DateTime('UTC'),
    dead_letters SimpleAggregateFunction(sum, UInt64),
    last_received SimpleAggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (source, stage, hour)
TTL hour + toIntervalDay(35)
