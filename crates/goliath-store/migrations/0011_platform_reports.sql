-- What each process of the platform says of itself, every few seconds: its
-- roles, its version, when it started, and its counters. A process that
-- stops is found by its newest row growing old. Kept a day: only the
-- newest of each process, and how many started lately, are asked for. See
-- docs/adr/0023-platform-health.md.
CREATE TABLE IF NOT EXISTS platform_reports
(
    received DateTime64(3, 'UTC'),
    instance String,
    roles Array(LowCardinality(String)),
    version LowCardinality(String),
    started DateTime64(3, 'UTC'),
    sent DateTime64(3, 'UTC'),
    counters Map(LowCardinality(String), UInt64)
)
ENGINE = MergeTree
PARTITION BY toDate(received)
ORDER BY (instance, started, received)
TTL toDateTime(received) + toIntervalDay(1)
