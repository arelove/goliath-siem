-- The conditions processes report, one row for each time a condition's
-- status held: every report writes its conditions again, and rows of one
-- instance, role, type, and `since` are one row, the last seen, since
-- `since` moves only when the status does. So the table is the history of
-- what was wrong, since when, and until when it was last seen. Kept five
-- weeks, as the counts of source health are.
CREATE TABLE IF NOT EXISTS platform_conditions
(
    instance String,
    role LowCardinality(String),
    type LowCardinality(String),
    since DateTime64(3, 'UTC'),
    status LowCardinality(String),
    reason LowCardinality(String),
    message String,
    seen DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(seen)
PARTITION BY toYYYYMM(since)
ORDER BY (instance, role, type, since)
TTL toDateTime(seen) + toIntervalDay(35)
