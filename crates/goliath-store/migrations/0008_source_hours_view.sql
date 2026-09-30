-- Counts each block inserted into `events` into `source_hours`. Events
-- stored before this migration are not counted.
CREATE MATERIALIZED VIEW IF NOT EXISTS source_hours_view TO source_hours AS
SELECT
    source,
    toStartOfHour(received) AS hour,
    count() AS events,
    max(received) AS last_received
FROM events
GROUP BY source, hour
