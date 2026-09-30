-- Counts each block inserted into `dead_letters` into `dead_letter_hours`.
CREATE MATERIALIZED VIEW IF NOT EXISTS dead_letter_hours_view TO dead_letter_hours AS
SELECT
    source,
    stage,
    toStartOfHour(received) AS hour,
    count() AS dead_letters,
    max(received) AS last_received
FROM dead_letters
GROUP BY source, stage, hour
