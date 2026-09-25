-- OCSF events, one row per event. See docs/adr/0013-event-storage.md.
--
-- `received` is when the platform took the record, and decides partition and
-- retention, because `time` is written by the source and an attacker who
-- controls it must not be able to age an event out early. `time` is what
-- queries filter on; it falls back to `received` when the event has none
-- that fits.
--
-- The event is stored whole in `event`, including `unmapped`, so that what a
-- query returns is the OCSF event as normalized. The class columns repeat
-- what it holds, for the sorting key.
--
-- ReplacingMergeTree drops a row whose sorting key, which includes the
-- event's content identity, repeats within a partition: a record delivered
-- twice is stored once after merges, and at once for a query using FINAL.
CREATE TABLE IF NOT EXISTS events
(
    received DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    time DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    class_uid UInt32,
    category_uid UInt32,
    type_uid UInt64,
    activity_id UInt32,
    severity_id UInt8,
    id FixedString(16),
    source LowCardinality(String),
    source_version UInt32,
    kind LowCardinality(String),
    event JSON(max_dynamic_paths = 1024),
    issues Nested(target String, source String, reason String)
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(received)
ORDER BY (class_uid, time, id)
SETTINGS ttl_only_drop_parts = 1
