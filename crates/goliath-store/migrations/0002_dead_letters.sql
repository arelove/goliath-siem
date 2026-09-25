-- Records that could not become events, with their raw bytes, so they can be
-- processed again once the source definition is fixed. See
-- docs/adr/0007-source-and-parser-model.md.
CREATE TABLE IF NOT EXISTS dead_letters
(
    received DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    source LowCardinality(String),
    source_version UInt32,
    stage LowCardinality(String),
    error String,
    raw String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toDate(received)
ORDER BY (source, stage, received)
SETTINGS ttl_only_drop_parts = 1
