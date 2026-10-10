-- The runs of resolution: one row once a run has written all its rows of
-- `graph_entities`, with what it read and what it found. The newest row
-- names the version readers take, and the rows together are the history
-- of how the entities changed in number.
CREATE TABLE IF NOT EXISTS graph_resolutions
(
    version UInt64,
    finished DateTime64(3, 'UTC'),
    claims UInt64,
    entities UInt64,
    members UInt64,
    aliases UInt64,
    shared UInt64,
    held_apart UInt64,
    decisions String
)
ENGINE = ReplacingMergeTree(finished)
ORDER BY version
