-- A minmax index on `received`, one entry per granule. Parts are written in
-- the order records arrive, so the index lets a question about the last
-- minutes, such as the overview's arrivals, skip every older granule of the
-- day's partition instead of reading it.
ALTER TABLE events ADD INDEX IF NOT EXISTS received_range received TYPE minmax GRANULARITY 1
