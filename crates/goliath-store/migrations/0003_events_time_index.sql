-- A minmax index on `time`, one entry per granule. The sorting key starts
-- with `class_uid`, so a search over every class narrows `time` only within
-- each class; parts are partitioned by `received`, so none is skipped by the
-- time it holds. The index skips every granule outside the window instead.
-- See docs/benchmarks.md, Search.
ALTER TABLE events ADD INDEX IF NOT EXISTS time_range time TYPE minmax GRANULARITY 1
