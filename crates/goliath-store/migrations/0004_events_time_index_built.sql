-- Builds the index of migration 3 for parts written before it, in the
-- background: new parts and merges build it themselves. Running it again
-- rebuilds it, which is harmless.
ALTER TABLE events MATERIALIZE INDEX time_range
