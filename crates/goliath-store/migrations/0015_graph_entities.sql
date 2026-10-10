-- Which identifiers are one entity, as resolution decided it. See
-- docs/adr/0025-entity-graph.md.
--
-- One row for each identifier that is a member of an entity of more than
-- one, an alias of an entity, or set aside as shared; an identifier with
-- no row is an entity of its own. `entity` is the entity's strongest
-- identifier. `via` is the identifier this one was seen as one thing
-- with, `rule` what read that, and `said` the file, its version, and the
-- reason where a person decided it: every row says why it is there.
--
-- A run of resolution writes all of its rows under one version, and is
-- complete once `graph_resolutions` names that version. Readers take the
-- newest complete version. Each version is a partition, so that old ones
-- are dropped whole.
--
-- Nothing else is changed by a run: the links and the claims stay under
-- the identifiers the events gave, and this table says which of them are
-- read together.
CREATE TABLE IF NOT EXISTS graph_entities
(
    version UInt64,
    scope LowCardinality(String),
    identifier String,
    entity String,
    standing LowCardinality(String),
    via String,
    rule LowCardinality(String),
    said String,
    events UInt64,
    first_seen DateTime64(3, 'UTC'),
    last_seen DateTime64(3, 'UTC'),
    PROJECTION by_entity
    (
        SELECT *
        ORDER BY (scope, entity, standing, identifier)
    )
)
ENGINE = MergeTree
PARTITION BY version
ORDER BY (scope, identifier, entity)
