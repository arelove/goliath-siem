//! What resolution reads and writes: the claims added up, and the mapping
//! from identifiers to entities as one run decided it.
//!
//! See `docs/adr/0025-entity-graph.md`. The deciding is `goliath-graph`'s;
//! here identifiers are text, and a run is a version.

use clickhouse::Row;
use serde::{Deserialize, Serialize};

use crate::error::StoreError;
use crate::store::Store;

/// Versions of the mapping kept: the newest, and two before it for a
/// reader that began with one of them.
const KEPT: usize = 3;

/// Two identifiers seen as one thing, added up over every day it was seen.
#[derive(Debug, Clone, PartialEq, Eq, Row, Deserialize)]
pub struct Claimed {
    /// The scope of the events; empty for none.
    pub scope: String,
    /// The strongest identifier of the object that gave both.
    pub one: String,
    /// The other.
    pub other: String,
    /// What read them as one.
    pub rule: String,
    /// Events that showed it.
    pub events: u64,
    /// When it was first seen, in milliseconds since the epoch.
    pub first_seen: i64,
    /// When it was last seen.
    pub last_seen: i64,
}

/// One identifier's place in an entity, and why it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    /// The scope the identifier is of; empty for none.
    pub scope: String,
    /// The identifier.
    pub identifier: String,
    /// The entity, as its strongest identifier.
    pub entity: String,
    /// `member`, `alias`, or `shared`.
    pub standing: String,
    /// The identifier it was seen as one thing with; empty for an entity's
    /// own first identifier.
    pub via: String,
    /// What read that, or `said` for a person's word.
    pub rule: String,
    /// The file, its version, and the reason, for a person's word.
    pub said: String,
    /// Events that showed it.
    pub events: u64,
    /// When it was first seen, in milliseconds since the epoch.
    pub first_seen: i64,
    /// When it was last seen.
    pub last_seen: i64,
}

/// One run of resolution: what it read and what it found.
#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub struct Resolving {
    /// The run's version: when it began, in milliseconds since the epoch.
    pub version: u64,
    /// When it had written everything.
    pub finished: i64,
    /// Claims read.
    pub claims: u64,
    /// Entities of more than one identifier.
    pub entities: u64,
    /// Identifiers that are members of those.
    pub members: u64,
    /// Weak identifiers attached to an entity.
    pub aliases: u64,
    /// Identifiers set aside as shared.
    pub shared: u64,
    /// Claims not followed, since a person said the two are different.
    pub held_apart: u64,
    /// The decisions files in force, each with its version.
    pub decisions: String,
}

#[derive(Debug, Row, Serialize)]
struct PlacedRow<'a> {
    version: u64,
    scope: &'a str,
    identifier: &'a str,
    entity: &'a str,
    standing: &'a str,
    via: &'a str,
    rule: &'a str,
    said: &'a str,
    events: u64,
    first_seen: i64,
    last_seen: i64,
}

#[derive(Debug, Row, Deserialize)]
struct Partition {
    partition: String,
}

impl Store {
    /// Every claim the store holds, each pair and rule once, added up.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails.
    pub async fn claimed(&self) -> Result<Vec<Claimed>, StoreError> {
        Ok(self
            .client()
            .query(
                "SELECT scope, one, other, rule, sum(events) AS events, \
                 toUnixTimestamp64Milli(min(first_seen)) AS first_seen, \
                 toUnixTimestamp64Milli(max(last_seen)) AS last_seen \
                 FROM graph_claims GROUP BY scope, one, other, rule \
                 ORDER BY scope, one, other, rule",
            )
            .with_setting("prefer_column_name_to_alias", "1")
            .fetch_all::<Claimed>()
            .await?)
    }

    /// Writes a run of resolution: its rows, then the row that says the run
    /// is complete, and drops the versions before the last few.
    ///
    /// A run that stops between the two leaves rows no reader takes, which
    /// the next run's cleaning drops.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a request fails.
    pub async fn write_resolution(
        &self,
        run: &Resolving,
        placed: &[Placed],
    ) -> Result<(), StoreError> {
        if !placed.is_empty() {
            let mut insert = self
                .client()
                .insert::<PlacedRow<'_>>("graph_entities")
                .await?;
            for one in placed {
                insert
                    .write(&PlacedRow {
                        version: run.version,
                        scope: &one.scope,
                        identifier: &one.identifier,
                        entity: &one.entity,
                        standing: &one.standing,
                        via: &one.via,
                        rule: &one.rule,
                        said: &one.said,
                        events: one.events,
                        first_seen: one.first_seen,
                        last_seen: one.last_seen,
                    })
                    .await?;
            }
            insert.end().await?;
        }
        let mut insert = self
            .client()
            .insert::<Resolving>("graph_resolutions")
            .await?;
        insert.write(run).await?;
        insert.end().await?;
        self.drop_old_resolutions().await
    }

    /// Drops every version of the mapping but the last [`KEPT`] complete
    /// ones.
    async fn drop_old_resolutions(&self) -> Result<(), StoreError> {
        let kept: Vec<u64> = self
            .client()
            .query(&format!(
                "SELECT DISTINCT version FROM graph_resolutions ORDER BY version DESC LIMIT {KEPT}"
            ))
            .fetch_all::<u64>()
            .await?;
        let Some(oldest) = kept.last().copied() else {
            return Ok(());
        };
        let partitions = self
            .client()
            .query(
                "SELECT DISTINCT partition FROM system.parts \
                 WHERE database = currentDatabase() AND table = 'graph_entities' AND active",
            )
            .fetch_all::<Partition>()
            .await?;
        for partition in partitions {
            // A partition is named by its version, a number and nothing
            // else; what is not one is not this table's and is left.
            let Ok(version) = partition.partition.parse::<u64>() else {
                continue;
            };
            if version < oldest {
                self.client()
                    .query(&format!(
                        "ALTER TABLE graph_entities DROP PARTITION {version}"
                    ))
                    .execute()
                    .await?;
            }
        }
        Ok(())
    }

    /// The newest complete run of resolution, if there was one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails.
    pub async fn resolution(&self) -> Result<Option<Resolving>, StoreError> {
        Ok(self
            .client()
            .query(
                "SELECT version, toUnixTimestamp64Milli(finished) AS finished, claims, entities, \
                 members, aliases, shared, held_apart, decisions \
                 FROM graph_resolutions FINAL ORDER BY version DESC LIMIT 1",
            )
            .with_setting("prefer_column_name_to_alias", "1")
            .fetch_optional::<Resolving>()
            .await?)
    }
}
