//! Reading the graph: what one entity holds, and what it was seen with.
//!
//! See "What the API answers" in `docs/adr/0025-entity-graph.md`. Links are
//! stored under identifiers; the mapping of the newest complete resolution
//! says which identifiers are read together, here and nowhere else, so a
//! reader sees a merge only for as long as resolution stands by it.
//!
//! Every query is read-only, within the limits of a search, and takes its
//! values as parameters.

use clickhouse::Row;
use serde::Deserialize;

use crate::error::StoreError;
use crate::resolution::Placed;
use crate::search::{SearchLimits, with_limits};
use crate::store::Store;

/// The newest complete resolution, as a query's own value. With none yet,
/// the version is 0, which no row has: every identifier is then its own
/// entity.
const NEWEST: &str = "(SELECT max(version) FROM graph_resolutions)";

/// An entity as the newest resolution has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    /// The entity, as its strongest identifier: the one asked for, if it is
    /// in no entity of more than one.
    pub entity: String,
    /// Its identifiers and the weak ones seen with it, each with why it is
    /// there; empty for an identifier that is an entity of its own.
    pub identifiers: Vec<Placed>,
    /// The entities the identifier asked for is an alias of, if it is weak
    /// and was seen with any.
    pub alias_of: Vec<String>,
    /// Whether the identifier asked for is set aside as shared.
    pub shared: bool,
}

/// What an entity was seen with in one way, within a time range.
#[derive(Debug, Clone, PartialEq, Eq, Row, Deserialize)]
pub struct Neighbour {
    /// The other entity, as its strongest identifier.
    pub entity: String,
    /// Whether the entity asked for acted, `out`, or was acted on, `in`.
    pub direction: String,
    /// What was done, such as `logged_on_to`.
    pub link: String,
    /// Events that showed it.
    pub events: u64,
    /// When it was first seen in the range, in milliseconds since the
    /// epoch.
    pub first_seen: i64,
    /// When it was last seen in the range.
    pub last_seen: i64,
}

/// The neighbours of an entity within a time range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbours {
    /// The neighbours, the most recently seen first, as many as were asked
    /// for at most.
    pub neighbours: Vec<Neighbour>,
    /// How many entities it was seen with in the range in all: its degree.
    pub degree: u64,
}

#[derive(Debug, Row, Deserialize)]
struct PlacedRow {
    scope: String,
    identifier: String,
    entity: String,
    standing: String,
    via: String,
    rule: String,
    said: String,
    events: u64,
    first_seen: i64,
    last_seen: i64,
}

impl From<PlacedRow> for Placed {
    fn from(row: PlacedRow) -> Self {
        Self {
            scope: row.scope,
            identifier: row.identifier,
            entity: row.entity,
            standing: row.standing,
            via: row.via,
            rule: row.rule,
            said: row.said,
            events: row.events,
            first_seen: row.first_seen,
            last_seen: row.last_seen,
        }
    }
}

const PLACED: &str = "scope, identifier, entity, standing, via, rule, said, events, \
                      toUnixTimestamp64Milli(first_seen) AS first_seen, \
                      toUnixTimestamp64Milli(last_seen) AS last_seen";

fn by_column(query: clickhouse::query::Query) -> clickhouse::query::Query {
    query.with_setting("prefer_column_name_to_alias", "1")
}

impl Store {
    /// The entity the identifier `identifier` of `scope` is in, with
    /// everything the newest resolution says of it.
    ///
    /// An identifier resolution says nothing of is an entity of its own,
    /// and so is every identifier before the first resolution.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a query fails or exceeds
    /// `limits`.
    pub async fn entity(
        &self,
        scope: &str,
        identifier: &str,
        limits: SearchLimits,
    ) -> Result<Entity, StoreError> {
        // Where the identifier itself stands.
        let own: Vec<Placed> = with_limits(
            by_column(self.client().query(&format!(
                "SELECT {PLACED} FROM graph_entities \
                 WHERE version = {NEWEST} AND scope = {{scope:String}} \
                 AND identifier = {{identifier:String}} ORDER BY standing, entity"
            )))
            .param("scope", scope)
            .param("identifier", identifier),
            limits,
        )
        .fetch_all::<PlacedRow>()
        .await?
        .into_iter()
        .map(Placed::from)
        .collect();
        let member = own.iter().find(|placed| placed.standing == "member");
        let entity = member.map_or(identifier, |placed| placed.entity.as_str());
        let alias_of = own
            .iter()
            .filter(|placed| placed.standing == "alias")
            .map(|placed| placed.entity.clone())
            .collect();
        let shared = own.iter().any(|placed| placed.standing == "shared");
        // Everything the entity holds, its own identifiers first.
        let identifiers = with_limits(
            by_column(self.client().query(&format!(
                "SELECT {PLACED} FROM graph_entities \
                 WHERE version = {NEWEST} AND scope = {{scope:String}} \
                 AND entity = {{entity:String}} AND standing != 'shared' \
                 ORDER BY standing = 'alias', via != '', identifier"
            )))
            .param("scope", scope)
            .param("entity", entity),
            limits,
        )
        .fetch_all::<PlacedRow>()
        .await?
        .into_iter()
        .map(Placed::from)
        .collect();
        Ok(Entity {
            entity: entity.to_owned(),
            identifiers,
            alias_of,
            shared,
        })
    }

    /// What the entity that holds `identifiers` was seen with from `from`
    /// up to and not including `to`, in milliseconds since the epoch: its
    /// neighbours, each once for each way and direction it was seen in,
    /// the most recently seen first and `limit` at most, and how many
    /// entities that is in all.
    ///
    /// `links` bounds the kinds of link; every kind if empty. A neighbour
    /// is named by its entity as the newest resolution has it, so two
    /// identifiers of one neighbour are one row.
    ///
    /// The range is taken by the hour links are counted in: a link is
    /// found if its hour begins in the range.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a query fails or exceeds
    /// `limits`.
    pub async fn neighbours(
        &self,
        scope: &str,
        identifiers: &[String],
        (from, to): (i64, i64),
        links: &[String],
        limit: u32,
        limits: SearchLimits,
    ) -> Result<Neighbours, StoreError> {
        let kinds = if links.is_empty() {
            ""
        } else {
            "AND link IN {links:Array(String)}"
        };
        // Both directions, each from the order that serves it, and each
        // other end as the entity it is a member of.
        // The columns of the rows read are named apart from what is
        // answered, so that no name means two things.
        let seen = format!(
            "SELECT if(placed.entity = '', seen.other, placed.entity) AS neighbour, \
             seen.direction AS direction, seen.link AS link, seen.counted AS counted, \
             seen.first_at AS first_at, seen.last_at AS last_at FROM ( \
               SELECT dst AS other, 'out' AS direction, link, events AS counted, \
               first_seen AS first_at, last_seen AS last_at \
               FROM graph_links WHERE scope = {{scope:String}} \
               AND src IN {{identifiers:Array(String)}} \
               AND hour >= toDateTime(intDiv({{from:Int64}}, 1000), 'UTC') \
               AND hour < toDateTime(intDiv({{to:Int64}}, 1000), 'UTC') {kinds} \
               UNION ALL \
               SELECT src AS other, 'in' AS direction, link, events AS counted, \
               first_seen AS first_at, last_seen AS last_at \
               FROM graph_links WHERE scope = {{scope:String}} \
               AND dst IN {{identifiers:Array(String)}} \
               AND hour >= toDateTime(intDiv({{from:Int64}}, 1000), 'UTC') \
               AND hour < toDateTime(intDiv({{to:Int64}}, 1000), 'UTC') {kinds} \
             ) AS seen LEFT JOIN ( \
               SELECT identifier, entity FROM graph_entities \
               WHERE version = {NEWEST} AND scope = {{scope:String}} AND standing = 'member' \
             ) AS placed ON placed.identifier = seen.other"
        );
        let bind = |sql: &str| {
            let mut query = self
                .client()
                .query(sql)
                .param("scope", scope)
                .param("identifiers", identifiers)
                .param("from", from)
                .param("to", to);
            if !links.is_empty() {
                query = query.param("links", links);
            }
            with_limits(query, limits)
        };
        // What an entity did to itself, one of its identifiers to another,
        // is no neighbour.
        let others = format!("FROM ({seen}) WHERE neighbour NOT IN {{identifiers:Array(String)}}");
        let neighbours = bind(&format!(
            "SELECT neighbour AS entity, direction, link, sum(counted) AS events, \
             toUnixTimestamp64Milli(min(first_at)) AS first_seen, \
             toUnixTimestamp64Milli(max(last_at)) AS last_seen \
             {others} GROUP BY neighbour, direction, link \
             ORDER BY last_seen DESC, neighbour, direction, link LIMIT {{limit:UInt32}}"
        ))
        .param("limit", limit)
        .fetch_all::<Neighbour>()
        .await?;
        let degree = bind(&format!("SELECT uniqExact(neighbour) {others}"))
            .fetch_one::<u64>()
            .await?;
        Ok(Neighbours { neighbours, degree })
    }
}
