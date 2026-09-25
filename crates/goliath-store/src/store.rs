//! A connection to the event store.

use std::num::NonZeroU16;

use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};

use crate::batch::{Batch, DeadLetterRow, EventRow};
use crate::error::StoreError;
use crate::migrate::{LEDGER, MIGRATIONS};

/// The event store: one ClickHouse database.
///
/// Cheap to clone; clones share connections.
#[derive(Clone)]
pub struct Store {
    /// Connected to the store's database.
    client: Client,
    /// The same server with no database selected, to create it.
    server: Client,
    database: String,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The client holds credentials; show only where it points.
        f.debug_struct("Store")
            .field("database", &self.database)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Row, Deserialize)]
struct Applied {
    version: u32,
    name: String,
    checksum: String,
}

#[derive(Debug, Row, Serialize)]
struct Record<'a> {
    version: u32,
    name: &'a str,
    checksum: &'a str,
}

impl Store {
    /// A store in the database `database` of the ClickHouse server at `url`,
    /// such as `http://localhost:8123`. Nothing is contacted until the first
    /// request.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DatabaseName`] unless `database` is a plain
    /// identifier.
    pub fn new(url: &str, database: &str) -> Result<Self, StoreError> {
        let valid = database
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && database
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(StoreError::DatabaseName(database.to_owned()));
        }
        let server = Client::default()
            .with_url(url)
            // The event column is JSON, sent as its text.
            .with_setting("input_format_binary_read_json_as_string", "1")
            // Newer servers answer in ZSTD by default; the client reads LZ4,
            // which also costs less CPU per byte on the write path.
            .with_setting("network_compression_method", "lz4");
        Ok(Self {
            client: server.clone().with_database(database),
            server,
            database: database.to_owned(),
        })
    }

    /// The same store, authenticating as `user`.
    #[must_use]
    pub fn with_credentials(self, user: &str, password: &str) -> Self {
        Self {
            client: self.client.with_user(user).with_password(password),
            server: self.server.with_user(user).with_password(password),
            database: self.database,
        }
    }

    /// The database's name.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Creates the database if needed, and applies the migrations it lacks,
    /// in order. Returns the versions applied.
    ///
    /// Safe to run from several processes at once: every migration is
    /// repeatable, so one that runs twice does nothing the second time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::MigrationChanged`] if an applied migration was
    /// edited since, [`StoreError::SchemaNewer`] if a newer build migrated
    /// the database, and [`StoreError::ClickHouse`] if a request fails.
    pub async fn migrate(&self) -> Result<Vec<u32>, StoreError> {
        self.server
            .query(&format!("CREATE DATABASE IF NOT EXISTS {}", self.database))
            .execute()
            .await?;
        self.client.query(LEDGER).execute().await?;
        let applied = self
            .client
            // Every record, not one per version: two processes migrating at
            // once may record a version twice, and each record is checked,
            // so that a changed one cannot hide behind an unchanged one.
            .query(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version, checksum",
            )
            .fetch_all::<Applied>()
            .await?;

        let build = MIGRATIONS.last().map_or(0, |migration| migration.version);
        if let Some(newest) = applied.last().filter(|newest| newest.version > build) {
            return Err(StoreError::SchemaNewer {
                database: newest.version,
                build,
            });
        }
        for record in &applied {
            let unchanged = MIGRATIONS.iter().any(|migration| {
                migration.version == record.version && migration.checksum() == record.checksum
            });
            if !unchanged {
                return Err(StoreError::MigrationChanged {
                    version: record.version,
                    name: record.name.clone(),
                });
            }
        }

        let mut done = Vec::new();
        for migration in MIGRATIONS {
            if applied
                .iter()
                .any(|record| record.version == migration.version)
            {
                continue;
            }
            self.client.query(migration.sql).execute().await?;
            let checksum = migration.checksum();
            let mut insert = self
                .client
                .insert::<Record<'_>>("schema_migrations")
                .await?;
            insert
                .write(&Record {
                    version: migration.version,
                    name: migration.name,
                    checksum: &checksum,
                })
                .await?;
            insert.end().await?;
            done.push(migration.version);
        }
        Ok(done)
    }

    /// Deletes what was received more than `days` days ago, events and dead
    /// letters alike, or keeps everything if `days` is `None`.
    ///
    /// Age is counted from when the platform received a record, not from the
    /// time the record claims: that is written by the source, and must not
    /// let whoever writes the logs decide when evidence is deleted. Whole
    /// days are deleted at once, as partitions, never row by row.
    ///
    /// Does nothing if the retention is already `days`. Changing it makes
    /// ClickHouse read the receipt time of every stored part once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a request fails.
    pub async fn set_retention(&self, days: Option<NonZeroU16>) -> Result<(), StoreError> {
        if self.retention().await? == days {
            return Ok(());
        }
        for table in ["events", "dead_letters"] {
            let change = match days {
                Some(days) => format!(
                    "ALTER TABLE {table} MODIFY TTL toDateTime(received) + toIntervalDay({days})"
                ),
                None => format!("ALTER TABLE {table} REMOVE TTL"),
            };
            self.client.query(&change).execute().await?;
        }
        Ok(())
    }

    /// The retention in days, as [`set_retention`](Self::set_retention)
    /// set it, or `None` if everything is kept.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a request fails.
    pub async fn retention(&self) -> Result<Option<NonZeroU16>, StoreError> {
        let engines = self
            .client
            .query(
                "SELECT engine_full FROM system.tables                  WHERE database = currentDatabase() AND name IN ('events', 'dead_letters')                  ORDER BY name",
            )
            .fetch_all::<String>()
            .await?;
        let days: Vec<Option<NonZeroU16>> =
            engines.iter().map(|engine| days_kept(engine)).collect();
        // The tables are changed one after the other; if a change stopped
        // between them, they disagree, and neither answer is the retention.
        Ok(match days.as_slice() {
            [first, rest @ ..] if rest.iter().all(|days| days == first) => *first,
            _ => None,
        })
    }

    /// Writes a batch: its events, then its dead letters.
    ///
    /// Writing the same batch again is safe: events are deduplicated by
    /// identity. Dead letters are not, and may repeat.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a request fails. Events may
    /// then have been written without the dead letters; write the batch
    /// again.
    pub async fn write(&self, batch: &Batch) -> Result<(), StoreError> {
        if !batch.events.is_empty() {
            let mut insert = self.client.insert::<EventRow>("events").await?;
            for row in &batch.events {
                insert.write(row).await?;
            }
            insert.end().await?;
        }
        if !batch.dead_letters.is_empty() {
            let mut insert = self.client.insert::<DeadLetterRow>("dead_letters").await?;
            for row in &batch.dead_letters {
                insert.write(row).await?;
            }
            insert.end().await?;
        }
        Ok(())
    }
}

/// The days in a table's TTL, as [`Store::set_retention`] writes it.
fn days_kept(engine: &str) -> Option<NonZeroU16> {
    let (_, rest) = engine.split_once("TTL toDateTime(received) + toIntervalDay(")?;
    let (days, _) = rest.split_once(')')?;
    days.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_back_the_retention_it_writes() {
        let engine = "MergeTree PARTITION BY toDate(received) ORDER BY x                       TTL toDateTime(received) + toIntervalDay(30) SETTINGS ttl_only_drop_parts = 1";
        assert_eq!(days_kept(engine), NonZeroU16::new(30));
        assert_eq!(days_kept("MergeTree ORDER BY x"), None);
    }

    #[test]
    fn database_names_are_plain_identifiers() {
        assert!(Store::new("http://localhost:8123", "goliath_1").is_ok());
        for name in ["", "1st", "a-b", "a;DROP", "a b"] {
            assert!(matches!(
                Store::new("http://localhost:8123", name),
                Err(StoreError::DatabaseName(_))
            ));
        }
    }
}
