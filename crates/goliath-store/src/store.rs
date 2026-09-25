//! A connection to the event store.

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
            .query("SELECT version, any(name) AS name, any(checksum) AS checksum FROM schema_migrations GROUP BY version ORDER BY version")
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
