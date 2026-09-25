//! Error types.

use thiserror::Error;

/// A storage operation that failed.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum StoreError {
    /// ClickHouse refused a request, or could not be reached.
    #[error("clickhouse: {0}")]
    ClickHouse(#[from] clickhouse::error::Error),

    /// A database name that is not a plain identifier. It is written into
    /// statements, so nothing else is accepted.
    #[error("`{0}` is not a valid database name: use letters, digits, and underscores")]
    DatabaseName(String),

    /// A migration recorded as applied differs from the one this build
    /// carries: it was edited after release.
    #[error(
        "migration {version} (`{name}`) was changed after it was applied; add a new migration instead"
    )]
    MigrationChanged {
        /// Its version.
        version: u32,
        /// Its name.
        name: String,
    },

    /// The database has migrations this build does not know, so it was
    /// migrated by a newer build, whose schema this one may misuse.
    #[error("the database schema is at version {database}, newer than this build's {build}")]
    SchemaNewer {
        /// The highest version applied to the database.
        database: u32,
        /// The highest version this build carries.
        build: u32,
    },

    /// A kind of normalization outcome this crate does not know where to
    /// store.
    #[error("no storage for outcome {0}")]
    UnknownOutcome(String),
}
