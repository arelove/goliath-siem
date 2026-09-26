//! The storage schema, as forward-only, versioned migrations.
//!
//! Each migration is one statement. ClickHouse applies DDL statement by
//! statement, with no transaction around several, so a migration of two
//! statements could stop halfway and leave a schema no version describes.
//! Each statement is also written to be repeatable (`IF NOT EXISTS`): a
//! migration that ran but was not yet recorded runs again harmlessly.
//!
//! Applied migrations are recorded with a checksum of their text. Editing a
//! migration after release is refused at startup rather than silently
//! diverging from the databases it already ran on: change the schema with a
//! new migration instead.

/// One schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The position in the sequence, from 1, without gaps.
    pub version: u32,
    /// A short name, such as `events`.
    pub name: &'static str,
    /// The statement.
    pub sql: &'static str,
}

impl Migration {
    /// The BLAKE3 hash of the statement, in hexadecimal, recorded when the
    /// migration is applied.
    pub fn checksum(&self) -> String {
        blake3::hash(self.sql.as_bytes()).to_hex().to_string()
    }
}

/// Every migration, in order.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "events",
        sql: include_str!("../migrations/0001_events.sql"),
    },
    Migration {
        version: 2,
        name: "dead_letters",
        sql: include_str!("../migrations/0002_dead_letters.sql"),
    },
    Migration {
        version: 3,
        name: "events_time_index",
        sql: include_str!("../migrations/0003_events_time_index.sql"),
    },
    Migration {
        version: 4,
        name: "events_time_index_built",
        sql: include_str!("../migrations/0004_events_time_index_built.sql"),
    },
];

/// Where applied migrations are recorded. Created before any migration runs,
/// so it is not a migration itself.
pub(crate) const LEDGER: &str = "CREATE TABLE IF NOT EXISTS schema_migrations
(
    version UInt32,
    name String,
    checksum String,
    applied DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY version";

#[cfg(test)]
mod tests {
    use super::*;

    /// The statement without comments or surrounding whitespace.
    fn statement(sql: &str) -> String {
        sql.lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_owned()
    }

    #[test]
    fn versions_start_at_one_without_gaps() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migration.version as usize, index + 1, "{}", migration.name);
        }
    }

    #[test]
    fn each_migration_is_one_repeatable_statement() {
        for migration in MIGRATIONS {
            let statement = statement(migration.sql);
            assert!(
                !statement.contains(';'),
                "{} has more than one statement",
                migration.name
            );
            assert!(
                ["CREATE TABLE IF NOT EXISTS ", "ALTER TABLE "]
                    .iter()
                    .any(|start| statement.starts_with(start))
                    && (!statement.contains(" ADD ") || statement.contains(" IF NOT EXISTS ")),
                "{} is not repeatable",
                migration.name
            );
        }
    }

    #[test]
    fn checksums_differ_between_migrations() {
        assert_ne!(MIGRATIONS[0].checksum(), MIGRATIONS[1].checksum());
        assert_eq!(MIGRATIONS[0].checksum().len(), 64);
    }
}
