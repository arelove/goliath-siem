//! The configuration file.
//!
//! Written by an operator, and read strictly: an unknown key is an error, so
//! that a misspelled setting is not silently replaced by its default.

use std::collections::BTreeSet;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::Duration;

use goliath_normalize::Normalizer;
use serde::Deserialize;

use crate::RunError;

/// A deployment of some roles.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The roles this process runs.
    pub roles: BTreeSet<Role>,
    /// Where durable topics and positions are kept.
    pub data: PathBuf,
    /// The sources to collect and normalize.
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    /// The event store, for the writer.
    pub store: Option<StoreConfig>,
    /// How the writer batches.
    #[serde(default)]
    pub writer: WriterConfig,
}

/// A role, as named in the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Takes raw records from sources into the pipe.
    Collector,
    /// Turns raw records into OCSF outcomes.
    Normalizer,
    /// Writes outcomes to the event store.
    Writer,
}

/// One source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// The source definition: the name of a built-in one, such as `sysmon`,
    /// or the path of a YAML file.
    pub definition: String,
    /// A directory the collector takes files from.
    pub inbox: PathBuf,
}

/// The event store.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    /// The ClickHouse server, such as `http://localhost:8123`.
    pub url: String,
    /// The database; created if missing.
    pub database: String,
    /// The user, if the server needs one.
    pub user: Option<String>,
    /// The environment variable holding the password. The password itself
    /// is never written in the file.
    pub password_env: Option<String>,
    /// Days to keep events and dead letters, counted from receipt; kept
    /// forever if absent.
    pub retention_days: Option<NonZeroU16>,
}

/// How the writer batches.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterConfig {
    /// Rows per insert at most.
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
    /// Milliseconds a row waits at most before it is written.
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            max_rows: default_max_rows(),
            max_delay_ms: default_max_delay_ms(),
        }
    }
}

impl WriterConfig {
    /// The delay as a duration.
    pub fn max_delay(&self) -> Duration {
        Duration::from_millis(self.max_delay_ms)
    }
}

fn default_max_rows() -> usize {
    50_000
}

fn default_max_delay_ms() -> u64 {
    1000
}

impl Config {
    /// Reads and checks a configuration file. Relative paths in it are taken
    /// relative to the file.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if the file cannot be read, is not a
    /// valid configuration, or names a source definition that does not load.
    pub fn load(path: &Path) -> Result<Self, RunError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| RunError::Config(format!("{}: {error}", path.display())))?;
        let mut config: Self = toml::from_str(&text)
            .map_err(|error| RunError::Config(format!("{}: {error}", path.display())))?;
        let base = path.parent().unwrap_or(Path::new("."));
        config.data = base.join(&config.data);
        for source in &mut config.sources {
            source.inbox = base.join(&source.inbox);
            if !is_builtin(&source.definition) {
                source.definition = base.join(&source.definition).to_string_lossy().into_owned();
            }
        }
        config.check()?;
        Ok(config)
    }

    /// Checks what the types cannot: that every source loads, that names do
    /// not repeat, and that the roles have what they need.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] describing the first problem.
    pub fn check(&self) -> Result<(), RunError> {
        let mut names = BTreeSet::new();
        for source in &self.sources {
            let normalizer = source.normalizer()?;
            if !names.insert(normalizer.name().to_owned()) {
                return Err(RunError::Config(format!(
                    "source `{}` is configured twice",
                    normalizer.name()
                )));
            }
        }
        if self.roles.contains(&Role::Writer) && self.store.is_none() {
            return Err(RunError::Config(
                "the writer role needs a [store] section".to_owned(),
            ));
        }
        if self.writer.max_rows == 0 || self.writer.max_delay_ms == 0 {
            return Err(RunError::Config(
                "writer limits must be above zero".to_owned(),
            ));
        }
        Ok(())
    }
}

impl SourceConfig {
    /// Loads the source definition.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if it cannot be read or does not load.
    pub fn normalizer(&self) -> Result<Normalizer, RunError> {
        let text = match self.definition.as_str() {
            "sysmon" => goliath_normalize::SYSMON.to_owned(),
            path => std::fs::read_to_string(path)
                .map_err(|error| RunError::Config(format!("{path}: {error}")))?,
        };
        Normalizer::from_yaml(&text).map_err(|error| {
            RunError::Config(format!("source definition `{}`: {error}", self.definition))
        })
    }
}

fn is_builtin(definition: &str) -> bool {
    definition == "sysmon"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, RunError> {
        let config: Config =
            toml::from_str(text).map_err(|error| RunError::Config(error.to_string()))?;
        config.check()?;
        Ok(config)
    }

    const MINIMAL: &str = r#"
roles = ["collector", "normalizer", "writer"]
data = "data"

[[sources]]
definition = "sysmon"
inbox = "inbox/sysmon"

[store]
url = "http://localhost:8123"
database = "goliath"
"#;

    #[test]
    fn a_minimal_configuration_loads_with_defaults() {
        let config = parse(MINIMAL).unwrap();
        assert_eq!(config.roles.len(), 3);
        assert_eq!(config.writer.max_rows, 50_000);
        assert_eq!(config.sources[0].normalizer().unwrap().name(), "sysmon");
    }

    #[test]
    fn mistakes_are_errors_not_defaults() {
        let misspelled = MINIMAL.replace("[store]", "[store]\nretention_dayz = 3");
        assert!(parse(&misspelled).is_err());
        let unknown_role = MINIMAL.replace("\"writer\"]", "\"writer\", \"wirter\"]");
        assert!(parse(&unknown_role).is_err());
        let twice = format!(
            "{MINIMAL}
[[sources]]
definition = \"sysmon\"
inbox = \"other\"
"
        );
        assert!(parse(&twice).is_err());
        let no_store = MINIMAL.split("[store]").next().unwrap().to_owned();
        assert!(parse(&no_store).is_err());
    }
}
