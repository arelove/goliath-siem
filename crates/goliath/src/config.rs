//! The configuration file.
//!
//! Written by an operator, and read strictly: an unknown key is an error, so
//! that a misspelled setting is not silently replaced by its default.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU64};
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
    /// Where durable topics and positions are kept, unless they are in
    /// Kafka.
    pub data: Option<PathBuf>,
    /// Kafka, to keep topics in instead of the data directory, so that roles
    /// can run in separate processes.
    pub kafka: Option<KafkaConfig>,
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
    /// The source definition: the name of a built-in one, `sysmon`, `falco`, or `entra`,
    /// or the path of a YAML file.
    pub definition: String,
    /// A directory the collector takes files from; needed by the collector
    /// only.
    pub inbox: Option<PathBuf>,
}

/// Kafka, or a service with its API such as Redpanda.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KafkaConfig {
    /// The bootstrap servers, such as `redpanda:9092`.
    pub brokers: String,
    /// Put before every topic and group name, so that deployments can share
    /// a cluster.
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Replicas of each topic created; 3 unless the cluster has fewer
    /// brokers.
    #[serde(default = "default_replication")]
    pub replication: i32,
    /// Records a topic holds for its slowest reader before senders wait.
    pub capacity: Option<NonZeroU64>,
    /// The environment variable holding the SASL password.
    pub password_env: Option<String>,
    /// A file holding the SASL password, as secrets are mounted. Preferred
    /// over `password_env`.
    pub password_file: Option<PathBuf>,
    /// Further librdkafka settings, such as `security.protocol`,
    /// `sasl.mechanism`, and `sasl.username`; never the password.
    #[serde(default)]
    pub client: BTreeMap<String, String>,
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
    /// A file holding the password, as Docker and Kubernetes mount secrets,
    /// such as `/run/secrets/clickhouse_password`. Surrounding whitespace is
    /// ignored. Preferred over `password_env`: a file is not inherited by
    /// child processes or shown by `docker inspect`.
    pub password_file: Option<PathBuf>,
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

fn default_prefix() -> String {
    "goliath-".to_owned()
}

fn default_replication() -> i32 {
    3
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
        let files = [
            config.data.as_mut(),
            config
                .store
                .as_mut()
                .and_then(|store| store.password_file.as_mut()),
            config
                .kafka
                .as_mut()
                .and_then(|kafka| kafka.password_file.as_mut()),
        ];
        for file in files.into_iter().flatten() {
            *file = base.join(&*file);
        }
        for source in &mut config.sources {
            if let Some(inbox) = &mut source.inbox {
                *inbox = base.join(&*inbox);
            }
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
            if self.roles.contains(&Role::Collector) && source.inbox.is_none() {
                return Err(RunError::Config(format!(
                    "source `{}` needs an inbox for the collector",
                    normalizer.name()
                )));
            }
        }
        match &self.kafka {
            None if self.data.is_none() => {
                return Err(RunError::Config(
                    "set `data` for topics on disk, or a [kafka] section".to_owned(),
                ));
            }
            None => {}
            Some(kafka) => kafka.check()?,
        }
        if self.roles.contains(&Role::Writer) && self.store.is_none() {
            return Err(RunError::Config(
                "the writer role needs a [store] section".to_owned(),
            ));
        }
        if let Some(store) = &self.store
            && store.password_env.is_some()
            && store.password_file.is_some()
        {
            return Err(RunError::Config(
                "[store] takes password_env or password_file, not both".to_owned(),
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

impl StoreConfig {
    /// The password, from the file or the environment variable named, or
    /// empty if neither is.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if the file cannot be read or the
    /// variable is not set.
    pub fn password(&self) -> Result<String, RunError> {
        Ok(secret(self.password_env.as_ref(), self.password_file.as_ref())?.unwrap_or_default())
    }
}

impl KafkaConfig {
    fn check(&self) -> Result<(), RunError> {
        if cfg!(not(feature = "kafka")) {
            return Err(RunError::Config(
                "this goliath was built without Kafka; build it with `--features kafka`".to_owned(),
            ));
        }
        if self.password_env.is_some() && self.password_file.is_some() {
            return Err(RunError::Config(
                "[kafka] takes password_env or password_file, not both".to_owned(),
            ));
        }
        for key in ["bootstrap.servers", "sasl.password"] {
            if self.client.contains_key(key) {
                return Err(RunError::Config(format!(
                    "set `{key}` through `brokers` or `password_file`, not [kafka.client]"
                )));
            }
        }
        if self.replication < 1 {
            return Err(RunError::Config(
                "[kafka] replication must be at least 1".to_owned(),
            ));
        }
        Ok(())
    }

    /// The client settings, with the SASL password added if one is named.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if the password cannot be read.
    pub fn client(&self) -> Result<BTreeMap<String, String>, RunError> {
        let mut client = self.client.clone();
        if let Some(password) = secret(self.password_env.as_ref(), self.password_file.as_ref())? {
            client.insert("sasl.password".to_owned(), password);
        }
        Ok(client)
    }
}

/// A secret from a file, without surrounding whitespace, or from an
/// environment variable, if either is named.
fn secret(variable: Option<&String>, file: Option<&PathBuf>) -> Result<Option<String>, RunError> {
    if let Some(path) = file {
        let text = std::fs::read_to_string(path)
            .map_err(|error| RunError::Config(format!("{}: {error}", path.display())))?;
        return Ok(Some(text.trim().to_owned()));
    }
    match variable {
        Some(variable) => std::env::var(variable)
            .map(Some)
            .map_err(|_| RunError::Config(format!("environment variable {variable} is not set"))),
        None => Ok(None),
    }
}

impl SourceConfig {
    /// Loads the source definition.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if it cannot be read or does not load.
    pub fn normalizer(&self) -> Result<Normalizer, RunError> {
        let text = match goliath_normalize::builtin(&self.definition) {
            Some(text) => text.to_owned(),
            None => std::fs::read_to_string(&self.definition)
                .map_err(|error| RunError::Config(format!("{}: {error}", self.definition)))?,
        };
        Normalizer::from_yaml(&text).map_err(|error| {
            RunError::Config(format!("source definition `{}`: {error}", self.definition))
        })
    }
}

fn is_builtin(definition: &str) -> bool {
    goliath_normalize::builtin(definition).is_some()
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
        let no_inbox = MINIMAL.replace("inbox = \"inbox/sysmon\"", "");
        assert!(parse(&no_inbox).is_err());
        let no_topics = MINIMAL.replace("data = \"data\"", "");
        assert!(parse(&no_topics).is_err());
    }

    const NORMALIZER: &str = r#"
roles = ["normalizer"]

[[sources]]
definition = "sysmon"

[kafka]
brokers = "redpanda:9092"
"#;

    #[cfg(feature = "kafka")]
    #[test]
    fn a_role_alone_needs_kafka_and_nothing_it_does_not_use() {
        let config = parse(NORMALIZER).unwrap();
        let kafka = config.kafka.unwrap();
        assert_eq!(kafka.prefix, "goliath-");
        assert_eq!(kafka.replication, 3);
        assert!(config.data.is_none());
        assert!(config.sources[0].inbox.is_none());

        let password_in_file = format!("{NORMALIZER}[kafka.client]\n\"sasl.password\" = \"x\"\n");
        assert!(parse(&password_in_file).is_err());
        let no_replicas = format!("{NORMALIZER}replication = 0\n");
        assert!(parse(&no_replicas).is_err());
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn kafka_is_refused_by_a_build_without_it() {
        let error = parse(NORMALIZER).unwrap_err().to_string();
        assert!(error.contains("--features kafka"), "{error}");
    }

    #[test]
    fn a_password_comes_from_a_file_without_its_newline() {
        let directory = std::env::temp_dir().join(format!("goliath-config-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let secret = directory.join("clickhouse_password");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let text = MINIMAL.replace(
            "database = \"goliath\"",
            &format!("database = \"goliath\"\nuser = \"goliath\"\npassword_file = {secret:?}"),
        );
        let config = parse(&text).unwrap();
        assert_eq!(config.store.unwrap().password().unwrap(), "s3cret");

        let both = text.replace(
            "user = \"goliath\"",
            "user = \"goliath\"\npassword_env = \"X\"",
        );
        assert!(parse(&both).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
