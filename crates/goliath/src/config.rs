//! The configuration file.
//!
//! Written by an operator, and read strictly: an unknown key is an error, so
//! that a misspelled setting is not silently replaced by its default.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize};
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
    /// What this process is called in the health of the platform; its
    /// host's name, or its pod's, if left out.
    pub instance: Option<String>,
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
    /// How the normalizer uses the machine.
    #[serde(default)]
    pub normalizer: NormalizerConfig,
    /// The indicators the detector matches; needed by the detector role.
    pub detector: Option<DetectorConfig>,
    /// Where and how the API listens.
    #[serde(default)]
    pub api: ApiConfig,
    /// Where the receiver listens.
    #[serde(default)]
    pub receiver: ReceiverConfig,
    /// Where Prometheus reads this process's metrics; not served if absent.
    pub metrics: Option<MetricsConfig>,
}

/// Where the metrics endpoint listens.
///
/// It takes no token: it holds counts and durations, never an event's
/// content. Listen on an address only the monitoring system reaches.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// The address to serve `/metrics` on, such as `127.0.0.1:9464`.
    pub listen: SocketAddr,
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
    /// Serves searches over the stored events, and the interface.
    Api,
    /// Takes records sent over the network into sources' raw topics.
    Receiver,
    /// Matches indicators against normalized events, and sends each match
    /// on as a finding for the writer to store.
    Detector,
}

impl Role {
    /// The role as the configuration names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collector => "collector",
            Self::Normalizer => "normalizer",
            Self::Writer => "writer",
            Self::Api => "api",
            Self::Receiver => "receiver",
            Self::Detector => "detector",
        }
    }
}

/// The receiver: where it listens, and with what certificate.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverConfig {
    /// The address to listen on; `127.0.0.1:8514` by default. An address
    /// beyond loopback needs `tls`.
    #[serde(default = "default_receiver_listen")]
    pub listen: SocketAddr,
    /// The certificate to serve HTTPS with; plain HTTP if left out.
    pub tls: Option<TlsConfig>,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            listen: default_receiver_listen(),
            tls: None,
        }
    }
}

/// A certificate and its private key, each a PEM file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// The certificate chain, the listener's own certificate first.
    pub certificate: PathBuf,
    /// The certificate's private key.
    pub key: PathBuf,
}

fn default_receiver_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8514))
}

/// How a source takes records over HTTP.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSourceConfig {
    /// A file holding the bearer token a sender must carry, at least 32
    /// bytes, and different from every other source's.
    pub token_file: PathBuf,
}

impl HttpSourceConfig {
    /// The bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if the file cannot be read, or holds
    /// fewer than 32 bytes.
    pub fn token(&self) -> Result<String, RunError> {
        let token = secret(None, Some(&self.token_file))?.unwrap_or_default();
        if token.len() < MIN_TOKEN {
            return Err(RunError::Config(format!(
                "{}: a source's token must be at least {MIN_TOKEN} bytes; generate one with `openssl rand -hex 32`",
                self.token_file.display()
            )));
        }
        Ok(token)
    }
}

/// The API: where it listens, who may use it, and what a search may ask.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// The address to listen on; `127.0.0.1:8080` by default.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// A file holding the bearer token every API request must carry. Needed
    /// unless the API listens on a loopback address only.
    pub token_file: Option<PathBuf>,
    /// A directory holding the built interface, served at `/`.
    pub ui: Option<PathBuf>,
    /// The address people open the interface at, such as
    /// `http://127.0.0.1:8080`, written to the log when the API starts. In
    /// a container the API cannot tell which address of the host its port
    /// is published on, and this says it.
    pub url: Option<String>,
    /// The longest time range a search may cover, in days.
    #[serde(default = "default_max_span_days")]
    pub max_span_days: NonZeroU16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            token_file: None,
            ui: None,
            url: None,
            max_span_days: default_max_span_days(),
        }
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

fn default_max_span_days() -> NonZeroU16 {
    NonZeroU16::new(31).unwrap_or(NonZeroU16::MIN)
}

/// The shortest token accepted: 32 bytes, as `openssl rand -hex 16` writes.
const MIN_TOKEN: usize = 32;

impl ApiConfig {
    /// The bearer token, if one is configured.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if the file cannot be read, or holds
    /// fewer than 32 bytes.
    pub fn token(&self) -> Result<Option<String>, RunError> {
        let Some(token) = secret(None, self.token_file.as_ref())? else {
            return Ok(None);
        };
        if token.len() < MIN_TOKEN {
            return Err(RunError::Config(format!(
                "the API token must be at least {MIN_TOKEN} bytes; generate one with `openssl rand -hex 32`"
            )));
        }
        Ok(Some(token))
    }
}

/// One source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// The source definition: the name of a built-in one, such as `sysmon` or `windows-security`,
    /// or the path of a YAML file.
    pub definition: String,
    /// A directory the collector takes files from; needed by the collector
    /// only.
    pub inbox: Option<PathBuf>,
    /// Whether, and with what token, the receiver takes this source's
    /// records over HTTP.
    pub http: Option<HttpSourceConfig>,
    /// Whether, and where, the receiver takes this source's records as
    /// syslog over TCP.
    pub syslog: Option<SyslogSourceConfig>,
    /// Minutes without an event before source health calls this source
    /// silent; 60 if left out. Longer for a source that delivers late or
    /// seldom. See docs/adr/0019-source-health.md.
    pub silent_after_minutes: Option<NonZeroU32>,
}

/// How a source takes syslog over TCP: a port of its own, since syslog
/// names no source in its messages.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogSourceConfig {
    /// The address to listen on. An address beyond loopback needs `tls`.
    pub listen: SocketAddr,
    /// The certificate to serve TLS with; plain TCP if left out.
    pub tls: Option<TlsConfig>,
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

/// How the normalizer uses the machine.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerConfig {
    /// Threads that normalize a batch at once; every core by default.
    pub threads: Option<NonZeroUsize>,
}

impl NormalizerConfig {
    /// The threads to normalize on.
    pub fn threads(&self) -> NonZeroUsize {
        self.threads.unwrap_or_else(every_core)
    }
}

/// The indicators the detector matches, and where it keeps them. See
/// docs/adr/0021-enrichment-placement.md.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorConfig {
    /// The directory of the indicator store; `intel` in the data directory
    /// if left out.
    pub state: Option<PathBuf>,
    /// The feeds of indicators.
    #[serde(default)]
    pub feeds: Vec<FeedConfig>,
    /// Allowlists, each a YAML file: what is never reported, whatever a
    /// feed says.
    #[serde(default)]
    pub allowlists: Vec<PathBuf>,
    /// What the site knows of its own networks, machines, and accounts,
    /// added to findings. See docs/adr/0022-context-snapshot.md.
    #[serde(default)]
    pub context: Vec<ContextConfig>,
    /// Threads that match a batch at once; every core by default.
    pub threads: Option<NonZeroUsize>,
    /// The block cache of the indicator store, in mebibytes; 1024 if left
    /// out.
    pub cache_mebibytes: Option<NonZeroU64>,
    /// How many days of stored events are matched against indicators a
    /// feed adds; 7 if left out, and never with 0.
    pub look_back_days: Option<u16>,
    /// The least hours from one look back to the next; 24 if left out.
    pub look_back_every_hours: Option<NonZeroU32>,
}

impl DetectorConfig {
    /// The days of stored events a look back reads; none means never.
    pub fn look_back_days(&self) -> u16 {
        self.look_back_days.unwrap_or(7)
    }

    /// The least hours from one look back to the next.
    pub fn look_back_every_hours(&self) -> u32 {
        self.look_back_every_hours.map_or(24, NonZeroU32::get)
    }

    /// The threads to match on.
    pub fn threads(&self) -> NonZeroUsize {
        self.threads.unwrap_or_else(every_core)
    }
}

/// One source of context: an export of the site, and how it is read.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConfig {
    /// The YAML file that says how the export is read: which of its
    /// columns are identifiers, typed fields, and labels.
    pub definition: PathBuf,
    /// The export, read at start and again whenever it changes. Whatever
    /// puts it there writes it under another name and renames it, so that
    /// it is never read half written.
    pub file: PathBuf,
}

/// One feed: how it is read, and where its publication is.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig {
    /// The feed's definition: the name of a shipped one, such as `urlhaus`,
    /// or the path of a YAML file.
    pub definition: String,
    /// The file the feed's publication is kept in, read at start and again
    /// whenever it changes. With a file and no `url`, nothing is fetched:
    /// whatever puts the file there writes it under another name and
    /// renames it, so that it is never read half written. Without a file,
    /// the publication is fetched and kept in the indicator store's
    /// directory.
    pub file: Option<PathBuf>,
    /// Where the publication is fetched from, every `refresh_minutes` of
    /// the definition; the definition's own `url` if left out. HTTPS, or
    /// HTTP on this host alone.
    pub url: Option<String>,
}

impl FeedConfig {
    /// The feed's definition, loaded.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if the definition cannot be read or
    /// used.
    pub fn feed(&self) -> Result<goliath_intel::Feed, RunError> {
        let shipped = goliath_intel::FEEDS
            .iter()
            .find(|(name, _)| *name == self.definition);
        let yaml = match shipped {
            Some((_, yaml)) => (*yaml).to_owned(),
            None => std::fs::read_to_string(&self.definition)
                .map_err(|error| RunError::Config(format!("{}: {error}", self.definition)))?,
        };
        goliath_intel::Feed::from_yaml(&yaml)
            .map_err(|error| RunError::Config(format!("{}: {error}", self.definition)))
    }

    /// Where the publication is fetched from, if it is fetched: the
    /// configured `url`, or the definition's when no `file` is given.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if there is neither a file nor a URL,
    /// or the URL is not one a feed may be fetched from.
    pub fn fetched_from(&self, feed: &goliath_intel::Feed) -> Result<Option<String>, RunError> {
        let url = match (&self.url, &self.file) {
            (Some(url), _) => url.clone(),
            (None, Some(_)) => return Ok(None),
            (None, None) => feed.url.clone().ok_or_else(|| {
                RunError::Config(format!(
                    "feed `{}` needs a `file` or a `url`: its definition names no URL",
                    feed.name
                ))
            })?,
        };
        crate::fetch::check_url(&url)
            .map_err(|why| RunError::Config(format!("feed `{}`: {why}", feed.name)))?;
        Ok(Some(url))
    }
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
    /// Threads that decode received outcomes into rows at once; every core
    /// by default.
    #[serde(default)]
    pub threads: Option<NonZeroUsize>,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            max_rows: default_max_rows(),
            max_delay_ms: default_max_delay_ms(),
            threads: None,
        }
    }
}

impl WriterConfig {
    /// The delay as a duration.
    pub fn max_delay(&self) -> Duration {
        Duration::from_millis(self.max_delay_ms)
    }

    /// The threads to decode on.
    pub fn threads(&self) -> NonZeroUsize {
        self.threads.unwrap_or_else(every_core)
    }
}

fn default_prefix() -> String {
    "goliath-".to_owned()
}

fn default_replication() -> i32 {
    3
}

/// The machine's cores, or one if they cannot be told.
fn every_core() -> NonZeroUsize {
    std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
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
            config.api.token_file.as_mut(),
            config.api.ui.as_mut(),
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
        if let Some(tls) = &mut config.receiver.tls {
            tls.certificate = base.join(&tls.certificate);
            tls.key = base.join(&tls.key);
        }
        for source in &mut config.sources {
            if let Some(inbox) = &mut source.inbox {
                *inbox = base.join(&*inbox);
            }
            if let Some(http) = &mut source.http {
                http.token_file = base.join(&http.token_file);
            }
            if let Some(tls) = source
                .syslog
                .as_mut()
                .and_then(|syslog| syslog.tls.as_mut())
            {
                tls.certificate = base.join(&tls.certificate);
                tls.key = base.join(&tls.key);
            }
            if !is_builtin(&source.definition) {
                source.definition = base.join(&source.definition).to_string_lossy().into_owned();
            }
        }
        if let Some(detector) = &mut config.detector {
            if let Some(state) = &mut detector.state {
                *state = base.join(&*state);
            }
            for list in &mut detector.allowlists {
                *list = base.join(&*list);
            }
            for source in &mut detector.context {
                source.definition = base.join(&source.definition);
                source.file = base.join(&source.file);
            }
            for feed in &mut detector.feeds {
                if let Some(file) = &mut feed.file {
                    *file = base.join(&*file);
                }
                let shipped = goliath_intel::FEEDS
                    .iter()
                    .any(|(name, _)| *name == feed.definition);
                if !shipped {
                    feed.definition = base.join(&feed.definition).to_string_lossy().into_owned();
                }
            }
        }
        config.check()?;
        Ok(config)
    }

    /// Whether this process runs a role that moves records through topics.
    pub fn has_pipeline(&self) -> bool {
        self.roles.iter().any(|role| {
            matches!(
                role,
                Role::Collector | Role::Normalizer | Role::Writer | Role::Receiver | Role::Detector
            )
        })
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
        if self.roles.contains(&Role::Receiver) {
            self.check_receiver()?;
        }
        if self.roles.contains(&Role::Detector) {
            self.check_detector()?;
        }
        match &self.kafka {
            None if self.data.is_none() && self.has_pipeline() => {
                return Err(RunError::Config(
                    "set `data` for topics on disk, or a [kafka] section".to_owned(),
                ));
            }
            None => {}
            Some(kafka) => kafka.check()?,
        }
        if (self.roles.contains(&Role::Writer) || self.roles.contains(&Role::Api))
            && self.store.is_none()
        {
            return Err(RunError::Config(
                "the writer and api roles need a [store] section".to_owned(),
            ));
        }
        if self.roles.contains(&Role::Api)
            && !self.api.listen.ip().is_loopback()
            && self.api.token_file.is_none()
        {
            return Err(RunError::Config(format!(
                "the API listens on {}, beyond this host, so [api] needs a token_file",
                self.api.listen
            )));
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

    /// Checks the detector: feeds to match, each definition loading and
    /// named once, and a place for the indicator store.
    fn check_detector(&self) -> Result<(), RunError> {
        let Some(detector) = &self.detector else {
            return Err(RunError::Config(
                "the detector role needs a [detector] section".to_owned(),
            ));
        };
        if detector.feeds.is_empty() {
            return Err(RunError::Config(
                "the detector role needs a feed: [[detector.feeds]] with a `definition`".to_owned(),
            ));
        }
        let mut names = BTreeSet::new();
        for feed in &detector.feeds {
            let definition = feed.feed()?;
            feed.fetched_from(&definition)?;
            let name = definition.name;
            if !names.insert(name.clone()) {
                return Err(RunError::Config(format!(
                    "feed `{name}` is configured twice"
                )));
            }
        }
        if detector.state.is_none() && self.data.is_none() {
            return Err(RunError::Config(
                "set `state` in [detector], or `data`, for the indicator store".to_owned(),
            ));
        }
        Ok(())
    }

    /// The directory of the detector's indicator store.
    pub fn detector_state(&self) -> Option<PathBuf> {
        let detector = self.detector.as_ref()?;
        detector
            .state
            .clone()
            .or_else(|| self.data.as_ref().map(|data| data.join("intel")))
    }

    /// Checks the receiver: something to receive, tokens that each name one
    /// source, an address for each listener, and TLS for any beyond
    /// loopback.
    fn check_receiver(&self) -> Result<(), RunError> {
        let exposed = |listen: SocketAddr, tls: bool, what: &str| {
            if listen.ip().is_loopback() || tls {
                Ok(())
            } else {
                Err(RunError::Config(format!(
                    "{what} listens on {listen}, beyond this host, so it needs `tls = {{ certificate = ..., key = ... }}`"
                )))
            }
        };
        let mut tokens = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for source in &self.sources {
            if let Some(http) = &source.http
                && !tokens.insert(http.token()?)
            {
                return Err(RunError::Config(
                    "two sources share a token; each needs its own, so that a token writes to one source only"
                        .to_owned(),
                ));
            }
            if let Some(syslog) = &source.syslog {
                let what = format!("the syslog listener of `{}`", source.definition);
                exposed(syslog.listen, syslog.tls.is_some(), &what)?;
                if !addresses.insert(syslog.listen) {
                    return Err(RunError::Config(format!(
                        "two syslog listeners share {}; syslog names no source, so each source needs its own port",
                        syslog.listen
                    )));
                }
            }
        }
        if tokens.is_empty() && addresses.is_empty() {
            return Err(RunError::Config(
                "the receiver role needs a source with `http = { token_file = ... }` or `syslog = { listen = ... }`"
                    .to_owned(),
            ));
        }
        if !tokens.is_empty() {
            exposed(
                self.receiver.listen,
                self.receiver.tls.is_some(),
                "[receiver]",
            )?;
            if addresses.contains(&self.receiver.listen) {
                return Err(RunError::Config(format!(
                    "a syslog listener and [receiver] share {}",
                    self.receiver.listen
                )));
            }
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

impl Config {
    /// The configured sources, by the name their definitions give them, and
    /// how long each may send nothing, for source health.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::Config`] if a definition cannot be read or does
    /// not load.
    pub fn watched(&self) -> Result<Vec<goliath_store::Watched>, RunError> {
        self.sources
            .iter()
            .map(|source| {
                Ok(goliath_store::Watched {
                    source: source.normalizer()?.name().to_owned(),
                    silent_after_minutes: source
                        .silent_after_minutes
                        .map_or(goliath_store::DEFAULT_SILENT_AFTER_MINUTES, NonZeroU32::get),
                })
            })
            .collect()
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

    const API: &str = r#"
roles = ["api"]

[store]
url = "http://localhost:8123"
database = "goliath"
"#;

    #[test]
    fn the_api_alone_needs_a_store_and_no_topics() {
        let config = parse(API).unwrap();
        assert!(!config.has_pipeline());
        assert!(config.api.listen.ip().is_loopback());
        assert_eq!(config.api.max_span_days.get(), 31);
        assert!(parse("roles = [\"api\"]").is_err());
    }

    #[test]
    fn an_api_beyond_this_host_needs_a_long_token() {
        let open = format!("{API}\n[api]\nlisten = \"0.0.0.0:8080\"\n");
        let error = parse(&open).unwrap_err().to_string();
        assert!(error.contains("needs a token_file"), "{error}");

        let directory = std::env::temp_dir().join(format!("goliath-api-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("token");
        let with_token = format!("{open}token_file = {file:?}\n");
        std::fs::write(&file, "short\n").unwrap();
        let config = parse(&with_token).unwrap();
        assert!(config.api.token().is_err());
        std::fs::write(&file, format!("{}\n", "a".repeat(64))).unwrap();
        assert_eq!(config.api.token().unwrap(), Some("a".repeat(64)));
        std::fs::remove_dir_all(directory).unwrap();
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

    #[test]
    fn a_receiver_needs_a_source_distinct_tokens_and_tls_beyond_loopback() {
        let directory =
            std::env::temp_dir().join(format!("goliath-receiver-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let (one, two, short) = (
            directory.join("one"),
            directory.join("two"),
            directory.join("short"),
        );
        std::fs::write(&one, "a".repeat(32)).unwrap();
        std::fs::write(&two, "b".repeat(32)).unwrap();
        std::fs::write(&short, "c".repeat(31)).unwrap();
        let config = |falco: &Path, auditd: &Path, listen: &str| {
            format!(
                r#"
roles = ["receiver", "normalizer"]
data = "data"

[receiver]
listen = "{listen}"

[[sources]]
definition = "falco"
http = {{ token_file = '{}' }}

[[sources]]
definition = "auditd"
http = {{ token_file = '{}' }}
"#,
                falco.display(),
                auditd.display()
            )
        };

        let loaded = parse(&config(&one, &two, "127.0.0.1:8514")).unwrap();
        assert!(loaded.has_pipeline());
        assert_eq!(
            loaded.sources[0].http.as_ref().unwrap().token().unwrap(),
            "a".repeat(32)
        );

        let shared = parse(&config(&one, &one, "127.0.0.1:8514"))
            .unwrap_err()
            .to_string();
        assert!(shared.contains("share a token"), "{shared}");
        let weak = parse(&config(&one, &short, "127.0.0.1:8514"))
            .unwrap_err()
            .to_string();
        assert!(weak.contains("at least 32 bytes"), "{weak}");
        let exposed = parse(&config(&one, &two, "0.0.0.0:8514"))
            .unwrap_err()
            .to_string();
        assert!(exposed.contains("needs `tls"), "{exposed}");
        let served = parse(&config(&one, &two, "0.0.0.0:8514").replace(
            "[receiver]",
            "[receiver]\ntls = { certificate = 'cert.pem', key = 'key.pem' }",
        ))
        .unwrap();
        assert!(served.receiver.tls.unwrap().key.ends_with("key.pem"));
        let nothing = parse(
            "roles = [\"receiver\"]
data = \"data\"
",
        )
        .unwrap_err()
        .to_string();
        assert!(nothing.contains("needs a source"), "{nothing}");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_syslog_listener_needs_a_port_of_its_own_and_tls_beyond_loopback() {
        let config = |first: &str, second: &str| {
            format!(
                r#"
roles = ["receiver", "normalizer"]
data = "data"

[[sources]]
definition = "falco"
syslog = {{ {first} }}

[[sources]]
definition = "auditd"
syslog = {{ {second} }}
"#
            )
        };
        let loaded = parse(&config(
            "listen = '127.0.0.1:6514'",
            "listen = '0.0.0.0:6515', tls = { certificate = 'c.pem', key = 'k.pem' }",
        ))
        .unwrap();
        assert!(loaded.has_pipeline());
        let tls = loaded.sources[1]
            .syslog
            .as_ref()
            .unwrap()
            .tls
            .as_ref()
            .unwrap();
        assert!(tls.certificate.ends_with("c.pem"));

        let shared = parse(&config(
            "listen = '127.0.0.1:6514'",
            "listen = '127.0.0.1:6514'",
        ))
        .unwrap_err()
        .to_string();
        assert!(shared.contains("its own port"), "{shared}");
        let exposed = parse(&config(
            "listen = '127.0.0.1:6514'",
            "listen = '0.0.0.0:6515'",
        ))
        .unwrap_err()
        .to_string();
        assert!(exposed.contains("needs `tls"), "{exposed}");
    }
}
