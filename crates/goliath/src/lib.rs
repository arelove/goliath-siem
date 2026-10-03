//! The Goliath security platform as one binary.
//!
//! A process runs the roles its configuration lists
//! (`docs/adr/0006-deployment-topology.md`), connected by durable topics:
//! `raw-<source>` from the collector to the normalizer, and `normalized` from
//! the normalizer to the writer. The topics are in the data directory, for
//! roles in one process, or in Kafka, for roles in several. The `api` role
//! serves searches over the stored events, and the interface, over HTTP.

// Tests assert on outcomes; a failed assertion should abort the test.
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod api;
pub mod config;
mod detector;
mod fetch;
mod metrics;
mod otlp;
pub mod raw;
mod receiver;
mod roles;
mod syslog;
mod tls;
mod topics;

use std::future::Future;

use goliath_pipe::PipeError;
use goliath_store::{Limits, Store, StoreError};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info};

use crate::metrics::Metrics;
use crate::topics::Topics;

pub use config::{Config, Role};

/// Why the process stopped with an error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The configuration is wrong.
    #[error("configuration: {0}")]
    Config(String),
    /// A file or directory could not be used.
    #[error("{0}")]
    Io(String),
    /// A topic failed.
    #[error("pipe: {0}")]
    Pipe(#[from] PipeError),
    /// The event store failed in a way retrying does not fix.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A topic holds bytes no role wrote.
    #[error("corrupt record: {0}")]
    Corrupt(String),
    /// A role stopped unexpectedly.
    #[error("role failed: {0}")]
    Role(String),
}

/// Runs the configured roles until `shutdown` completes or a role fails,
/// then stops the others, letting each finish what it holds.
///
/// # Errors
///
/// Returns the first error of any role, or of setting them up.
pub async fn run(config: Config, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
    let (stop, stopped) = watch::channel(false);
    let mut roles = JoinSet::new();
    let metrics = Metrics::new();

    if let Some(served) = &config.metrics {
        roles.spawn(metrics::serve(
            served.listen,
            metrics.clone(),
            stopped.clone(),
        ));
    }
    if config.roles.contains(&Role::Api) {
        let settings = config
            .store
            .as_ref()
            .ok_or_else(|| RunError::Config("no [store]".to_owned()))?;
        let server = api::Server::bind(
            &config.api,
            connect(settings)?,
            config.watched()?,
            metrics.clone(),
        )
        .await?;
        roles.spawn(server.serve(stopped.clone()));
    }
    if config.has_pipeline() {
        match &config.kafka {
            #[cfg(feature = "kafka")]
            Some(kafka) => {
                let topics = topics::Kafka::new(kafka)?;
                start_pipeline(&config, &topics, &metrics, &mut roles, &stopped).await?;
            }
            #[cfg(not(feature = "kafka"))]
            Some(_) => {
                return Err(RunError::Config(
                    "this goliath was built without Kafka; build it with `--features kafka`"
                        .to_owned(),
                ));
            }
            None => {
                let data = config
                    .data
                    .clone()
                    .ok_or_else(|| RunError::Config("no `data` directory".to_owned()))?;
                let topics = topics::Disk::new(data);
                start_pipeline(&config, &topics, &metrics, &mut roles, &stopped).await?;
            }
        }
    }
    info!(roles = ?config.roles, sources = config.sources.len(), "running");

    let mut outcome = Ok(());
    tokio::select! {
        () = shutdown => info!("shutting down"),
        Some(ended) = roles.join_next() => {
            outcome = settle(ended);
            error!("a role stopped; shutting down the others");
        }
    }
    let _ = stop.send(true);
    while let Some(ended) = roles.join_next().await {
        let result = settle(ended);
        if outcome.is_ok() {
            outcome = result;
        }
    }
    outcome
}

/// Starts the collector, normalizer, and writer this process runs, over
/// `topics`.
async fn start_pipeline<T: Topics>(
    config: &Config,
    topics: &T,
    metrics: &Metrics,
    roles: &mut JoinSet<Result<(), RunError>>,
    stopped: &watch::Receiver<bool>,
) -> Result<(), RunError> {
    let outcomes = topics.open("normalized", "writer").await?;
    // What the detector finds, for the writer to store beside the events.
    let findings = topics.open("findings", "writer").await?;

    // Readers subscribe before anything is sent, so that no record is sent
    // before the group that needs it exists.
    if config.roles.contains(&Role::Writer) {
        let settings = config
            .store
            .as_ref()
            .ok_or_else(|| RunError::Config("no [store]".to_owned()))?;
        let store = connect(settings)?;
        let applied = store.migrate().await?;
        if !applied.is_empty() {
            info!(?applied, "migrations applied");
        }
        store.set_retention(settings.retention_days).await?;
        let limits = Limits {
            max_rows: config.writer.max_rows,
            max_delay: config.writer.max_delay(),
        };
        for (name, topic) in [("normalized", &outcomes), ("findings", &findings)] {
            roles.spawn(roles::write(
                store.clone(),
                limits,
                config.writer.threads(),
                name,
                topics.subscribe(topic, "writer").await?,
                metrics.clone(),
                stopped.clone(),
            ));
        }
    }
    if config.roles.contains(&Role::Detector) {
        let (Some(settings), Some(state)) = (&config.detector, config.detector_state()) else {
            return Err(RunError::Config("no [detector]".to_owned()));
        };
        let intel = detector::Intel::open(settings, &state)?;
        roles.spawn(detector::detect(
            intel.matcher(),
            settings.threads(),
            topics.subscribe(&outcomes, "detector").await?,
            T::sender(&findings),
            metrics.clone(),
            stopped.clone(),
        ));
        roles.spawn(detector::refresh(intel, metrics.clone(), stopped.clone()));
    }
    start_sources(config, topics, &outcomes, metrics, roles, stopped).await
}

/// Starts, for each source, the roles that take and normalize its records.
async fn start_sources<T: Topics>(
    config: &Config,
    topics: &T,
    outcomes: &T::Topic,
    metrics: &Metrics,
    roles: &mut JoinSet<Result<(), RunError>>,
    stopped: &watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut over_http = std::collections::BTreeMap::new();
    for source in &config.sources {
        let normalizer = source.normalizer()?;
        let raw = topics
            .open(&format!("raw-{}", normalizer.name()), "normalizer")
            .await?;
        if config.roles.contains(&Role::Normalizer) {
            let receiver = topics.subscribe(&raw, "normalizer").await?;
            roles.spawn(roles::normalize(
                normalizer.clone(),
                config.normalizer.threads(),
                receiver,
                T::sender(outcomes),
                metrics.clone(),
                stopped.clone(),
            ));
        }
        if config.roles.contains(&Role::Collector) {
            let inbox = source.inbox.clone().ok_or_else(|| {
                RunError::Config(format!("source `{}` has no inbox", normalizer.name()))
            })?;
            roles.spawn(roles::collect(
                normalizer.name().to_owned(),
                inbox,
                T::sender(&raw),
                metrics.clone(),
                stopped.clone(),
            ));
        }
        if config.roles.contains(&Role::Receiver)
            && let Some(syslog) = &source.syslog
        {
            let listener =
                listen_syslog(&normalizer, syslog, T::sender(&raw), metrics.clone()).await?;
            roles.spawn(listener.serve(stopped.clone()));
        }
        if config.roles.contains(&Role::Receiver)
            && let Some(http) = &source.http
        {
            over_http.insert(
                normalizer.name().to_owned(),
                receiver::Source {
                    token: http.token()?,
                    raw: T::sender(&raw),
                },
            );
        }
    }
    if config.roles.contains(&Role::Receiver) && !over_http.is_empty() {
        let tls = match &config.receiver.tls {
            Some(tls) => Some(tls::acceptor(tls, &[b"http/1.1"])?),
            None => None,
        };
        let server =
            receiver::Server::bind(config.receiver.listen, tls, over_http, metrics.clone()).await?;
        roles.spawn(server.serve(stopped.clone()));
    }
    Ok(())
}

/// Binds the syslog listener of the source `normalizer` reads.
async fn listen_syslog<S: goliath_pipe::Sender + Send + Sync + 'static>(
    normalizer: &goliath_normalize::Normalizer,
    syslog: &config::SyslogSourceConfig,
    raw: S,
    metrics: Metrics,
) -> Result<syslog::Listener<S>, RunError> {
    if normalizer.framing() != goliath_normalize::definition::Framing::Syslog {
        return Err(RunError::Config(format!(
            "source `{}` takes syslog, so its definition needs `framing: syslog`",
            normalizer.name()
        )));
    }
    let tls = match &syslog.tls {
        Some(tls) => Some(tls::acceptor(tls, &[])?),
        None => None,
    };
    syslog::Listener::bind(
        normalizer.name().to_owned(),
        syslog.listen,
        tls,
        raw,
        metrics,
    )
    .await
}

fn connect(settings: &config::StoreConfig) -> Result<Store, RunError> {
    let store = Store::new(&settings.url, &settings.database)?;
    Ok(match &settings.user {
        Some(user) => store.with_credentials(user, &settings.password()?),
        None => store,
    })
}

fn settle(ended: Result<Result<(), RunError>, tokio::task::JoinError>) -> Result<(), RunError> {
    match ended {
        Ok(result) => result,
        Err(error) => Err(RunError::Role(error.to_string())),
    }
}
