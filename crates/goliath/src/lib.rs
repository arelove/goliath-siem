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
mod roles;
mod topics;

use std::future::Future;

use goliath_pipe::PipeError;
use goliath_store::{Limits, Store, StoreError};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info};

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

    if config.roles.contains(&Role::Api) {
        let settings = config
            .store
            .as_ref()
            .ok_or_else(|| RunError::Config("no [store]".to_owned()))?;
        let server = api::Server::bind(&config.api, connect(settings)?).await?;
        roles.spawn(server.serve(stopped.clone()));
    }
    if config.has_pipeline() {
        match &config.kafka {
            #[cfg(feature = "kafka")]
            Some(kafka) => {
                start_pipeline(&config, &topics::Kafka::new(kafka)?, &mut roles, &stopped).await?;
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
                start_pipeline(&config, &topics::Disk::new(data), &mut roles, &stopped).await?;
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
    roles: &mut JoinSet<Result<(), RunError>>,
    stopped: &watch::Receiver<bool>,
) -> Result<(), RunError> {
    let outcomes = topics.open("normalized", "writer").await?;

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
        roles.spawn(roles::write(
            store,
            limits,
            topics.subscribe(&outcomes, "writer").await?,
            stopped.clone(),
        ));
    }
    for source in &config.sources {
        let normalizer = source.normalizer()?;
        let raw = topics
            .open(&format!("raw-{}", normalizer.name()), "normalizer")
            .await?;
        if config.roles.contains(&Role::Normalizer) {
            let receiver = topics.subscribe(&raw, "normalizer").await?;
            roles.spawn(roles::normalize(
                normalizer.clone(),
                receiver,
                T::sender(&outcomes),
                stopped.clone(),
            ));
        }
        if config.roles.contains(&Role::Collector) {
            let inbox = source.inbox.clone().ok_or_else(|| {
                RunError::Config(format!("source `{}` has no inbox", normalizer.name()))
            })?;
            roles.spawn(roles::collect(inbox, T::sender(&raw), stopped.clone()));
        }
    }
    Ok(())
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
