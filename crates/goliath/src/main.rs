//! The `goliath` command.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use goliath::Config;
use tracing_subscriber::EnvFilter;

/// The Goliath security platform.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Runs the roles a configuration lists, until interrupted.
    Run {
        /// The configuration file.
        #[arg(long, default_value = "goliath.toml")]
        config: PathBuf,
    },
    /// Checks a configuration and its source definitions, and exits.
    Check {
        /// The configuration file.
        #[arg(long, default_value = "goliath.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Check { config: path } => Config::load(&path).map(|config| {
            println!(
                "{}: valid, {} roles, {} sources",
                path.display(),
                config.roles.len(),
                config.sources.len()
            );
        }),
        Command::Run { config } => Config::load(&config).and_then(|config| {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| goliath::RunError::Io(format!("starting the runtime: {error}")))?;
            runtime.block_on(goliath::run(config, async {
                let _ = tokio::signal::ctrl_c().await;
            }))
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error);
            ExitCode::FAILURE
        }
    }
}
