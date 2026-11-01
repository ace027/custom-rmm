//! Endpoint agent binary: `enroll` once, then `run`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rmm_agent_core::blocks::PlatformBlocks;
use rmm_agent_core::commands::{self, Agent, IntakeOptions};
use rmm_agent_core::enroll::{self, EnrollError, EnrollOptions};
use rmm_agent_core::identity;
use rmm_agent_core::shell::{Indicator, SessionConfig, ShellLink, ShellManager};
use rmm_agent_core::store::{STORE_KEY_FILE, Store};
use rmm_agent_core::telemetry::{self as agent_telemetry, CancellationToken, Intervals};
use rmm_agent_core::transport::{self, ConnState};
use rmm_platform::indicator::IndicatorServer;
use tokio::sync::Notify;

const EXIT_FAILURE: u8 = 1;
const EXIT_ALREADY_ENROLLED: u8 = 2;
const EXIT_TOKEN_REJECTED: u8 = 3;
const EXIT_UNREACHABLE: u8 = 4;

#[derive(Debug, Parser)]
#[command(name = "rmm-agent", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enroll this machine with the server.
    Enroll {
        /// Server base URL, e.g. https://rmm.example.com
        #[arg(long)]
        server: String,
        /// One-time enrollment token (rmmenr_...).
        #[arg(long)]
        token: String,
        /// State directory (default: platform specific).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Replace an existing enrollment.
        #[arg(long)]
        force: bool,
    },
    /// Connect to the server and stay connected.
    Run {
        /// State directory (default: platform specific).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Exit 0 after the first successful connect.
        #[arg(long)]
        once: bool,
    },
}

/// Extra CA for dev servers; honoured in debug builds only.
fn extra_ca() -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        std::env::var_os("RMM_AGENT_EXTRA_CA").map(PathBuf::from)
    } else {
        None
    }
}

async fn do_enroll(server: String, token: String, state_dir: Option<PathBuf>, force: bool) -> u8 {
    let dir = state_dir.unwrap_or_else(rmm_platform::default_state_dir);
    let http = match enroll::http_client(extra_ca().as_deref()) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("{e}");
            return EXIT_FAILURE;
        }
    };
    if !enroll::compiled_roots_configured() {
        tracing::warn!("no root keys compiled in (dev build): trust bundle is not verified");
    }
    let keystore = rmm_platform::keystore(&dir);
    let platform = rmm_platform::current();
    let mut opts = EnrollOptions::new(dir);
    opts.force = force;
    match enroll::enroll(&server, &token, keystore.as_ref(), &platform, http, &opts).await {
        Ok(done) => {
            println!(
                "enrolled: agent_id={} status={}",
                done.identity.agent_id, done.status
            );
            0
        }
        Err(e) => {
            tracing::error!("{e}");
            match e {
                EnrollError::AlreadyEnrolled => EXIT_ALREADY_ENROLLED,
                EnrollError::TokenRejected => EXIT_TOKEN_REJECTED,
                EnrollError::Unreachable(_) => EXIT_UNREACHABLE,
                _ => EXIT_FAILURE,
            }
        }
    }
}

/// Resolves on SIGINT, or SIGTERM on Unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn run(state_dir: Option<PathBuf>, once: bool) -> u8 {
    let dir = state_dir.unwrap_or_else(rmm_platform::default_state_dir);
    let ident = match identity::load(&dir) {
        Ok(Some(i)) => i,
        Ok(None) => {
            tracing::error!("not enrolled: run `rmm-agent enroll` first");
            return EXIT_FAILURE;
        }
        Err(e) => {
            tracing::error!("load identity: {e}");
            return EXIT_FAILURE;
        }
    };
    let mut seed = match rmm_platform::keystore(&dir).load() {
        Ok(Some(s)) => s,
        Ok(None) => {
            tracing::error!("device key missing: re-enroll with --force");
            return EXIT_FAILURE;
        }
        Err(e) => {
            tracing::error!("load device key: {e}");
            return EXIT_FAILURE;
        }
    };
    let store = if once {
        None
    } else {
        let key = rmm_platform::keystore_named(&dir, STORE_KEY_FILE);
        match Store::open(&dir, key.as_ref()) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                tracing::error!("open local store: {e}");
                return EXIT_FAILURE;
            }
        }
    };
    // The result signer keeps its own (zeroizing) copy of the seed.
    let agent = match &store {
        Some(_) => match Agent::from_identity(&ident, seed) {
            Ok(a) => Some(Arc::new(a)),
            Err(e) => {
                tracing::error!("command trust roots: {e}");
                return EXIT_FAILURE;
            }
        },
        None => None,
    };
    let reconnect = Arc::new(Notify::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let ca = extra_ca();
    let client = transport::connect_observed(&ident, &seed, ca.as_deref(), tx).await;
    seed.fill(0);
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("{e}");
            return EXIT_FAILURE;
        }
    };
    tracing::info!(agent_id = %ident.agent_id, url = %ident.nats_url, "connecting");
    let shutdown = CancellationToken::new();
    // Results share the telemetry outbox; `reconnect` doubles as the drain
    // task's wake-up so a queued result is sent at once.
    let intake_task = store.clone().zip(agent).map(|(store, agent)| {
        let client = client.clone();
        let ident = ident.clone();
        let shell = shell_manager(&agent.agent_id, &client);
        let opts = IntakeOptions {
            agent,
            blocks: Arc::new(PlatformBlocks::for_agent(&dir)),
            outbox_wake: Arc::clone(&reconnect),
            shutdown: shutdown.clone(),
        };
        tokio::spawn(async move {
            commands::intake_with(client, &ident, store, opts, Some(shell)).await;
        })
    });
    let telemetry_task = store.map(|store| {
        let client = client.clone();
        let ident = ident.clone();
        let token = shutdown.clone();
        let reconnect = Arc::clone(&reconnect);
        tokio::spawn(async move {
            let platform = rmm_platform::current();
            if let Err(e) = agent_telemetry::run_telemetry(
                client,
                &ident,
                platform,
                Intervals::from_env_debug(),
                store,
                reconnect,
                token,
            )
            .await
            {
                tracing::error!("telemetry stopped: {e}");
            }
        })
    });
    let code = loop {
        tokio::select! {
            state = rx.recv() => match state {
                Some(ConnState::Connected) => {
                    tracing::info!("nats connected");
                    reconnect.notify_one();
                    if once {
                        break 0;
                    }
                }
                Some(ConnState::Disconnected) => tracing::warn!("nats disconnected, retrying"),
                Some(ConnState::Closed) | None => {
                    tracing::error!("nats connection closed");
                    break EXIT_FAILURE;
                }
            },
            () = shutdown_signal() => {
                tracing::info!("shutting down");
                break 0;
            }
        }
    };
    shutdown.cancel();
    if let Some(task) = intake_task {
        let _ = task.await;
    }
    if let Some(task) = telemetry_task {
        let _ = task.await;
    }
    code
}

/// The shell session manager over the agent's NATS connection, with the
/// session indicator (socket from `RMM_INDICATOR_SOCKET` or the platform
/// default). Shells still run when the indicator cannot start.
fn shell_manager<L: ShellLink + Clone + 'static>(agent_id: &str, client: &L) -> ShellManager {
    let indicator: Option<Arc<dyn Indicator>> = match IndicatorServer::start(None) {
        Ok(s) => {
            tracing::info!(path = ?s.path(), "session indicator listening");
            Some(Arc::new(s))
        }
        Err(e) => {
            tracing::warn!("session indicator unavailable: {e}");
            None
        }
    };
    let link: Arc<dyn ShellLink> = Arc::new(client.clone());
    ShellManager::new(agent_id, link, indicator, SessionConfig::default())
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let code = match cli.command {
        Some(Command::Enroll {
            server,
            token,
            state_dir,
            force,
        }) => do_enroll(server, token, state_dir, force).await,
        Some(Command::Run { state_dir, once }) => run(state_dir, once).await,
        None => {
            println!("rmm-agent: {}", rmm_agent_core::identity());
            0
        }
    };
    ExitCode::from(code)
}
