//! Server binary: api, ingest, authd and migrate run as separate processes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use utoipa::OpenApi;

mod api;
mod dev_token;

/// RMM server.
#[derive(Debug, Parser)]
#[command(name = "rmm-server", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum Command {
    /// Run the HTTP API.
    Api,
    /// Run the telemetry ingest process.
    Ingest,
    /// Run the NATS auth callout service.
    Authd,
    /// Apply database migrations.
    Migrate,
    /// Print the OpenAPI document as pretty JSON.
    Openapi,
    /// Print a development JWT (needs RMM_AUTH_DEV_KEY_FILE and RMM_ENTRA_AUDIENCE).
    DevToken {
        /// App role to grant.
        #[arg(long, default_value = "RMM.Admin")]
        role: String,
        /// Token subject.
        #[arg(long, default_value = "dev-admin")]
        sub: String,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },
    /// Probe an http:// URL and exit non-zero unless it answers 2xx.
    Healthcheck {
        /// URL to probe, e.g. http://127.0.0.1:8080/healthz
        url: String,
    },
}

/// Plain HTTP/1.1 GET with a 3 second budget; `Ok` only for a 2xx status.
async fn healthcheck(url: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), probe(url))
        .await
        .context("healthcheck timed out")?
}

async fn probe(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("http://")
        .context("only http:// URLs are supported")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let mut stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect {addr}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    (&mut stream).take(64).read_to_end(&mut head).await?;
    let head = String::from_utf8_lossy(&head);
    let line = head.lines().next().unwrap_or("");
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    match status {
        Some(code) if (200..300).contains(&code) => Ok(()),
        _ => bail!(
            "unhealthy: {}",
            if line.is_empty() { "no response" } else { line }
        ),
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutdown signal received");
}

async fn serve(addr: &str, app: Router) -> Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("bad listen address {addr}"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Health state shared with the NATS watcher.
type Connected = Arc<AtomicBool>;

async fn health_handler(State(connected): State<Connected>) -> StatusCode {
    if connected.load(Ordering::Relaxed) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn health_router(connected: Connected) -> Router {
    Router::new()
        .route("/healthz", get(health_handler))
        .with_state(connected)
}

/// Connect to NATS (retrying with backoff in the background) and serve /healthz.
async fn run_nats_service(name: &'static str, default_listen: &str) -> Result<()> {
    let url = env_required("RMM_NATS_URL")?;
    let user = env_required("RMM_NATS_USER")?;
    let password = env_required("RMM_NATS_PASSWORD")?;
    let listen = env_or("RMM_HEALTH_LISTEN", default_listen);
    let connected: Connected = Arc::new(AtomicBool::new(false));

    let watcher_state = connected.clone();
    let watcher = tokio::spawn(async move {
        let mut backoff = Duration::from_millis(500);
        let client = loop {
            let attempt =
                async_nats::ConnectOptions::with_user_and_password(user.clone(), password.clone())
                    .name(name)
                    .retry_on_initial_connect()
                    .connect(&url)
                    .await;
            match attempt {
                Ok(c) => break c,
                Err(err) => {
                    tracing::warn!(%err, "nats connect failed, retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(10));
                }
            }
        };
        loop {
            let up = client.connection_state() == async_nats::connection::State::Connected;
            if watcher_state.swap(up, Ordering::Relaxed) != up {
                tracing::info!(connected = up, "nats connection state changed");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let result = serve(&listen, health_router(connected)).await;
    watcher.abort();
    result
}

async fn run_migrate() -> Result<()> {
    let url = env_required("RMM_DATABASE_URL")?;
    let pool = rmm_db::connect(&url).await.context("connect database")?;
    rmm_db::migrate(&pool).await.context("run migrations")?;
    let one = rmm_db::ping(&pool).await.context("ping database")?;
    tracing::info!(ping = one, "migrations applied");
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if std::env::var("RMM_LOG_FORMAT").as_deref() == Ok("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    match Cli::parse().command {
        Command::Openapi => {
            let json = rmm_api::ApiDoc::openapi().to_pretty_json()?;
            println!("{json}");
        }
        Command::Healthcheck { url } => {
            if let Err(err) = healthcheck(&url).await {
                eprintln!("{err:#}");
                std::process::exit(1);
            }
        }
        Command::DevToken { role, sub, ttl } => {
            println!("{}", dev_token::run(&role, &sub, ttl)?);
        }
        Command::Api => {
            let app = api::build_router().await?;
            serve(&env_or("RMM_API_LISTEN", "0.0.0.0:8080"), app).await?;
        }
        Command::Ingest => run_nats_service("rmm-ingest", "0.0.0.0:8081").await?,
        Command::Authd => run_nats_service("rmm-authd", "0.0.0.0:8082").await?,
        Command::Migrate => run_migrate().await?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn parses_subcommands() {
        for (arg, want) in [
            ("api", Command::Api),
            ("ingest", Command::Ingest),
            ("authd", Command::Authd),
            ("migrate", Command::Migrate),
            ("openapi", Command::Openapi),
        ] {
            assert_eq!(
                Cli::try_parse_from(["rmm-server", arg]).expect(arg).command,
                want
            );
        }
        let cli = Cli::try_parse_from(["rmm-server", "dev-token", "--role", "X", "--ttl", "60"])
            .expect("dev-token");
        assert_eq!(
            cli.command,
            Command::DevToken {
                role: "X".to_string(),
                sub: "dev-admin".to_string(),
                ttl: 60
            }
        );
        let cli = Cli::try_parse_from(["rmm-server", "healthcheck", "http://x/y"]).expect("hc");
        assert_eq!(
            cli.command,
            Command::Healthcheck {
                url: "http://x/y".to_string()
            }
        );
    }

    async fn status_of(connected: bool) -> StatusCode {
        let state: Connected = Arc::new(AtomicBool::new(connected));
        health_router(state)
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
            .status()
    }

    #[tokio::test]
    async fn health_handler_follows_state() {
        assert_eq!(status_of(false).await, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(true).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn healthcheck_against_local_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let ok = Arc::new(AtomicBool::new(true));
        let app = health_router(ok.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        let url = format!("http://{addr}/healthz");
        healthcheck(&url).await.expect("2xx");
        ok.store(false, Ordering::Relaxed);
        assert!(healthcheck(&url).await.is_err());
        assert!(healthcheck("https://x/").await.is_err());
    }
}
