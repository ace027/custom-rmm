//! The `api` subcommand: build [`rmm_api::AppState`] from the environment.

use anyhow::{Context, Result};
use axum::Router;
use rmm_api::auth::Authenticator;
use rmm_api::{AppState, TrustRoots};

/// Connect to NATS as the `api` user without blocking startup on the server.
async fn connect_nats() -> Result<Option<async_nats::Client>> {
    let Ok(url) = std::env::var("RMM_NATS_URL") else {
        tracing::warn!("RMM_NATS_URL is not set; agent revocations will not be published");
        return Ok(None);
    };
    let user = crate::env_or("RMM_NATS_USER", "api");
    let password = crate::env_required("RMM_NATS_PASSWORD")?;
    let client = async_nats::ConnectOptions::with_user_and_password(user, password)
        .name("rmm-api")
        .retry_on_initial_connect()
        .connect(&url)
        .await
        .context("nats connect")?;
    Ok(Some(client))
}

/// Build the API router with all state wired from the environment.
pub async fn build_router() -> Result<Router> {
    let url = crate::env_required("RMM_DATABASE_URL")?;
    let pool = rmm_db::scope::connect_as(&url, "rmm_api")
        .await
        .context("connect database as rmm_api")?;
    let authenticator = Authenticator::from_env().map_err(anyhow::Error::msg)?;

    let threshold: u8 = crate::env_or("RMM_ROOT_THRESHOLD", "1")
        .parse()
        .context("RMM_ROOT_THRESHOLD must be a small integer")?;
    let roots = TrustRoots::parse(&crate::env_or("RMM_ROOT_PUBKEYS", ""), threshold)
        .map_err(anyhow::Error::msg)?;
    if roots.keys.is_empty() {
        tracing::warn!("RMM_ROOT_PUBKEYS is empty; trust artifact uploads will be rejected");
    }
    let nats_public_url = crate::env_or("RMM_NATS_PUBLIC_URL", "wss://localhost/nats");
    let nats = connect_nats().await?;

    let command_key = match std::env::var("RMM_COMMAND_KEY_FILE") {
        Ok(path) => match rmm_api::load_command_key(std::path::Path::new(&path)) {
            Ok(key) => Some(key),
            Err(err) => {
                tracing::error!(%err, "command key unusable; the issue endpoint answers 503");
                None
            }
        },
        Err(_) => {
            tracing::warn!("RMM_COMMAND_KEY_FILE is not set; the issue endpoint answers 503");
            None
        }
    };

    let state = AppState::new(pool, authenticator, nats, roots, nats_public_url)
        .with_command_key(command_key);

    let retention_days: u32 = crate::env_or(
        "RMM_RECORDING_RETENTION_DAYS",
        &rmm_api::recording::DEFAULT_RETENTION_DAYS.to_string(),
    )
    .parse()
    .context("RMM_RECORDING_RETENTION_DAYS must be a number of days")?;
    anyhow::ensure!(
        retention_days >= 1,
        "RMM_RECORDING_RETENTION_DAYS must be at least 1"
    );
    tracing::info!(
        dir = %state.recording_dir.display(),
        retention_days,
        "shell recordings"
    );
    tokio::spawn(rmm_api::recording::retention_loop(
        state.clone(),
        retention_days,
    ));

    // Agents fetch the latest trust documents and release over NATS.
    tracing::info!(dir = %state.artifact_dir.display(), "release artifacts");
    rmm_api::artifacts::sweep_stale(&state.artifact_dir);
    if rmm_api::distribution::spawn(&state).is_none() {
        tracing::warn!("no NATS client; trust and release distribution is disabled");
    }

    Ok(rmm_api::router(state))
}
