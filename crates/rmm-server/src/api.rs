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

    Ok(rmm_api::router(AppState::new(
        pool,
        authenticator,
        nats,
        roots,
        nats_public_url,
    )))
}
