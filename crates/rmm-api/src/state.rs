//! Shared application state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::PgPool;

use crate::auth::Authenticator;

/// Compiled-in trust roots used to verify uploaded trust artifacts.
#[derive(Debug, Clone, Default)]
pub struct TrustRoots {
    /// Root public keys (32-byte Ed25519).
    pub keys: Vec<[u8; 32]>,
    /// Number of root signatures required (0 never verifies anything).
    pub threshold: u8,
}

impl TrustRoots {
    /// Parse a comma-separated list of hex public keys.
    pub fn parse(keys_hex: &str, threshold: u8) -> Result<Self, String> {
        let mut keys = Vec::new();
        for part in keys_hex.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let raw = data_encoding::HEXLOWER_PERMISSIVE
                .decode(part.as_bytes())
                .map_err(|e| format!("bad root public key hex: {e}"))?;
            let key = <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| "root public key must be 32 bytes".to_string())?;
            keys.push(key);
        }
        Ok(Self { keys, threshold })
    }
}

/// Fixed-window per-key request limiter.
#[derive(Debug)]
pub struct IpLimiter {
    limit: usize,
    window: Duration,
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl IpLimiter {
    /// A limiter allowing `limit` hits per `window` for each key.
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Record a hit; false when the key is over its limit.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let Ok(mut map) = self.hits.lock() else {
            return false;
        };
        if map.len() > 10_000 {
            map.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < self.window));
        }
        let entry = map.entry(key.to_owned()).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() >= self.limit {
            return false;
        }
        entry.push(now);
        true
    }
}

/// State handed to every handler.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Database pool, connected as the `rmm_api` role.
    pub pool: PgPool,
    /// Technician JWT validation.
    pub authenticator: Authenticator,
    /// NATS client (user `api`), when configured.
    pub nats: Option<async_nats::Client>,
    /// Trust roots for artifact upload.
    pub roots: TrustRoots,
    /// NATS URL handed to enrolled agents.
    pub nats_public_url: String,
    /// Per-IP limiter for `/v1/enroll` (10 per minute).
    pub(crate) enroll_limiter: Arc<IpLimiter>,
}

impl AppState {
    /// Build the state with the default enrollment rate limit.
    pub fn new(
        pool: PgPool,
        authenticator: Authenticator,
        nats: Option<async_nats::Client>,
        roots: TrustRoots,
        nats_public_url: String,
    ) -> Self {
        Self {
            pool,
            authenticator,
            nats,
            roots,
            nats_public_url,
            enroll_limiter: Arc::new(IpLimiter::new(10, Duration::from_secs(60))),
        }
    }
}
