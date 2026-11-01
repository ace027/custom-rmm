//! Shared application state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sqlx::PgPool;

use crate::attestation::AttestationConfig;
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

/// Read the server command key: a file holding the 32-byte Ed25519 seed as hex.
pub fn load_command_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read command key file {}: {e}", path.display()))?;
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.trim().as_bytes())
        .map_err(|e| format!("command key is not hex: {e}"))?;
    let seed = <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| "command key must be a 32-byte seed".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

/// AAGUID of the development fake authenticator (`xtask fake-authn`),
/// "rmm-dev-fake-key" in ASCII. Never a real device.
pub const DEV_AAGUID: [u8; 16] = *b"rmm-dev-fake-key";

fn load_attestation() -> Option<Arc<AttestationConfig>> {
    match AttestationConfig::from_env() {
        Ok(Some(cfg))
            if cfg.aaguids.contains(&DEV_AAGUID)
                && std::env::var("RMM_AUTH_ALLOW_DEV").as_deref() != Ok("1") =>
        {
            tracing::error!(
                "RMM_WEBAUTHN_AAGUIDS lists the development fake authenticator but \
                 RMM_AUTH_ALLOW_DEV is not set; registration is disabled"
            );
            None
        }
        Ok(Some(cfg)) => {
            tracing::info!(
                roots = cfg.roots.len(),
                aaguids = cfg.aaguids.len(),
                "WebAuthn hardware attestation configured"
            );
            Some(Arc::new(cfg))
        }
        Ok(None) => {
            tracing::warn!(
                "RMM_WEBAUTHN_ATTESTATION_ROOTS or RMM_WEBAUTHN_AAGUIDS is unset; \
                 technician credential registration is disabled"
            );
            None
        }
        Err(err) => {
            tracing::error!(%err, "WebAuthn attestation config is invalid; registration is disabled");
            None
        }
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
    /// Server command signing key (`RMM_COMMAND_KEY_FILE`); `None` makes the
    /// issue endpoint answer 503.
    pub command_key: Option<Arc<SigningKey>>,
    /// Set once the missing command key has been logged.
    pub(crate) command_key_warned: Arc<AtomicBool>,
    /// Per-IP limiter for `/v1/enroll` (10 per minute).
    pub(crate) enroll_limiter: Arc<IpLimiter>,
    /// WebAuthn attestation roots and AAGUID allowlist; `None` makes the
    /// credential registration endpoints answer 503.
    pub attestation: Option<Arc<AttestationConfig>>,
    /// Directory holding shell session recordings (`RMM_RECORDING_DIR`).
    pub recording_dir: PathBuf,
    /// Directory holding release artifacts, one file per SHA-256
    /// (`RMM_ARTIFACT_DIR`).
    pub artifact_dir: PathBuf,
}

/// Default for `RMM_RECORDING_DIR`.
pub const DEFAULT_RECORDING_DIR: &str = "/var/lib/rmm/recordings";
/// Default for `RMM_ARTIFACT_DIR`.
pub const DEFAULT_ARTIFACT_DIR: &str = "/var/lib/rmm/artifacts";

impl AppState {
    /// Build the state with the default enrollment rate limit. WebAuthn
    /// attestation settings are read from `RMM_WEBAUTHN_ATTESTATION_ROOTS` and
    /// `RMM_WEBAUTHN_AAGUIDS`; when unset or invalid, registration stays
    /// disabled (fail closed).
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
            command_key: None,
            command_key_warned: Arc::new(AtomicBool::new(false)),
            enroll_limiter: Arc::new(IpLimiter::new(10, Duration::from_secs(60))),
            attestation: load_attestation(),
            recording_dir: std::env::var_os("RMM_RECORDING_DIR")
                .filter(|v| !v.is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_RECORDING_DIR), PathBuf::from),
            artifact_dir: std::env::var_os("RMM_ARTIFACT_DIR")
                .filter(|v| !v.is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_ARTIFACT_DIR), PathBuf::from),
        }
    }

    /// Set the directory release artifacts are stored in.
    #[must_use]
    pub fn with_artifact_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.artifact_dir = dir.into();
        self
    }

    /// Set (or clear) the WebAuthn attestation configuration.
    #[must_use]
    pub fn with_attestation(mut self, cfg: Option<AttestationConfig>) -> Self {
        self.attestation = cfg.map(Arc::new);
        self
    }

    /// Set the directory recordings are written to.
    #[must_use]
    pub fn with_recording_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.recording_dir = dir.into();
        self
    }

    /// Set (or clear) the command signing key.
    #[must_use]
    pub fn with_command_key(mut self, key: Option<SigningKey>) -> Self {
        self.command_key = key.map(Arc::new);
        self
    }
}
