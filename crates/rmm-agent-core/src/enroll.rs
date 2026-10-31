//! Enrollment client: generate the device key, prove possession of it to the
//! server with a one-time token, and persist the identity and trust bundle.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand::TryRng;
use rmm_platform::{KeyStore, Platform};
use rmm_proto::enroll::{EnrollRequest, EnrollResponse, TrustBundle};
use rmm_trust::keys::PublicKey;
use rmm_trust::store::{Clock, DocKind, SeqStore, TrustStore};

use crate::identity::{self, Identity};

/// Comma-separated hex Ed25519 root public keys compiled into the agent.
const ROOT_PUBKEYS: Option<&str> = option_env!("RMM_ROOT_PUBKEYS");
/// Root signature threshold used before the first manifest is installed.
const ROOT_THRESHOLD: Option<&str> = option_env!("RMM_ROOT_THRESHOLD");

// Release builds must carry the root keys; only debug builds may go without.
#[cfg(not(debug_assertions))]
const _: () = assert!(
    ROOT_PUBKEYS.is_some(),
    "RMM_ROOT_PUBKEYS must be set when building a release agent"
);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Retry policy for connect failures.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    /// Total attempts, including the first.
    pub attempts: u32,
    /// Delay before the second attempt; doubles each time.
    pub base_delay: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            attempts: 3,
            base_delay: Duration::from_secs(1),
        }
    }
}

/// Inputs of [`enroll`] that are not the token or the server.
#[derive(Debug, Clone)]
pub struct EnrollOptions {
    /// Directory where identity and trust files are stored.
    pub state_dir: PathBuf,
    /// Replace an existing enrollment.
    pub force: bool,
    /// Connect retry policy.
    pub retry: Retry,
}

impl EnrollOptions {
    /// Options with default retries and no force.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            force: false,
            retry: Retry::default(),
        }
    }
}

/// Result of a successful enrollment.
#[derive(Debug, Clone)]
pub struct Enrolled {
    /// The stored identity.
    pub identity: Identity,
    /// Device status reported by the server, e.g. `active`.
    pub status: String,
}

/// Why enrollment failed.
#[derive(Debug)]
pub enum EnrollError {
    /// An identity or key already exists and `force` was not set.
    AlreadyEnrolled,
    /// The server answered 401.
    TokenRejected,
    /// The server could not be reached after all attempts.
    Unreachable(String),
    /// The server answered with another error status.
    Server(u16),
    /// The server reply was malformed.
    BadResponse(String),
    /// The server URL is unusable.
    BadUrl(String),
    /// The trust bundle did not verify.
    Trust(String),
    /// Key store, platform or file system failure.
    Local(String),
}

impl fmt::Display for EnrollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyEnrolled => write!(f, "already enrolled (use --force to replace)"),
            Self::TokenRejected => write!(f, "enrollment token rejected"),
            Self::Unreachable(e) => write!(f, "server unreachable: {e}"),
            Self::Server(s) => write!(f, "server returned status {s}"),
            Self::BadResponse(e) => write!(f, "invalid server response: {e}"),
            Self::BadUrl(e) => write!(f, "invalid server url: {e}"),
            Self::Trust(e) => write!(f, "trust bundle rejected: {e}"),
            Self::Local(e) => write!(f, "local error: {e}"),
        }
    }
}

impl std::error::Error for EnrollError {}

/// HTTP client for enrollment, optionally trusting an extra CA (dev servers).
pub fn http_client(extra_ca: Option<&Path>) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder();
    if let Some(path) = extra_ca {
        let pem = std::fs::read(path).map_err(|e| format!("read extra CA: {e}"))?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| format!("extra CA: {e}"))?;
        b = b.add_root_certificate(cert);
    }
    b.build().map_err(|e| format!("http client: {e}"))
}

/// Whether root keys were compiled in (false only in dev builds).
pub fn compiled_roots_configured() -> bool {
    ROOT_PUBKEYS.is_some_and(|s| !s.trim().is_empty())
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

fn compiled_roots() -> Result<(Vec<PublicKey>, u8), EnrollError> {
    let mut keys = Vec::new();
    for part in ROOT_PUBKEYS
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let raw = parse_hex32(part)
            .ok_or_else(|| EnrollError::Trust("compiled root key is not 32 hex bytes".into()))?;
        keys.push(
            PublicKey::from_bytes(&raw)
                .map_err(|e| EnrollError::Trust(format!("compiled root key: {e}")))?,
        );
    }
    let default = u8::try_from(keys.len()).unwrap_or(u8::MAX);
    let threshold = match ROOT_THRESHOLD {
        Some(t) => t
            .trim()
            .parse::<u8>()
            .map_err(|_| EnrollError::Trust("RMM_ROOT_THRESHOLD is not a number".into()))?,
        None => default,
    };
    Ok((keys, threshold))
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        now_secs()
    }
}

#[derive(Default)]
struct MemSeq(BTreeMap<DocKind, (u64, [u8; 32])>);

impl SeqStore for MemSeq {
    fn get(&self, kind: DocKind) -> Option<(u64, [u8; 32])> {
        self.0.get(&kind).copied()
    }
    fn put(&mut self, kind: DocKind, seq: u64, content_id: [u8; 32]) {
        self.0.insert(kind, (seq, content_id));
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Verify the bundle against the compiled-in roots. An empty bundle carries
/// nothing to verify; a non-empty one needs configured roots (fail closed).
fn verify_bundle(bundle: &TrustBundle) -> Result<(), EnrollError> {
    if bundle.manifest.is_none() && bundle.revocations.is_none() && bundle.techlist.is_none() {
        return Ok(());
    }
    let (roots, threshold) = compiled_roots()?;
    let mut store = TrustStore::new(roots, threshold);
    let mut seq = MemSeq::default();
    let trust = |e: rmm_trust::error::TrustError| EnrollError::Trust(e.to_string());
    let Some(manifest) = &bundle.manifest else {
        return Err(EnrollError::Trust(
            "bundle has documents but no manifest".into(),
        ));
    };
    store
        .apply_manifest(manifest, &SystemClock, &mut seq)
        .map_err(trust)?;
    if let Some(r) = &bundle.revocations {
        store
            .apply_revocations(r, &SystemClock, &mut seq)
            .map_err(trust)?;
    }
    if let Some(t) = &bundle.techlist {
        store
            .apply_techlist(t, &SystemClock, &mut seq)
            .map_err(trust)?;
    }
    Ok(())
}

/// Plain http is only acceptable towards the local machine.
fn check_url(url: &str) -> Result<(), EnrollError> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        let host = if rest.starts_with('[') { "[::1]" } else { host };
        if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            return Ok(());
        }
    }
    Err(EnrollError::BadUrl("an https:// url is required".into()))
}

async fn post_with_retry(
    http: &reqwest::Client,
    url: &str,
    req: &EnrollRequest,
    retry: Retry,
) -> Result<reqwest::Response, EnrollError> {
    let attempts = retry.attempts.max(1);
    let mut delay = retry.base_delay;
    let mut last = String::new();
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2);
        }
        match http
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .json(req)
            .send()
            .await
        {
            Ok(resp) => return Ok(resp),
            // Only connect failures are retried: after a request was sent the
            // one-time token may already be spent.
            Err(e) if e.is_connect() => last = e.without_url().to_string(),
            Err(e) => return Err(EnrollError::Unreachable(e.without_url().to_string())),
        }
    }
    Err(EnrollError::Unreachable(last))
}

/// Enroll this machine and persist the identity and trust bundle in
/// `opts.state_dir`. The device key is removed again on any failure.
pub async fn enroll(
    server_url: &str,
    token: &str,
    keystore: &dyn KeyStore,
    platform: &dyn Platform,
    http: reqwest::Client,
    opts: &EnrollOptions,
) -> Result<Enrolled, EnrollError> {
    let server_url = server_url.trim_end_matches('/');
    check_url(server_url)?;
    let local = |e: &dyn fmt::Display| EnrollError::Local(e.to_string());

    let existing = identity::load(&opts.state_dir).map_err(|e| local(&e))?;
    let old_seed = keystore.load().map_err(|e| local(&e))?;
    if (existing.is_some() || old_seed.is_some()) && !opts.force {
        return Err(EnrollError::AlreadyEnrolled);
    }

    let mut seed = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| local(&e))?;
    keystore.store(&seed).map_err(|e| local(&e))?;

    let result = run_enrollment(server_url, token, &seed, platform, &http, opts).await;
    seed.fill(0);
    match result {
        Ok(done) => Ok(done),
        Err(e) => {
            // Never leave a key behind that the server does not know about;
            // with --force, put the previous one back.
            let _ = match &old_seed {
                Some(old) => keystore.store(old),
                None => keystore.delete(),
            };
            if existing.is_none() {
                identity::remove(&opts.state_dir);
            }
            Err(e)
        }
    }
}

async fn run_enrollment(
    server_url: &str,
    token: &str,
    seed: &[u8; 32],
    platform: &dyn Platform,
    http: &reqwest::Client,
    opts: &EnrollOptions,
) -> Result<Enrolled, EnrollError> {
    let key = SigningKey::from_bytes(seed);
    let (os_family, os_version) = platform.os_info();
    let mut req = EnrollRequest {
        token: token.to_owned(),
        agent_pubkey: key.verifying_key().to_bytes(),
        hw: platform.hw_facts(),
        os_family,
        os_version,
        hostname: platform
            .hostname()
            .map_err(|e| EnrollError::Local(e.to_string()))?,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        ts: now_secs(),
        proof: Vec::new(),
    };
    req.proof = key.sign(&req.signing_bytes()).to_bytes().to_vec();

    let url = format!("{server_url}/v1/enroll");
    let resp = post_with_retry(http, &url, &req, opts.retry).await?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(EnrollError::TokenRejected);
    }
    if !status.is_success() {
        return Err(EnrollError::Server(status.as_u16()));
    }
    let body: EnrollResponse = resp
        .json()
        .await
        .map_err(|e| EnrollError::BadResponse(e.without_url().to_string()))?;

    verify_bundle(&body.trust)?;

    let ident = Identity {
        agent_id: body.agent_id,
        device_id: body.device_id,
        client_id: body.client_id,
        nats_url: body.nats_url,
        server_url: server_url.to_owned(),
    };
    // The identity file is written last: it is what marks the agent enrolled.
    let dir: &Path = &opts.state_dir;
    identity::save_trust(dir, &body.trust).map_err(|e| EnrollError::Local(e.to_string()))?;
    identity::save(dir, &ident).map_err(|e| EnrollError::Local(e.to_string()))?;
    Ok(Enrolled {
        identity: ident,
        status: body.status,
    })
}
