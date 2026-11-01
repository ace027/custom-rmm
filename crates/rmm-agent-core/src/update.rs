//! Update client: stage a verified newer release for the watchdog.
//!
//! The refresh task hands over releases that verified under the release role.
//! [`on_release`] decides whether this platform needs one (newer than the
//! running version, not known bad to the watchdog, nothing already staged),
//! downloads the artifact from the server into `<root>/pending/`, checks its
//! size and SHA-256 against the signed release and only then writes the
//! envelopes and, last, the empty `READY` file the watchdog waits for. The
//! watchdog verifies everything again on its own; this module never installs
//! anything. The download channel is untrusted: the signed hash is the anchor.
//!
//! Layout written (watchdog contract): `manifest.env`, `release.env`,
//! `artifact`, then `READY`.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rmm_trust::docs::{ReleaseLatest, ReleaseManifest, decode_doc};
use rmm_trust::store::DocKind;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::commands::{Agent, SystemClock};
use crate::refresh::{RELEASE_SUBJECT, REQUEST_TIMEOUT, verify_release_latest};
use crate::store::Store;

/// Staging directory under the watchdog root.
pub const PENDING_DIR: &str = "pending";
/// Written last; tells the watchdog the staged release is complete.
pub const READY_FILE: &str = "READY";
/// Release envelope file name.
pub const RELEASE_FILE: &str = "release.env";
/// Trust manifest envelope file name.
pub const MANIFEST_FILE: &str = "manifest.env";
/// Staged artifact file name.
pub const ARTIFACT_FILE: &str = "artifact";
/// Watchdog state file inside the root (read only here).
pub const STATE_FILE: &str = "state.json";
/// Environment variable naming the watchdog root.
pub const ROOT_ENV: &str = "RMM_WATCHDOG_ROOT";
/// Longest an artifact download may take.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Version of this build (`RMM_AGENT_VERSION` at build time, else the crate
/// version).
pub const AGENT_VERSION: &str = match option_env!("RMM_AGENT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// The NATS client type the updater fetches releases with.
pub use async_nats::Client as NatsClient;

/// Everything [`on_release`] needs.
#[derive(Debug, Clone)]
pub struct UpdateCtx {
    /// Server base URL, e.g. `https://rmm.example.com` (no trailing slash needed).
    pub api_base: String,
    /// Watchdog root directory.
    pub root: PathBuf,
    /// Release platform string, e.g. `linux-x86_64`.
    pub platform: String,
    /// Version of the running agent.
    pub current_version: String,
    /// HTTP client (carries the agent's extra CA in dev builds).
    pub http: reqwest::Client,
}

/// What [`on_release`] did with an offered release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Same version as the running agent.
    UpToDate,
    /// Older than the running agent; refused.
    Downgrade,
    /// The watchdog recorded this artifact as having failed a trial.
    KnownBad,
    /// Downloaded, verified and staged with `READY` written.
    Staged,
    /// Not staged; the reason is stable (`pending_exists`, `hash_mismatch`, ...).
    Failed(String),
}

/// Release platform string of this build, e.g. `linux-x86_64` (same as the
/// watchdog's).
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Watchdog root: `RMM_WATCHDOG_ROOT`, else `%ProgramData%\RMM` on Windows and
/// the parent of the state directory elsewhere.
pub fn watchdog_root(state_dir: &Path) -> Option<PathBuf> {
    if let Some(v) = std::env::var_os(ROOT_ENV).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(v));
    }
    if cfg!(windows) {
        std::env::var_os("ProgramData").map(|p| PathBuf::from(p).join("RMM"))
    } else {
        state_dir.parent().map(Path::to_path_buf)
    }
}

/// Whether `root` looks like a watchdog root (has `state.json` or the
/// installer's `bootstrap/`). A plain directory is not enough: the default
/// root on unix is just the parent of the state directory.
pub fn root_is_managed(root: &Path) -> bool {
    root.join(STATE_FILE).is_file() || root.join("bootstrap").is_dir()
}

#[derive(Deserialize)]
struct WatchdogState {
    #[serde(default)]
    bad_hashes: Vec<String>,
}

/// Hashes the watchdog recorded as bad (empty when `state.json` is missing or
/// unreadable).
fn bad_hashes(root: &Path) -> Vec<String> {
    fs::read(root.join(STATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<WatchdogState>(&b).ok())
        .map(|s| s.bad_hashes)
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn failed(reason: &str) -> UpdateOutcome {
    UpdateOutcome::Failed(reason.to_owned())
}

fn io_failed(what: &str, e: &io::Error) -> UpdateOutcome {
    tracing::warn!("update: {what}: {e}");
    UpdateOutcome::Failed(format!("io_{what}"))
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn sync_dir(dir: &Path) {
    if cfg!(unix)
        && let Ok(f) = File::open(dir)
    {
        let _ = f.sync_all();
    }
}

/// Decide about, download and stage `release` (already verified by the
/// caller). `release_env` and `manifest_env` are the envelopes the watchdog
/// verifies again.
pub async fn on_release(
    release: &ReleaseManifest,
    release_env: &[u8],
    manifest_env: &[u8],
    ctx: &UpdateCtx,
) -> UpdateOutcome {
    let Ok(current) = semver::Version::parse(&ctx.current_version) else {
        return failed("bad_current_version");
    };
    let Ok(offered) = semver::Version::parse(&release.version) else {
        return failed("bad_release_version");
    };
    match offered.cmp_precedence(&current) {
        std::cmp::Ordering::Equal => return UpdateOutcome::UpToDate,
        std::cmp::Ordering::Less => return UpdateOutcome::Downgrade,
        std::cmp::Ordering::Greater => {}
    }
    let Some(artifact) = release.artifact_for(&ctx.platform) else {
        return failed("no_artifact_for_platform");
    };
    let sha = hex(&artifact.sha256.0);
    if artifact.sha256.0.len() != 32 || artifact.size == 0 {
        return failed("bad_artifact");
    }
    if bad_hashes(&ctx.root).contains(&sha) {
        return UpdateOutcome::KnownBad;
    }
    let name = Path::new(&artifact.name);
    if name.file_name() != Some(name.as_os_str()) || artifact.name.is_empty() {
        return failed("bad_artifact_name");
    }

    let dir = ctx.root.join(PENDING_DIR);
    if dir.join(READY_FILE).exists() {
        return failed("pending_exists");
    }
    // Leftovers of an interrupted attempt (no READY, so the watchdog ignores
    // them) must not mix with this one.
    if let Err(e) = fs::remove_dir_all(&dir)
        && e.kind() != io::ErrorKind::NotFound
    {
        return io_failed("clear_pending", &e);
    }
    if let Err(e) = fs::create_dir_all(&dir) {
        return io_failed("create_pending", &e);
    }

    let part = dir.join(format!("{}.part", artifact.name));
    match download(ctx, &sha, artifact.size, &part).await {
        Ok(got) if got == artifact.sha256.0.as_slice() => {}
        Ok(_) => {
            let _ = fs::remove_file(&part);
            return failed("hash_mismatch");
        }
        Err(outcome) => {
            let _ = fs::remove_file(&part);
            return outcome;
        }
    }

    let staged = (|| -> io::Result<()> {
        write_synced(&dir.join(MANIFEST_FILE), manifest_env)?;
        write_synced(&dir.join(RELEASE_FILE), release_env)?;
        fs::rename(&part, dir.join(ARTIFACT_FILE))?;
        sync_dir(&dir);
        write_synced(&dir.join(READY_FILE), b"")?;
        sync_dir(&dir);
        Ok(())
    })();
    match staged {
        Ok(()) => {
            tracing::info!(version = %release.version, sha256 = %sha, "release staged for the watchdog");
            UpdateOutcome::Staged
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&dir);
            io_failed("stage", &e)
        }
    }
}

/// Download the artifact into `part`, hashing while writing. Fails when the
/// body is longer than `size` (aborted at once) or shorter. Returns the hash.
async fn download(
    ctx: &UpdateCtx,
    sha_hex: &str,
    size: u64,
    part: &Path,
) -> Result<[u8; 32], UpdateOutcome> {
    let url = format!(
        "{}/v1/artifacts/{sha_hex}",
        ctx.api_base.trim_end_matches('/')
    );
    let mut resp = ctx
        .http
        .get(&url)
        .timeout(DOWNLOAD_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!("update: download request failed: {e}");
            failed("download_failed")
        })?;
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "update: download refused");
        return Err(UpdateOutcome::Failed(format!(
            "download_http_{}",
            resp.status().as_u16()
        )));
    }
    if resp.content_length().is_some_and(|l| l > size) {
        return Err(failed("size_mismatch"));
    }
    let mut file = File::create(part).map_err(|e| io_failed("create_part", &e))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    loop {
        let chunk = resp.chunk().await.map_err(|e| {
            tracing::warn!("update: download interrupted: {e}");
            failed("download_failed")
        })?;
        let Some(chunk) = chunk else { break };
        total += chunk.len() as u64;
        if total > size {
            return Err(failed("size_mismatch"));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .map_err(|e| io_failed("write_part", &e))?;
    }
    if total != size {
        return Err(failed("size_mismatch"));
    }
    file.sync_all().map_err(|e| io_failed("sync_part", &e))?;
    Ok(hasher.finalize().into())
}

/// Wiring for the refresh callback: the callback only receives the decoded
/// release, so the envelope is fetched again (`svc.release.latest`), verified
/// the same way and must decode to the same release before the cached trust
/// manifest and the envelope go to [`on_release`]. At most one update runs at
/// a time; offers arriving meanwhile are dropped (the next refresh repeats
/// them).
#[derive(Clone)]
pub struct Updater {
    client: async_nats::Client,
    store: Arc<Store>,
    agent: Arc<Agent>,
    ctx: UpdateCtx,
    busy: Arc<AtomicBool>,
}

impl std::fmt::Debug for Updater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Updater")
            .field("ctx", &self.ctx)
            .finish_non_exhaustive()
    }
}

impl Updater {
    /// New updater over the agent's connection and store.
    pub fn new(
        client: async_nats::Client,
        store: Arc<Store>,
        agent: Arc<Agent>,
        ctx: UpdateCtx,
    ) -> Self {
        Self {
            client,
            store,
            agent,
            ctx,
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Handle an offered release without blocking the caller (spawns on the
    /// current Tokio runtime).
    pub fn offer(&self, release: ReleaseManifest) {
        if self.busy.swap(true, Ordering::AcqRel) {
            tracing::debug!(version = %release.version, "update already in progress; offer dropped");
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let outcome = me.handle(&release).await;
            me.busy.store(false, Ordering::Release);
            match outcome {
                UpdateOutcome::Staged => {
                    tracing::info!(version = %release.version, "update staged");
                }
                UpdateOutcome::Failed(reason) => {
                    tracing::warn!(version = %release.version, %reason, "update failed");
                }
                UpdateOutcome::Downgrade => {
                    tracing::info!(version = %release.version, "update skipped: downgrade");
                }
                other => {
                    tracing::info!(version = %release.version, outcome = ?other, "update skipped");
                }
            }
        });
    }

    async fn handle(&self, release: &ReleaseManifest) -> UpdateOutcome {
        // Cheap checks first so an unchanged offer costs no request.
        let reply = match tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.client.request(RELEASE_SUBJECT, Vec::new().into()),
        )
        .await
        {
            Ok(Ok(m)) => m.payload.to_vec(),
            _ => return failed("release_fetch_failed"),
        };
        let Ok(latest) = decode_doc::<ReleaseLatest>(&reply) else {
            return failed("release_fetch_failed");
        };
        let Some(env) = latest.release else {
            return failed("release_gone");
        };
        let (store, agent, reply2) = (
            Arc::clone(&self.store),
            Arc::clone(&self.agent),
            reply.clone(),
        );
        let verified = tokio::task::spawn_blocking(move || {
            let doc = verify_release_latest(&reply2, &agent, &store, &SystemClock)?;
            let manifest = store.trust_get(DocKind::Manifest).ok().flatten()?;
            Some((doc, manifest))
        })
        .await
        .ok()
        .flatten();
        match verified {
            Some((doc, manifest)) if doc == *release => {
                on_release(release, &env.0, &manifest, &self.ctx).await
            }
            _ => failed("release_changed"),
        }
    }
}
