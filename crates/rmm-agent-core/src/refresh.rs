//! Periodic trust and release refresh.
//!
//! On every (re)connect and every [`REFRESH_INTERVAL`] the agent asks the
//! server for the newest trust documents (`svc.trust.latest`) and release
//! (`svc.release.latest`). Trust documents go through exactly the verification
//! `TrustUpdate` uses ([`commands::trust_update`]: signer role, threshold,
//! time window and the persisted sequence floor), so a newer technician list
//! reaches the running agent without re-enrolling and an older or tampered one
//! changes nothing. A release is verified with the release role under the
//! current manifest and handed to a callback; the updater decides what to do
//! with it. Every failure is logged and never fatal.

use std::sync::Arc;
use std::time::Duration;

use rmm_recipe::result::RejectReason;
use rmm_trust::docs::{
    ReleaseLatest, ReleaseManifest, TechnicianList, TrustLatest, decode_doc, verify_release,
};
use rmm_trust::keys::Bytes;
use rmm_trust::store::{Clock, DocKind};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::commands::{self, Agent, SystemClock, load_trust, trust_update};
use crate::shell::ShellManager;
use crate::store::Store;

/// NATS subject answering with the latest trust documents.
pub const TRUST_SUBJECT: &str = "svc.trust.latest";
/// NATS subject answering with the latest release.
pub const RELEASE_SUBJECT: &str = "svc.release.latest";
/// Time between periodic refreshes.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// How long one request waits for the server.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Receives every verified release the server offers (the updater).
pub type ReleaseCallback = Arc<dyn Fn(ReleaseManifest) + Send + Sync>;

/// What [`run`] needs besides the connection and the store.
#[derive(Clone)]
pub struct RefreshOptions {
    /// This agent (trust roots and identity).
    pub agent: Arc<Agent>,
    /// Shell manager told about a new technician list.
    pub shell: Option<ShellManager>,
    /// Called with each verified release; `None` ignores releases.
    pub on_release: Option<ReleaseCallback>,
    /// Notified on every (re)connect to refresh at once.
    pub wake: Arc<Notify>,
    /// Stops the loop.
    pub shutdown: CancellationToken,
}

impl std::fmt::Debug for RefreshOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshOptions")
            .field("agent", &self.agent)
            .field("on_release", &self.on_release.is_some())
            .finish_non_exhaustive()
    }
}

/// Apply a `svc.trust.latest` reply: manifest, revocations and technician
/// list, each through the verifying trust store. Documents the Store already
/// caches byte for byte are skipped. An older sequence number is refused by
/// the store (rollback) and leaves the cached document in place.
pub fn apply_trust_latest(
    payload: &[u8],
    agent: &Agent,
    store: &Store,
    clock: &dyn Clock,
    on_techlist: &dyn Fn(&TechnicianList),
) -> Result<(), RejectReason> {
    let latest: TrustLatest = match decode_doc(payload) {
        Ok(l) => l,
        Err(e) => {
            return commands::reject(
                RejectReason::Validation,
                format_args!("trust refresh reply: {e}"),
            );
        }
    };
    let fresh = |kind: DocKind, doc: Option<Bytes>| {
        let cached = store.trust_get(kind).unwrap_or(None);
        doc.filter(|d| cached.as_deref() != Some(d.0.as_slice()))
    };
    let manifest = fresh(DocKind::Manifest, latest.manifest);
    let revocations = fresh(DocKind::Revocations, latest.revocations);
    let techlist = fresh(DocKind::Techlist, latest.techlist);
    if manifest.is_none() && revocations.is_none() && techlist.is_none() {
        return Ok(());
    }
    let trust = load_trust(store, agent.roots.clone(), agent.threshold, clock);
    let docs = [
        (DocKind::Manifest, &manifest),
        (DocKind::Revocations, &revocations),
        (DocKind::Techlist, &techlist),
    ];
    trust_update(trust, &docs, store, clock, on_techlist)
}

/// Verify a `svc.release.latest` reply: `None` when no release is offered or
/// it does not verify with the release role under the current manifest.
pub fn verify_release_latest(
    payload: &[u8],
    agent: &Agent,
    store: &Store,
    clock: &dyn Clock,
) -> Option<ReleaseManifest> {
    let latest: ReleaseLatest = match decode_doc(payload) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("release refresh reply: {e}");
            return None;
        }
    };
    let env = latest.release?;
    let trust = load_trust(store, agent.roots.clone(), agent.threshold, clock);
    match verify_release(&trust, &env.0, clock.now()) {
        Ok((signed, doc)) => {
            if trust.is_artifact_revoked(&signed.content_id())
                || doc.artifacts.iter().any(|a| {
                    <[u8; 32]>::try_from(a.sha256.0.as_slice())
                        .is_ok_and(|h| trust.is_artifact_revoked(&h))
                })
            {
                tracing::warn!(version = %doc.version, "offered release is revoked");
                return None;
            }
            Some(doc)
        }
        Err(e) => {
            tracing::warn!("offered release rejected: {e}");
            None
        }
    }
}

/// Verify a `svc.release.latest` reply and hand a valid release to
/// `on_release`. Returns whether a valid release was found.
pub fn offer_release(
    payload: &[u8],
    agent: &Agent,
    store: &Store,
    clock: &dyn Clock,
    on_release: Option<&(dyn Fn(ReleaseManifest) + Send + Sync)>,
) -> bool {
    let Some(doc) = verify_release_latest(payload, agent, store, clock) else {
        return false;
    };
    tracing::info!(version = %doc.version, seq = doc.seq, "release offered");
    if let Some(cb) = on_release {
        cb(doc);
    }
    true
}

async fn request(client: &async_nats::Client, subject: &'static str) -> Option<Vec<u8>> {
    match tokio::time::timeout(REQUEST_TIMEOUT, client.request(subject, Vec::new().into())).await {
        Ok(Ok(msg)) => Some(msg.payload.to_vec()),
        Ok(Err(e)) => {
            tracing::warn!(subject, "refresh request failed: {e}");
            None
        }
        Err(_) => {
            tracing::warn!(subject, "refresh request timed out");
            None
        }
    }
}

/// One refresh round: trust documents first (a new manifest may be what a
/// release verifies under), then the release.
async fn refresh_once(client: &async_nats::Client, store: &Arc<Store>, opts: &RefreshOptions) {
    if let Some(payload) = request(client, TRUST_SUBJECT).await {
        let (store, agent, shell) = (
            Arc::clone(store),
            Arc::clone(&opts.agent),
            opts.shell.clone(),
        );
        let done = tokio::task::spawn_blocking(move || {
            let on_techlist = |list: &TechnicianList| {
                if let Some(m) = &shell {
                    m.on_techlist(list);
                }
            };
            apply_trust_latest(&payload, &agent, &store, &SystemClock, &on_techlist)
        })
        .await;
        match done {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => tracing::warn!(?reason, "trust refresh not applied"),
            Err(e) => tracing::error!("trust refresh task failed: {e}"),
        }
    }
    if let Some(payload) = request(client, RELEASE_SUBJECT).await {
        let (store, agent) = (Arc::clone(store), Arc::clone(&opts.agent));
        let on_release = opts.on_release.clone();
        let done = tokio::task::spawn_blocking(move || {
            offer_release(
                &payload,
                &agent,
                &store,
                &SystemClock,
                on_release.as_deref(),
            );
        })
        .await;
        if let Err(e) = done {
            tracing::error!("release refresh task failed: {e}");
        }
    }
}

/// Refresh whenever `opts.wake` fires (connect) and every `interval`, until
/// `opts.shutdown`. While disconnected a round just times out and is logged.
pub async fn run(
    client: async_nats::Client,
    store: Arc<Store>,
    opts: RefreshOptions,
    interval: Duration,
) {
    loop {
        tokio::select! {
            () = opts.shutdown.cancelled() => return,
            () = opts.wake.notified() => {}
            () = tokio::time::sleep(interval) => {}
        }
        tokio::select! {
            () = opts.shutdown.cancelled() => return,
            () = refresh_once(&client, &store, &opts) => {}
        }
    }
}
