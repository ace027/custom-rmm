//! Command intake and the verification chain.
//!
//! Intake binds to the durable pull consumer `agent_<agent_id>` on stream
//! `CMD`, pulls one message at a time, stores the envelope in the encrypted
//! [`Store`] inbox, acks it, and then works the inbox: verify, execute, sign
//! the [`ActionResult`] and queue it in the outbox at priority 0 on
//! `result.<client>.<agent>`. A row is marked done only after its result is
//! queued, so a restart finishes (or rejects as a replay) every pending
//! command. Every envelope gets a result, rejected ones included.
//!
//! Verification order: [`TrustStore::verify_command`] (command role,
//! agent/client binding, time window, revocation, persisted replay cache,
//! trust freshness) -> inline definition signed by the catalog role and not
//! revoked -> `min_agent_version` -> static recipe validation -> parameter
//! validation -> capability within the manifest's `capability_ceiling`.
//! Until the signed policy engine exists, that root-signed ceiling is the
//! capability allow-list; it is applied to the definition's capability and
//! to the capability group of every block it uses.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmm_recipe::definition::{Definition, TYPE_DEFINITION};
use rmm_recipe::result::{ActionResult, RejectReason};
use rmm_recipe::validate::{BLOCKS, validate_definition, validate_params};
use rmm_trust::docs::{Command, CommandBody, Role, decode_doc};
use rmm_trust::envelope::Envelope;
use rmm_trust::error::TrustError;
use rmm_trust::keys::PublicKey;
use rmm_trust::store::{Clock, DocKind, ReplayCache, TrustStore};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::blocks::BlockRunner;
use crate::executor;
use crate::identity::Identity;
use crate::store::{Store, StoreError};

/// JetStream stream carrying commands.
pub const CMD_STREAM: &str = "CMD";
/// Outbox priority of command results (never dropped).
pub const PRIORITY_RESULT: u8 = 0;
/// How long one pull request waits for a message.
pub const PULL_EXPIRES: Duration = Duration::from_secs(30);
/// First retry delay of the intake loop.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Longest retry delay of the intake loop.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Comma-separated hex Ed25519 root public keys compiled into the agent
/// (same build inputs as enrollment).
const ROOT_PUBKEYS: Option<&str> = option_env!("RMM_ROOT_PUBKEYS");
/// Root signature threshold used before the first manifest is installed.
const ROOT_THRESHOLD: Option<&str> = option_env!("RMM_ROOT_THRESHOLD");

/// Name of an agent's durable command consumer.
pub fn consumer_name(agent_id: &str) -> String {
    format!("agent_{agent_id}")
}

/// Subject an agent's results are published on.
pub fn result_subject(client_id: &str, agent_id: &str) -> String {
    format!("result.{client_id}.{agent_id}")
}

/// Wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
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

/// Parse comma-separated hex root keys and an optional threshold (default:
/// all keys).
pub fn parse_roots(keys: &str, threshold: Option<&str>) -> Result<(Vec<PublicKey>, u8), String> {
    let mut out = Vec::new();
    for part in keys.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let raw = parse_hex32(part).ok_or("root key is not 32 hex bytes")?;
        out.push(PublicKey::from_bytes(&raw).map_err(|e| format!("root key: {e}"))?);
    }
    let threshold = match threshold {
        Some(t) => t
            .trim()
            .parse::<u8>()
            .map_err(|_| "root threshold is not a number".to_owned())?,
        None => u8::try_from(out.len()).unwrap_or(u8::MAX),
    };
    Ok((out, threshold))
}

/// The root keys compiled into this agent (`RMM_ROOT_PUBKEYS`).
pub fn compiled_roots() -> Result<(Vec<PublicKey>, u8), String> {
    parse_roots(ROOT_PUBKEYS.unwrap_or(""), ROOT_THRESHOLD)
}

/// Rebuild the trust state from the envelopes cached in the Store, checked
/// against `roots` and the Store's persisted sequence floors. A missing or
/// failing document is left out, so verification fails closed.
pub fn load_trust(
    store: &Store,
    roots: Vec<PublicKey>,
    threshold: u8,
    clock: &dyn Clock,
) -> TrustStore {
    let mut trust = TrustStore::new(roots, threshold);
    let mut seq = store;
    let get = |kind| match store.trust_get(kind) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, ?kind, "cached trust document unreadable");
            None
        }
    };
    let Some(manifest) = get(DocKind::Manifest) else {
        return trust;
    };
    if let Err(e) = trust.apply_manifest(&manifest, clock, &mut seq) {
        tracing::error!(error = %e, "cached manifest rejected");
        return trust;
    }
    if let Some(r) = get(DocKind::Revocations)
        && let Err(e) = trust.apply_revocations(&r, clock, &mut seq)
    {
        tracing::error!(error = %e, "cached revocations rejected");
    }
    if let Some(t) = get(DocKind::Techlist)
        && let Err(e) = trust.apply_techlist(&t, clock, &mut seq)
    {
        tracing::warn!(error = %e, "cached technician list rejected");
    }
    trust
}

/// Inputs of [`verify`].
pub struct VerifyCtx<'a> {
    /// Current trust state.
    pub trust: &'a TrustStore,
    /// This agent's id.
    pub agent_id: &'a str,
    /// This agent's client id.
    pub client_id: &'a str,
    /// Time source.
    pub clock: &'a dyn Clock,
    /// Persisted replay cache.
    pub replay: &'a mut dyn ReplayCache,
    /// This agent's version (semver `x.y.z`).
    pub agent_version: &'a str,
}

impl fmt::Debug for VerifyCtx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyCtx")
            .field("agent_id", &self.agent_id)
            .field("client_id", &self.client_id)
            .field("agent_version", &self.agent_version)
            .finish_non_exhaustive()
    }
}

/// A command that passed every check.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The verified command (body is `Invoke`).
    pub command: Command,
    /// The verified, validated definition.
    pub definition: Definition,
    /// Content id of the definition envelope.
    pub content_id: [u8; 32],
}

fn trust_reason(e: &TrustError) -> RejectReason {
    match e {
        TrustError::Expired | TrustError::NotYetValid => RejectReason::Expired,
        TrustError::Replay => RejectReason::Replay,
        TrustError::WrongAgent | TrustError::WrongClient => RejectReason::WrongAgent,
        TrustError::ArtifactRevoked => RejectReason::Revoked,
        TrustError::Stale | TrustError::NoManifest => RejectReason::StaleTrust,
        TrustError::InvalidDocument(_) => RejectReason::Validation,
        _ => RejectReason::BadSignature,
    }
}

/// `(major, minor, patch, is_release)` of a semantic version; build metadata
/// is ignored and a pre-release sorts before its release.
fn version_key(v: &str) -> Option<(u64, u64, u64, bool)> {
    let v = v.split('+').next()?;
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let (ma, mi, pa) = (it.next()??, it.next()??, it.next()??);
    if it.next().is_some() {
        return None;
    }
    Some((ma, mi, pa, pre.is_none()))
}

fn reject<T>(reason: RejectReason, why: impl fmt::Display) -> Result<T, RejectReason> {
    tracing::warn!(?reason, "command rejected: {why}");
    Err(reason)
}

/// Run the verification chain over a command envelope.
pub fn verify(env_bytes: &[u8], ctx: &mut VerifyCtx<'_>) -> Result<Verified, RejectReason> {
    let now = ctx.clock.now();
    let command = match ctx.trust.verify_command(
        env_bytes,
        ctx.agent_id,
        ctx.client_id,
        ctx.clock,
        ctx.replay,
    ) {
        Ok(c) => c,
        Err(e) => return reject(trust_reason(&e), e),
    };
    let CommandBody::Invoke { definition, params } = &command.body else {
        return reject(RejectReason::Validation, "not an invoke command");
    };

    let env = match Envelope::from_bytes(&definition.0) {
        Ok(e) => e,
        Err(e) => return reject(RejectReason::UnsignedDefinition, e),
    };
    if env.r#type != TYPE_DEFINITION {
        return reject(
            RejectReason::UnsignedDefinition,
            "definition has the wrong type",
        );
    }
    if let Err(e) = ctx.trust.verify_role(&env, Role::Catalog, now) {
        return reject(RejectReason::UnsignedDefinition, e);
    }
    let content_id = env.content_id();
    if ctx.trust.is_artifact_revoked(&content_id) {
        return reject(RejectReason::Revoked, "definition revoked");
    }
    let def = match Definition::from_envelope_payload(&env.payload.0) {
        Ok(d) => d,
        Err(e) => return reject(RejectReason::Validation, e),
    };

    let (Some(need), Some(have)) = (
        version_key(&def.min_agent_version),
        version_key(ctx.agent_version),
    ) else {
        return reject(RejectReason::Validation, "unparsable version");
    };
    if have < need {
        return reject(
            RejectReason::AgentVersion,
            format!("needs agent {}", def.min_agent_version),
        );
    }
    if let Err(e) = validate_definition(&def, BLOCKS) {
        return reject(RejectReason::Validation, e);
    }
    if let Err(e) = validate_params(&def, params) {
        return reject(RejectReason::Validation, e);
    }

    let ceiling = ctx
        .trust
        .manifest()
        .map(|m| m.capability_ceiling.as_slice())
        .unwrap_or_default();
    let block_caps = def
        .all_steps()
        .filter_map(|(_, st)| BLOCKS.iter().find(|b| b.name == st.block))
        .map(|b| b.capability);
    if let Some(cap) = std::iter::once(def.capability.as_str())
        .chain(block_caps)
        .find(|c| !ceiling.iter().any(|x| x == c))
    {
        return reject(
            RejectReason::Capability,
            format!("capability {cap} not in ceiling"),
        );
    }

    Ok(Verified {
        command,
        definition: def,
        content_id,
    })
}

/// Best-effort ids of an (unverified) envelope for inbox keys and rejection
/// results: the command's 16-byte `cmd_id` (or the first 16 bytes of the
/// envelope's SHA-256 when it cannot be read) and the inline definition's
/// content id (or zeros).
pub fn envelope_ids(env_bytes: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let cmd = Envelope::from_bytes(env_bytes)
        .ok()
        .and_then(|e| decode_doc::<Command>(&e.payload.0).ok());
    let cmd_id = cmd
        .as_ref()
        .map(|c| c.cmd_id.0.clone())
        .filter(|id| id.len() == 16)
        .unwrap_or_else(|| Sha256::digest(env_bytes)[..16].to_vec());
    let def_id = match cmd.map(|c| c.body) {
        Some(CommandBody::Invoke { definition, .. }) => Envelope::from_bytes(&definition.0)
            .map(|e| e.content_id())
            .unwrap_or([0; 32]),
        _ => [0; 32],
    };
    (cmd_id, def_id)
}

/// Who this agent is, and the key it signs results with.
pub struct Agent {
    /// Agent id as it appears in commands.
    pub agent_id: String,
    /// Client id as it appears in commands.
    pub client_id: String,
    /// Agent version checked against `min_agent_version`.
    pub version: String,
    seed: Zeroizing<[u8; 32]>,
    roots: Vec<PublicKey>,
    threshold: u8,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("agent_id", &self.agent_id)
            .field("client_id", &self.client_id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// An agent with explicit trust roots (tests, tools).
    pub fn new(
        agent_id: impl Into<String>,
        client_id: impl Into<String>,
        seed: [u8; 32],
        roots: Vec<PublicKey>,
        threshold: u8,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            client_id: client_id.into(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            seed: Zeroizing::new(seed),
            roots,
            threshold,
        }
    }

    /// The enrolled agent with the compiled-in roots.
    pub fn from_identity(identity: &Identity, seed: [u8; 32]) -> Result<Self, String> {
        let (roots, threshold) = compiled_roots()?;
        Ok(Self::new(
            identity.agent_id.to_string(),
            identity.client_id.to_string(),
            seed,
            roots,
            threshold,
        ))
    }

    /// Subject this agent publishes results on.
    pub fn result_subject(&self) -> String {
        result_subject(&self.client_id, &self.agent_id)
    }
}

/// Verify and, if accepted, execute one envelope. Never fails: every path
/// ends in a result.
pub fn handle(
    env_bytes: &[u8],
    agent: &Agent,
    store: &Store,
    blocks: &dyn BlockRunner,
    clock: &dyn Clock,
) -> ActionResult {
    let trust = load_trust(store, agent.roots.clone(), agent.threshold, clock);
    let mut replay = store;
    let mut ctx = VerifyCtx {
        trust: &trust,
        agent_id: &agent.agent_id,
        client_id: &agent.client_id,
        clock,
        replay: &mut replay,
        agent_version: &agent.version,
    };
    match verify(env_bytes, &mut ctx) {
        Ok(v) => {
            tracing::info!(
                cmd_id = %crate::blocks::hex(&v.command.cmd_id.0),
                definition = %v.definition.id,
                "running command"
            );
            executor::run(&v, blocks)
        }
        Err(reason) => {
            let (cmd_id, def_id) = envelope_ids(env_bytes);
            executor::rejected(cmd_id, &agent.agent_id, def_id, reason)
        }
    }
}

/// Sign `result` and queue it in the outbox at priority 0.
pub fn queue_result(store: &Store, agent: &Agent, result: &ActionResult) -> Result<(), StoreError> {
    let env = executor::sign_result(result, &agent.seed)
        .map_err(|e| StoreError::Io(format!("sign result: {e}")))?;
    let bytes = env
        .to_bytes()
        .map_err(|e| StoreError::Io(format!("encode result: {e}")))?;
    store.outbox_push(
        Uuid::now_v7().into_bytes(),
        &agent.result_subject(),
        PRIORITY_RESULT,
        &bytes,
    )?;
    Ok(())
}

/// Store a received envelope in the inbox; returns its inbox key.
pub fn accept(store: &Store, env_bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    let (cmd_id, _) = envelope_ids(env_bytes);
    store.inbox_put(&cmd_id, env_bytes)?;
    Ok(cmd_id)
}

/// Work every pending inbox entry, oldest first: handle it, queue its result,
/// mark it done. Returns how many were finished.
pub fn process_pending(
    store: &Store,
    agent: &Agent,
    blocks: &dyn BlockRunner,
    clock: &dyn Clock,
) -> Result<usize, StoreError> {
    let mut n = 0;
    while let Some((cmd_id, env)) = store.inbox_next_pending()? {
        let result = handle(&env, agent, store, blocks, clock);
        tracing::info!(
            cmd_id = %crate::blocks::hex(&cmd_id),
            outcome = ?result.outcome,
            reason = ?result.reason,
            "command finished"
        );
        queue_result(store, agent, &result)?;
        store.inbox_mark_done(&cmd_id)?;
        n += 1;
    }
    Ok(n)
}

/// What [`intake`] needs besides the connection.
#[derive(Debug, Clone)]
pub struct IntakeOptions {
    /// This agent.
    pub agent: Arc<Agent>,
    /// Building blocks.
    pub blocks: Arc<dyn BlockRunner>,
    /// Notified after a result is queued so the outbox drain runs at once
    /// (the telemetry drain task's wake-up notify).
    pub outbox_wake: Arc<Notify>,
    /// Stops the loop.
    pub shutdown: CancellationToken,
}

async fn run_pending(store: &Arc<Store>, opts: &IntakeOptions) {
    let (store, agent, blocks) = (
        Arc::clone(store),
        Arc::clone(&opts.agent),
        Arc::clone(&opts.blocks),
    );
    let done = tokio::task::spawn_blocking(move || {
        process_pending(&store, &agent, blocks.as_ref(), &SystemClock)
    })
    .await;
    match done {
        Ok(Ok(0)) => {}
        Ok(Ok(_)) => opts.outbox_wake.notify_one(),
        Ok(Err(e)) => tracing::error!("command inbox: {e}"),
        Err(e) => tracing::error!("command task failed: {e}"),
    }
}

/// Pull commands until `shutdown`: bind to `agent_<id>` on `CMD`, fetch one
/// message at a time, store it in the inbox, ack, then execute. Pending
/// inbox entries from before a restart are worked first.
pub async fn intake(
    client: async_nats::Client,
    identity: &Identity,
    store: Arc<Store>,
    opts: IntakeOptions,
) {
    let consumer = consumer_name(&identity.agent_id.to_string());
    let next_subject = format!("$JS.API.CONSUMER.MSG.NEXT.{CMD_STREAM}.{consumer}");
    let js = async_nats::jetstream::new(client.clone());
    let expires_ns = u64::try_from(PULL_EXPIRES.as_nanos()).unwrap_or(u64::MAX);
    let pull = serde_json::json!({ "batch": 1, "expires": expires_ns }).to_string();

    run_pending(&store, &opts).await;
    let mut bound = false;
    let mut backoff = BACKOFF_MIN;
    loop {
        let wait = |d: Duration| {
            let token = opts.shutdown.clone();
            async move {
                tokio::select! {
                    () = token.cancelled() => {}
                    () = tokio::time::sleep(d) => {}
                }
            }
        };
        if opts.shutdown.is_cancelled() {
            return;
        }
        if !bound {
            let got = tokio::select! {
                () = opts.shutdown.cancelled() => return,
                r = js.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
                    &consumer, CMD_STREAM,
                ) => r,
            };
            match got {
                Ok(_) => {
                    tracing::info!(%consumer, "bound to command consumer");
                    bound = true;
                    backoff = BACKOFF_MIN;
                }
                Err(e) => {
                    tracing::warn!(%consumer, "command consumer unavailable: {e}");
                    wait(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            }
        }
        // A fresh inbox per pull, not the shared request multiplexer: JetStream
        // delivers a pulled message under its stream subject
        // (`agent.<id>.cmd`), which the multiplexer cannot match to a pending
        // request (it routes by reply-subject prefix) and silently drops. A
        // dedicated subscription is routed by subscription id instead.
        let request = async_nats::Request::new()
            .payload(pull.clone().into())
            .inbox(client.new_inbox())
            .timeout(Some(PULL_EXPIRES + Duration::from_secs(5)));
        let reply = tokio::select! {
            () = opts.shutdown.cancelled() => return,
            r = client.send_request(next_subject.clone(), request) => r,
        };
        let msg = match reply {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("command pull failed: {e}");
                bound = false;
                wait(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        backoff = BACKOFF_MIN;
        if let Some(status) = msg.status {
            if status != async_nats::StatusCode::NOT_FOUND
                && status != async_nats::StatusCode::TIMEOUT
            {
                tracing::warn!(?status, desc = ?msg.description, "command pull status");
                wait(BACKOFF_MIN).await;
            }
            continue;
        }
        let Some(ack_subject) = msg.reply.clone() else {
            tracing::warn!("command message without ack subject ignored");
            continue;
        };
        let payload = msg.payload.to_vec();
        let st = Arc::clone(&store);
        match tokio::task::spawn_blocking(move || accept(&st, &payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                // Not acked: the server redelivers after its ack wait.
                tracing::error!("command not stored: {e}");
                wait(BACKOFF_MIN).await;
                continue;
            }
            Err(e) => {
                tracing::error!("command store task failed: {e}");
                continue;
            }
        }
        if let Err(e) = client.request(ack_subject, "+ACK".into()).await {
            // Stored already; a redelivery is rejected as a replay.
            tracing::warn!("command ack failed: {e}");
        }
        run_pending(&store, &opts).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare() {
        assert!(version_key("0.1.0") >= version_key("0.1.0"));
        assert!(version_key("0.1.0") < version_key("0.2.0"));
        assert!(version_key("1.0.0-rc.1") < version_key("1.0.0"));
        assert!(version_key("1.0.0+build") == version_key("1.0.0"));
        assert_eq!(version_key("1.0"), None);
        assert_eq!(version_key("x.1.0"), None);
    }

    #[test]
    fn subjects() {
        assert_eq!(consumer_name("a1"), "agent_a1");
        assert_eq!(result_subject("c1", "a1"), "result.c1.a1");
    }

    #[test]
    fn garbage_envelope_ids_are_stable() {
        let (a, d) = envelope_ids(b"junk");
        assert_eq!(a.len(), 16);
        assert_eq!(d, [0; 32]);
        assert_eq!(envelope_ids(b"junk").0, a);
    }
}
