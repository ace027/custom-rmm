//! Administrative routes: enrollment tokens, agent revocation and trust
//! artifact upload. All require the `RMM.Admin` app role.

use std::collections::HashMap;

use async_nats::jetstream;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rand::TryRng;
use rmm_db::repo::{self, NewToken};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_trust::docs::{Command, CommandBody};
use rmm_trust::envelope::Envelope;
use rmm_trust::keys::Bytes as KeyBytes;
use rmm_trust::keys::PublicKey;
use rmm_trust::store::{Clock, DocKind, SeqStore, TrustStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};
use utoipa::ToSchema;

use crate::actions::{cmd_subject, ensure_agent_consumer, sign_command};
use crate::auth::{Admin, RequireRole};
use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// NATS subject announcing a revoked agent.
pub const REVOKED_SUBJECT: &str = "rmm.internal.agent.revoked";

/// Request to mint an enrollment token.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    /// Client the token belongs to.
    #[schema(value_type = String)]
    pub client_id: Uuid,
    /// Site devices enroll into.
    #[schema(value_type = String)]
    pub site_id: Uuid,
    /// Lifetime in hours (1..=720).
    pub expires_in_hours: i64,
    /// Maximum uses (1..=1000).
    pub max_uses: i32,
    /// Whether a device may be reattached by this token.
    pub allow_reattach: bool,
}

/// A freshly minted token; the secret is shown only here.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateTokenResponse {
    /// Token secret (`rmmenr_...`).
    pub token: String,
    /// Token id.
    #[schema(value_type = String)]
    pub token_id: Uuid,
    /// Expiry instant (RFC 3339).
    pub expires_at: String,
}

/// New random enrollment token: `rmmenr_` + 32 base32 characters.
fn generate_token() -> Result<String, ApiError> {
    let mut bytes = [0u8; 20];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(ApiError::internal)?;
    Ok(format!(
        "rmmenr_{}",
        data_encoding::BASE32_NOPAD.encode(&bytes)
    ))
}

/// Create an enrollment token.
#[utoipa::path(
    post,
    path = "/api/v1/enrollment-tokens",
    request_body = CreateTokenRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Token created (shown once)", body = CreateTokenResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody)
    )
)]
pub async fn create_enrollment_token(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
    if !(1..=720).contains(&req.expires_in_hours) {
        return Err(ApiError::BadRequest(
            "expires_in_hours must be 1..720".into(),
        ));
    }
    if !(1..=1000).contains(&req.max_uses) {
        return Err(ApiError::BadRequest("max_uses must be 1..1000".into()));
    }
    let token = generate_token()?;
    let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let expires_at =
        DateTime::<Utc>::from_timestamp(Utc::now().timestamp() + req.expires_in_hours * 3600, 0)
            .ok_or(ApiError::Internal)?;
    let actor = claims.actor();

    let mut tx = begin_scoped(&state.pool, &Scope::Service("admin-token"), &actor).await?;
    let site_ok: bool = sqlx::query_scalar(
        "select exists(select 1 from tenant.site where id = $1 and client_id = $2)",
    )
    .bind(req.site_id)
    .bind(req.client_id)
    .fetch_one(&mut *tx)
    .await?;
    if !site_ok {
        return Err(ApiError::BadRequest("unknown client or site".into()));
    }
    let token_id = repo::create_enrollment_token(
        &mut tx,
        NewToken {
            client_id: req.client_id,
            site_id: req.site_id,
            token_hash,
            expires_at,
            max_uses: req.max_uses,
            allow_reattach: req.allow_reattach,
            created_by: actor.clone(),
        },
    )
    .await?;
    let detail = serde_json::json!({
        "site_id": req.site_id,
        "max_uses": req.max_uses,
        "allow_reattach": req.allow_reattach,
        "expires_at": expires_at.to_rfc3339(),
    });
    repo::insert_audit(
        &mut tx,
        &actor,
        "enrollment_token.create",
        Some(req.client_id),
        &format!("token:{token_id}"),
        &detail,
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTokenResponse {
            token,
            token_id,
            expires_at: expires_at.to_rfc3339(),
        }),
    ))
}

/// Publish a revocation notice per agent so authd kicks their connections.
/// False when any notice could not be handed to NATS (or no client is
/// configured): the database change is already committed, so the caller
/// reports a retryable failure instead of claiming the kick happened.
async fn publish_kicks(state: &AppState, agents: &[repo::AgentRow]) -> bool {
    let Some(nats) = &state.nats else {
        if !agents.is_empty() {
            tracing::error!("no NATS client configured; revocation not published");
        }
        return agents.is_empty();
    };
    let mut ok = true;
    for a in agents {
        let payload = serde_json::json!({"agent_id": a.id, "nkey": a.nkey}).to_string();
        if let Err(err) = nats.publish(REVOKED_SUBJECT, payload.into()).await {
            tracing::error!(%err, agent_id = %a.id, "failed to publish agent revocation");
            ok = false;
        }
    }
    if let Err(err) = nats.flush().await {
        tracing::error!(%err, "failed to flush agent revocations");
        ok = false;
    }
    ok
}

/// 204, or 503 when the kick could not be published. The status change is
/// committed either way; repeating the request republishes the kick.
fn kick_response(published: bool) -> Response {
    if published {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: "status changed but the connection kick could not be published; retry"
                    .into(),
            }),
        )
            .into_response()
    }
}

/// Revoke an agent and tell NATS to drop its connection.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{agent_id}/revoke",
    params(("agent_id" = String, Path, description = "Agent id")),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Agent revoked and connection kick published"),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 404, description = "Unknown or superseded agent", body = ErrorBody),
        (status = 503, description = "Agent revoked but the kick was not published; retry", body = ErrorBody)
    )
)]
pub async fn revoke_agent(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let actor = claims.actor();
    let mut tx = begin_scoped(&state.pool, &Scope::Service("admin-revoke"), &actor).await?;
    // Repeating a revoke is allowed (it republishes the kick); a superseded
    // agent cannot be revoked.
    let row = repo::transition_agent_status(
        &mut tx,
        agent_id,
        &["active", "suspect_clone", "revoked"],
        "revoked",
    )
    .await?
    .ok_or_else(|| ApiError::NotFound("unknown agent".into()))?;
    repo::insert_audit(
        &mut tx,
        &actor,
        "agent.revoke",
        Some(row.client_id),
        &format!("agent:{agent_id}"),
        &serde_json::json!({"device_id": row.device_id}),
    )
    .await?;
    tx.commit().await?;

    Ok(kick_response(
        publish_kicks(&state, std::slice::from_ref(&row)).await,
    ))
}

/// Approve a device held for review (`pending_review` or `flagged`).
#[utoipa::path(
    post,
    path = "/api/v1/devices/{device_id}/approve",
    params(("device_id" = String, Path, description = "Device id")),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Device and its agent activated; the original device's agents superseded"),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 404, description = "Unknown device or not held for review", body = ErrorBody),
        (status = 503, description = "Approved but the kick of superseded agents was not published; retry", body = ErrorBody)
    )
)]
pub async fn approve_device(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    Path(device_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let actor = claims.actor();
    let mut tx = begin_scoped(&state.pool, &Scope::Service("admin-device"), &actor).await?;
    let approval = repo::approve_device(&mut tx, device_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("device not held for review".into()))?;
    let ids = |rows: &[repo::AgentRow]| rows.iter().map(|a| a.id).collect::<Vec<_>>();
    repo::insert_audit(
        &mut tx,
        &actor,
        "device.approve",
        Some(approval.client_id),
        &format!("device:{device_id}"),
        &serde_json::json!({
            "activated": ids(&approval.activated),
            "superseded": ids(&approval.superseded),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(kick_response(
        publish_kicks(&state, &approval.superseded).await,
    ))
}

/// Reject a device held for review: its agents are revoked.
#[utoipa::path(
    post,
    path = "/api/v1/devices/{device_id}/reject",
    params(("device_id" = String, Path, description = "Device id")),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Agents of the device revoked and kick published"),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 404, description = "Unknown device or not held for review", body = ErrorBody),
        (status = 503, description = "Rejected but the kick was not published; retry", body = ErrorBody)
    )
)]
pub async fn reject_device(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    Path(device_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let actor = claims.actor();
    let mut tx = begin_scoped(&state.pool, &Scope::Service("admin-device"), &actor).await?;
    let (client_id, revoked) = repo::reject_device(&mut tx, device_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("device not held for review".into()))?;
    repo::insert_audit(
        &mut tx,
        &actor,
        "device.reject",
        Some(client_id),
        &format!("device:{device_id}"),
        &serde_json::json!({"revoked": revoked.iter().map(|a| a.id).collect::<Vec<_>>()}),
    )
    .await?;
    tx.commit().await?;
    Ok(kick_response(publish_kicks(&state, &revoked).await))
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        u64::try_from(Utc::now().timestamp()).unwrap_or(0)
    }
}

#[derive(Default)]
struct MemSeq(HashMap<DocKind, (u64, [u8; 32])>);

impl SeqStore for MemSeq {
    fn get(&self, kind: DocKind) -> Option<(u64, [u8; 32])> {
        self.0.get(&kind).copied()
    }

    fn put(&mut self, kind: DocKind, seq: u64, content_id: [u8; 32]) {
        self.0.insert(kind, (seq, content_id));
    }
}

fn parse_kind(kind: &str) -> Option<DocKind> {
    match kind {
        "manifest" => Some(DocKind::Manifest),
        "revocations" => Some(DocKind::Revocations),
        "techlist" => Some(DocKind::Techlist),
        _ => None,
    }
}

fn apply(
    store: &mut TrustStore,
    kind: DocKind,
    bytes: &[u8],
    seqs: &mut MemSeq,
) -> Result<(), rmm_trust::error::TrustError> {
    match kind {
        DocKind::Manifest => store.apply_manifest(bytes, &SystemClock, seqs),
        DocKind::Revocations => store.apply_revocations(bytes, &SystemClock, seqs),
        DocKind::Techlist => store.apply_techlist(bytes, &SystemClock, seqs),
    }
}

/// Upload a signed trust artifact.
#[utoipa::path(
    put,
    path = "/api/v1/trust/{kind}",
    params(("kind" = String, Path, description = "manifest, revocations or techlist")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Artifact verified and stored"),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 404, description = "Unknown kind", body = ErrorBody),
        (status = 422, description = "Verification failed", body = ErrorBody)
    )
)]
pub async fn put_trust(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    Path(kind): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let doc_kind = parse_kind(&kind).ok_or_else(|| ApiError::NotFound("unknown kind".into()))?;
    let roots = state
        .roots
        .keys
        .iter()
        .map(PublicKey::from_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;
    let actor = claims.actor();

    let mut tx = begin_scoped(&state.pool, &Scope::Service("admin-trust"), &actor).await?;
    let stored = repo::latest_trust_artifacts(&mut tx).await?;

    let mut store = TrustStore::new(roots, state.roots.threshold);
    let mut seqs = MemSeq::default();
    // Replay what is already accepted, manifest first. A stored artifact that
    // no longer verifies (for example expired) is skipped, not fatal.
    for replay in [DocKind::Manifest, DocKind::Revocations, DocKind::Techlist] {
        if let Some((_, _, env)) = stored
            .iter()
            .find(|(k, _, _)| parse_kind(k) == Some(replay))
            && let Err(err) = apply(&mut store, replay, env, &mut seqs)
        {
            tracing::warn!(%err, kind = ?replay, "stored trust artifact did not replay");
        }
    }

    apply(&mut store, doc_kind, &body, &mut seqs)
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let seq = match doc_kind {
        DocKind::Manifest => store.manifest().map(|d| d.seq),
        DocKind::Revocations => store.revocations().map(|d| d.seq),
        DocKind::Techlist => store.techlist().map(|d| d.seq),
    }
    .ok_or(ApiError::Internal)?;
    let seq = i64::try_from(seq).map_err(|_| ApiError::Unprocessable("seq out of range".into()))?;
    let envelope =
        Envelope::from_bytes(&body).map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let content_id = envelope.content_id();

    let inserted =
        repo::put_trust_artifact(&mut tx, &kind, seq, &content_id, &body, &actor).await?;
    let detail: JsonValue = serde_json::json!({"seq": seq, "new": inserted});
    repo::insert_audit(
        &mut tx,
        &actor,
        "trust.upload",
        None,
        &format!("trust:{kind}"),
        &detail,
    )
    .await?;
    let agents = if inserted {
        active_agents(&mut tx).await?
    } else {
        Vec::new()
    };
    tx.commit().await?;
    if inserted {
        push_trust_update(&state, doc_kind, &body, &agents).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// How long a pushed `TrustUpdate` stays valid. Long, so an agent that is
/// offline when a technician is removed still applies the list on reconnect.
const TRUST_UPDATE_TTL_SECS: u64 = 24 * 3600;

/// `(agent_id, client_id)` of every active agent.
async fn active_agents(tx: &mut repo::Tx<'_>) -> Result<Vec<(Uuid, Uuid)>, ApiError> {
    let rows = sqlx::query("select id, client_id from tenant.agent where status = 'active'")
        .fetch_all(&mut **tx)
        .await
        .map_err(ApiError::internal)?;
    rows.iter()
        .map(|r| Ok((r.get("id"), r.get("client_id"))))
        .collect::<Result<_, sqlx::Error>>()
        .map_err(ApiError::internal)
}

/// Sign a `TrustUpdate` carrying the stored document for every active agent
/// and publish it on the agent's command subject, so running agents apply a new
/// technician list (and close the shells of removed technicians) without a
/// restart. Best effort: the artifact is already stored and enrolling agents
/// read it from their bundle, so a failure is logged, not returned.
async fn push_trust_update(
    state: &AppState,
    kind: DocKind,
    envelope: &[u8],
    agents: &[(Uuid, Uuid)],
) {
    let (Some(key), Some(nats)) = (state.command_key.as_deref(), state.nats.as_ref()) else {
        tracing::warn!("no command key or NATS client; trust update not pushed to agents");
        return;
    };
    let js = jetstream::new(nats.clone());
    let doc = Some(KeyBytes(envelope.to_vec()));
    let (manifest, revocations, techlist) = match kind {
        DocKind::Manifest => (doc, None, None),
        DocKind::Revocations => (None, doc, None),
        DocKind::Techlist => (None, None, doc),
    };
    let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
    for &(agent_id, client_id) in agents {
        let mut raw = [0u8; 16];
        if let Err(err) = rand::rngs::SysRng.try_fill_bytes(&mut raw) {
            tracing::error!(%err, "no randomness for a trust update");
            return;
        }
        let cmd = Command {
            cmd_id: KeyBytes(raw.to_vec()),
            agent_id: agent_id.to_string(),
            client_id: client_id.to_string(),
            issued_at: now,
            expires_at: now + TRUST_UPDATE_TTL_SECS,
            policy_hash: KeyBytes(vec![0; 32]),
            body: CommandBody::TrustUpdate {
                manifest: manifest.clone(),
                revocations: revocations.clone(),
                techlist: techlist.clone(),
            },
        };
        let signed = match sign_command(key, &cmd) {
            Ok(b) => b,
            Err(err) => {
                tracing::error!(?err, %agent_id, "cannot sign a trust update");
                continue;
            }
        };
        if let Err(err) = ensure_agent_consumer(&js, agent_id).await {
            tracing::error!(%err, %agent_id, "cannot ensure the agent command consumer");
            continue;
        }
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(
            async_nats::header::NATS_MESSAGE_ID,
            Uuid::from_bytes(raw).to_string(),
        );
        let sent = async {
            js.publish_with_headers(cmd_subject(agent_id), headers, signed.into())
                .await?
                .await
        }
        .await;
        if let Err(err) = sent {
            tracing::error!(%err, %agent_id, "trust update not published");
        }
    }
}
