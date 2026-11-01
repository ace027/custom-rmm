//! Catalog upload, signed command issuing and action run status.
//!
//! The server can only invoke a definition that carries a valid catalog
//! signature and is not revoked: uploads are verified against the stored
//! trust artifacts, and so is every issue. Commands are signed with the
//! server command key and published to the target agent's own JetStream
//! consumer on the `CMD` stream.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_nats::jetstream::{self, consumer, stream};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use ed25519_dalek::{Signer, SigningKey};
use rand::TryRng;
use rmm_db::actions::{self, NewActionRun};
use rmm_db::repo::{self, Tx};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::telemetry::agent_for_telemetry;
use rmm_proto::canonical::to_canonical_vec;
use rmm_recipe::definition::{Definition, TYPE_DEFINITION};
use rmm_recipe::validate::{BLOCKS, validate_definition, validate_params};
use rmm_trust::docs::{Command, CommandBody, Role};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_COMMAND, signing_message,
};
use rmm_trust::keys::{Bytes as KeyBytes, PublicKey, Sig64};
use rmm_trust::store::{Clock, DocKind, SeqStore, TrustStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};
use utoipa::ToSchema;

use crate::auth::{Admin, RequireRole};
use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// JetStream stream carrying signed commands.
pub const CMD_STREAM: &str = "CMD";
/// How long an issued command stays valid.
pub const COMMAND_TTL_SECS: u64 = 600;
/// Most delivery attempts for one command to one agent.
const MAX_DELIVER: i64 = 5;

/// Subject a command for `agent_id` is published on.
pub fn cmd_subject(agent_id: Uuid) -> String {
    format!("agent.{agent_id}.cmd")
}

/// Name of the agent's durable pull consumer on the `CMD` stream.
pub fn consumer_name(agent_id: Uuid) -> String {
    format!("agent_{agent_id}")
}

/// Create the `CMD` stream if needed and create or update the durable pull
/// consumer `agent_<agent_id>` filtered to the agent's own command subject.
pub async fn ensure_agent_consumer(
    js: &jetstream::Context,
    agent_id: Uuid,
) -> Result<(), async_nats::Error> {
    let stream = js
        .get_or_create_stream(stream::Config {
            name: CMD_STREAM.to_owned(),
            subjects: vec!["agent.*.cmd".to_owned()],
            storage: stream::StorageType::File,
            max_age: Duration::from_secs(7 * 24 * 3600),
            duplicate_window: Duration::from_secs(600),
            ..Default::default()
        })
        .await?;
    stream
        .create_consumer(consumer::pull::Config {
            durable_name: Some(consumer_name(agent_id)),
            filter_subject: cmd_subject(agent_id),
            ack_policy: consumer::AckPolicy::Explicit,
            max_deliver: MAX_DELIVER,
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn unix_now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        unix_now()
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

/// Rebuild the trust store from the stored artifacts (manifest first). An
/// artifact that no longer verifies is skipped, so an expired revocation list
/// simply is not applied.
async fn load_trust(tx: &mut Tx<'_>, state: &AppState) -> Result<TrustStore, ApiError> {
    let roots = state
        .roots
        .keys
        .iter()
        .map(PublicKey::from_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;
    let stored = repo::latest_trust_artifacts(tx).await?;
    let mut store = TrustStore::new(roots, state.roots.threshold);
    let mut seqs = MemSeq::default();
    let find = |kind: &str| stored.iter().find(|(k, _, _)| k == kind);
    if let Some((_, _, env)) = find("manifest")
        && let Err(err) = store.apply_manifest(env, &SystemClock, &mut seqs)
    {
        tracing::warn!(%err, "stored manifest did not replay");
    }
    if let Some((_, _, env)) = find("revocations")
        && let Err(err) = store.apply_revocations(env, &SystemClock, &mut seqs)
    {
        tracing::warn!(%err, "stored revocations did not replay");
    }
    Ok(store)
}

fn unprocessable(msg: impl std::fmt::Display) -> ApiError {
    ApiError::Unprocessable(msg.to_string())
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

fn is_revoked(store: &TrustStore, envelope_bytes: &[u8], content_id: &[u8; 32]) -> bool {
    let raw: [u8; 32] = Sha256::digest(envelope_bytes).into();
    store.is_artifact_revoked(content_id) || store.is_artifact_revoked(&raw)
}

/// Verify a definition envelope: type, catalog signature, strict decoding,
/// static validation and revocation. Returns the definition and its content id.
fn check_definition(store: &TrustStore, bytes: &[u8]) -> Result<(Definition, [u8; 32]), ApiError> {
    let env = Envelope::from_bytes(bytes).map_err(unprocessable)?;
    if env.r#type != TYPE_DEFINITION {
        return Err(unprocessable("not a definition envelope"));
    }
    store
        .verify_role(&env, Role::Catalog, unix_now())
        .map_err(|e| unprocessable(format!("catalog signature: {e}")))?;
    let def = Definition::from_envelope_payload(&env.payload.0).map_err(unprocessable)?;
    validate_definition(&def, BLOCKS).map_err(unprocessable)?;
    let content_id = env.content_id();
    if is_revoked(store, bytes, &content_id) {
        return Err(unprocessable("definition is revoked"));
    }
    Ok((def, content_id))
}

/// A stored catalog definition.
#[derive(Debug, Serialize, ToSchema)]
pub struct CatalogEntry {
    /// Hex SHA-256 of the definition payload.
    pub content_id: String,
    /// Dotted action name.
    pub id: String,
    /// Definition version.
    pub version: u32,
    /// Capability group.
    pub capability: String,
    /// False when the same definition was already stored.
    pub new: bool,
}

/// Verify and store a catalog-signed definition.
pub async fn store_definition(
    state: &AppState,
    scope: &Scope,
    actor: &str,
    body: &[u8],
) -> Result<CatalogEntry, ApiError> {
    let mut tx = begin_scoped(&state.pool, scope, actor).await?;
    let store = load_trust(&mut tx, state).await?;
    let (def, content_id) = check_definition(&store, body)?;
    let version = i32::try_from(def.version).map_err(|_| unprocessable("version out of range"))?;
    let new = actions::put_definition(
        &mut tx,
        &content_id,
        &def.id,
        version,
        &def.capability,
        body,
        actor,
    )
    .await?;
    repo::insert_audit(
        &mut tx,
        actor,
        "catalog.upload",
        None,
        &format!("definition:{}", hex(&content_id)),
        &serde_json::json!({"id": def.id, "version": def.version, "new": new}),
    )
    .await?;
    tx.commit().await?;
    Ok(CatalogEntry {
        content_id: hex(&content_id),
        id: def.id,
        version: def.version,
        capability: def.capability,
        new,
    })
}

/// Upload a catalog-signed definition envelope.
#[utoipa::path(
    put,
    path = "/api/v1/catalog",
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Definition stored", body = CatalogEntry),
        (status = 200, description = "Definition already stored", body = CatalogEntry),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 422, description = "Not catalog-signed, invalid or revoked", body = ErrorBody)
    )
)]
pub async fn put_catalog(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    body: Bytes,
) -> Result<(StatusCode, Json<CatalogEntry>), ApiError> {
    let entry = store_definition(
        &state,
        &Scope::Service("admin-catalog"),
        &claims.actor(),
        &body,
    )
    .await?;
    let status = if entry.new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(entry)))
}

/// Request to invoke a catalog definition on one agent.
#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueRequest {
    /// Hex content id of an uploaded definition.
    pub definition_content_id: String,
    /// Parameters, validated against the definition.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub params: JsonValue,
}

/// An accepted command.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssueResponse {
    /// Command id; poll `/api/v1/action-runs/{cmd_id}`.
    #[schema(value_type = String)]
    pub cmd_id: Uuid,
}

/// A signed command that was recorded.
#[derive(Debug)]
pub struct Issued {
    /// Command id (also the action run id).
    pub cmd_id: Uuid,
    /// The signed command envelope as published.
    pub command: Vec<u8>,
}

/// Sign `cmd` into an `rmm.command/1` envelope with `key`.
pub fn sign_command(key: &SigningKey, cmd: &Command) -> Result<Vec<u8>, ApiError> {
    let payload = to_canonical_vec(cmd).map_err(ApiError::internal)?;
    let msg = signing_message(TYPE_COMMAND, &payload);
    let public =
        PublicKey::from_bytes(&key.verifying_key().to_bytes()).map_err(ApiError::internal)?;
    let env = Envelope {
        v: ENVELOPE_VERSION,
        r#type: TYPE_COMMAND.to_owned(),
        payload: KeyBytes(payload),
        sigs: vec![SigEntry {
            key_id: public.key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(key.sign(&msg).to_bytes()),
        }],
    };
    env.to_bytes().map_err(ApiError::internal)
}

fn command_key(state: &AppState) -> Result<&SigningKey, ApiError> {
    match &state.command_key {
        Some(k) => Ok(k),
        None => {
            if !state.command_key_warned.swap(true, Ordering::Relaxed) {
                tracing::error!("RMM_COMMAND_KEY_FILE is not usable; commands cannot be issued");
            }
            Err(ApiError::Unavailable(
                "command signing key is not configured".into(),
            ))
        }
    }
}

/// Validate, sign, record and publish a command that invokes a definition on
/// an agent. Without a NATS client the publish step is skipped.
pub async fn issue_command(
    state: &AppState,
    scope: &Scope,
    actor: &str,
    agent_id: Uuid,
    req: &IssueRequest,
) -> Result<Issued, ApiError> {
    let key = command_key(state)?;
    let content_id = data_encoding::HEXLOWER_PERMISSIVE
        .decode(req.definition_content_id.as_bytes())
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| unprocessable("definition_content_id must be 32 bytes of hex"))?;

    let mut tx = begin_scoped(&state.pool, scope, actor).await?;
    let agent = agent_for_telemetry(&mut tx, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("unknown agent".into()))?;
    if agent.status != "active" {
        return Err(ApiError::Conflict("agent is not active".into()));
    }
    let row = actions::definition_by_content_id(&mut tx, &content_id)
        .await?
        .ok_or_else(|| unprocessable("unknown definition"))?;
    let store = load_trust(&mut tx, state).await?;
    let (def, _) = check_definition(&store, &row.envelope)?;
    let manifest = store
        .manifest()
        .ok_or_else(|| unprocessable("no trusted manifest is stored"))?;
    if !manifest.capability_ceiling.contains(&def.capability) {
        return Err(unprocessable("capability is outside the signed ceiling"));
    }
    if !req.params.is_null() && !req.params.is_object() {
        return Err(unprocessable("params must be an object"));
    }
    let params_json = if req.params.is_null() {
        JsonValue::Object(Default::default())
    } else {
        req.params.clone()
    };
    let params = serde_json::from_value(params_json.clone())
        .map_err(|e| unprocessable(format!("params: {e}")))?;
    validate_params(&def, &params).map_err(unprocessable)?;

    let mut raw = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut raw)
        .map_err(ApiError::internal)?;
    let cmd_id = Uuid::from_bytes(raw);
    let policy_hash: [u8; 32] =
        Sha256::digest(to_canonical_vec(&manifest.capability_ceiling).map_err(ApiError::internal)?)
            .into();
    let now = unix_now();
    let cmd = Command {
        cmd_id: KeyBytes(raw.to_vec()),
        agent_id: agent.agent_id.to_string(),
        client_id: agent.client_id.to_string(),
        issued_at: now,
        expires_at: now + COMMAND_TTL_SECS,
        policy_hash: KeyBytes(policy_hash.to_vec()),
        body: CommandBody::Invoke {
            definition: KeyBytes(row.envelope.clone()),
            params,
        },
    };
    let command = sign_command(key, &cmd)?;

    let js = state.nats.as_ref().map(|c| jetstream::new(c.clone()));
    if let Some(js) = &js {
        ensure_agent_consumer(js, agent_id).await.map_err(|err| {
            tracing::error!(%err, %agent_id, "cannot ensure the agent command consumer");
            ApiError::Unavailable("command stream is unavailable".into())
        })?;
    } else {
        tracing::warn!("no NATS client configured; command recorded but not published");
    }

    actions::insert_action_run(
        &mut tx,
        NewActionRun {
            cmd_id,
            client_id: agent.client_id,
            agent_id,
            device_id: agent.device_id,
            definition_content_id: content_id.clone(),
            params: params_json,
            requested_by: actor.to_owned(),
        },
    )
    .await?;
    repo::insert_audit(
        &mut tx,
        actor,
        "action.issue",
        Some(agent.client_id),
        &format!("agent:{agent_id}"),
        &serde_json::json!({
            "cmd_id": cmd_id,
            "definition": def.id,
            "version": def.version,
            "definition_content_id": hex(&content_id),
        }),
    )
    .await?;
    // Publish before committing so a failed publish leaves no orphan `queued` run.
    if let Some(js) = &js {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(async_nats::header::NATS_MESSAGE_ID, cmd_id.to_string());
        let published = async {
            js.publish_with_headers(cmd_subject(agent_id), headers, command.clone().into())
                .await?
                .await
        }
        .await;
        if let Err(err) = published {
            // Dropping `tx` rolls the run back: no row is left `queued` for a
            // command that was never published.
            tracing::error!(%err, %cmd_id, %agent_id, "command not published; run rolled back");
            return Err(ApiError::Unavailable(
                "command could not be published".into(),
            ));
        }
    }
    tx.commit().await?;
    Ok(Issued { cmd_id, command })
}

/// Invoke a catalog definition on an agent.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{agent_id}/actions",
    params(("agent_id" = String, Path, description = "Agent id")),
    request_body = IssueRequest,
    security(("bearer" = [])),
    responses(
        (status = 202, description = "Command signed, recorded and published", body = IssueResponse),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 404, description = "Unknown agent", body = ErrorBody),
        (status = 409, description = "Agent is not active", body = ErrorBody),
        (status = 422, description = "Unknown definition or invalid parameters", body = ErrorBody),
        (status = 503, description = "Command key missing or command not published", body = ErrorBody)
    )
)]
pub async fn issue_action(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    Path(agent_id): Path<Uuid>,
    Json(req): Json<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), ApiError> {
    let issued = issue_command(
        &state,
        &Scope::Service("admin-actions"),
        &claims.actor(),
        agent_id,
        &req,
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(IssueResponse {
            cmd_id: issued.cmd_id,
        }),
    ))
}

/// State of an action run.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActionRunResponse {
    /// Command id.
    #[schema(value_type = String)]
    pub cmd_id: Uuid,
    /// `queued`, `succeeded`, `failed`, `rolled_back`, `rejected` or `expired`.
    pub status: String,
    /// Rejection reason, when rejected.
    pub reason: Option<String>,
    /// Per-stage outcomes reported by the agent.
    #[schema(value_type = Object)]
    pub stages: JsonValue,
    /// Creation time (RFC 3339).
    pub created_at: String,
    /// Completion time (RFC 3339), once the agent reported.
    pub finished_at: Option<String>,
}

/// The run `cmd_id` if it is visible to `scope`.
pub async fn read_run(
    state: &AppState,
    scope: &Scope,
    actor: &str,
    cmd_id: Uuid,
) -> Result<ActionRunResponse, ApiError> {
    let mut tx = begin_scoped(&state.pool, scope, actor).await?;
    let run = actions::action_run(&mut tx, cmd_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("unknown action run".into()))?;
    let rfc = |t: DateTime<Utc>| t.to_rfc3339();
    // A run still `queued` past its command TTL can no longer be executed (the
    // agent rejects expired commands), so report it as `expired`.
    let ttl = i64::try_from(COMMAND_TTL_SECS).unwrap_or(i64::MAX);
    let status = if run.status == "queued"
        && Utc::now().timestamp() > run.created_at.timestamp().saturating_add(ttl)
    {
        "expired".to_owned()
    } else {
        run.status
    };
    Ok(ActionRunResponse {
        cmd_id: run.cmd_id,
        status,
        reason: run.reason,
        stages: run.stages,
        created_at: rfc(run.created_at),
        finished_at: run.finished_at.map(rfc),
    })
}

/// Read an action run.
#[utoipa::path(
    get,
    path = "/api/v1/action-runs/{cmd_id}",
    params(("cmd_id" = String, Path, description = "Command id")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The run", body = ActionRunResponse),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody),
        (status = 404, description = "Unknown run", body = ErrorBody)
    )
)]
pub async fn get_action_run(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
    Path(cmd_id): Path<Uuid>,
) -> Result<Json<ActionRunResponse>, ApiError> {
    read_run(
        &state,
        &Scope::Service("admin-actions"),
        &claims.actor(),
        cmd_id,
    )
    .await
    .map(Json)
}
