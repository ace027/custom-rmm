//! Co-signed remote shell: the grant and open endpoints.
//!
//! A technician asks for a grant for one agent. The server builds a canonical
//! [`ShellGrant`] (bound to the agent, its client, the technician and one of
//! their hardware credentials), stores the session as `pending` and returns
//! the WebAuthn challenge `SHA-256("RMMSHELL1" || grant)`. The console has the
//! hardware key sign that challenge and posts the assertion to `open`. The API
//! pre-verifies the assertion (the agent verifies it again on its own), moves
//! the session to `opening` exactly once, signs a `ShellOpen` command with the
//! command key and publishes it on the agent's `CMD` subject. The browser then
//! connects to the relay with the single-use WebSocket ticket from `open`.

use std::collections::HashMap;

use async_nats::jetstream;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use rand::TryRng;
use rmm_db::repo::{self, Tx};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::shell::{self, NewShellSession};
use rmm_db::telemetry::agent_for_telemetry;
use rmm_proto::canonical::to_canonical_vec;
use rmm_proto::shell::MAX_DURATION_SECS;
use rmm_proto::subjects::sid_from_grant_id;
use rmm_trust::docs::{Command, CommandBody, ShellGrant, TrustManifest, decode_doc};
use rmm_trust::keys::{Bytes as KeyBytes, PublicKey};
use rmm_trust::store::{Clock, DocKind, SeqStore, TrustStore};
use rmm_trust::webauthn::{Assertion, Expected, parse_cose_key, shell_challenge, verify_assertion};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::chrono::Utc;
use utoipa::ToSchema;

use crate::actions::{COMMAND_TTL_SECS, cmd_subject, ensure_agent_consumer, sign_command};
use crate::auth::Claims;
use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// Session length when the request names none.
pub const DEFAULT_DURATION_SECS: u32 = 3600;
/// Seconds the technician has to open a fresh grant.
pub const OPEN_WINDOW_SECS: u64 = 60;
/// Validity of a WebSocket ticket in seconds.
pub const TICKET_TTL_SECS: i32 = 60;
/// Shells a grant may name; the agent maps them to the platform's shells.
pub const SHELLS: &[&str] = &["sh", "cmd", "powershell"];

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

/// The stored manifest, verified against the compiled roots.
async fn current_manifest(tx: &mut Tx<'_>, state: &AppState) -> Result<TrustManifest, ApiError> {
    let roots = state
        .roots
        .keys
        .iter()
        .map(PublicKey::from_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;
    let stored = repo::latest_trust_artifacts(tx).await?;
    let mut store = TrustStore::new(roots, state.roots.threshold);
    if let Some((_, _, env)) = stored.iter().find(|(k, _, _)| k == "manifest")
        && let Err(err) = store.apply_manifest(env, &SystemClock, &mut MemSeq::default())
    {
        tracing::warn!(%err, "stored manifest did not replay");
    }
    store
        .manifest()
        .cloned()
        .ok_or_else(|| ApiError::Unavailable("no valid trust manifest is installed".into()))
}

fn b64url(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

fn from_b64url(field: &str, s: &str) -> Result<Vec<u8>, ApiError> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.as_bytes())
        .map_err(|_| ApiError::BadRequest(format!("{field} is not unpadded base64url")))
}

fn random16() -> Result<[u8; 16], ApiError> {
    let mut raw = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut raw)
        .map_err(ApiError::internal)?;
    Ok(raw)
}

/// SHA-256 of a WebSocket ticket as presented by the browser.
pub fn ticket_hash(ticket: &str) -> [u8; 32] {
    Sha256::digest(ticket.as_bytes()).into()
}

/// Parse a session id (lowercase hex, 32 chars) or grant id (unpadded
/// base64url, 22 chars) into the 16 grant id bytes.
pub fn parse_grant_id(s: &str) -> Result<[u8; 16], ApiError> {
    let raw = if s.len() == 32 {
        data_encoding::HEXLOWER_PERMISSIVE.decode(s.as_bytes()).ok()
    } else {
        data_encoding::BASE64URL_NOPAD.decode(s.as_bytes()).ok()
    };
    raw.and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| ApiError::BadRequest("grant id must be 16 bytes".into()))
}

async fn technician_clients(tx: &mut Tx<'_>, tech: &str) -> Result<Vec<Uuid>, ApiError> {
    let rows = sqlx::query("select client_id from msp.technician_client where tech_id = $1")
        .bind(tech)
        .fetch_all(&mut **tx)
        .await?;
    rows.iter()
        .map(|r| r.try_get("client_id").map_err(ApiError::from))
        .collect()
}

/// Request for a shell grant.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    /// `sh`, `cmd` or `powershell`.
    pub shell: String,
    /// Longest session length in seconds (default 3600, at most 14400).
    #[serde(default)]
    pub max_duration_secs: Option<u32>,
    /// Credential that will co-sign. Required when the technician has more
    /// than one non-revoked credential.
    #[serde(default)]
    pub credential_id_b64url: Option<String>,
}

/// A grant waiting for its WebAuthn assertion.
#[derive(Debug, Serialize, ToSchema)]
pub struct GrantResponse {
    /// Grant id, unpadded base64url (16 bytes).
    pub grant_id_b64url: String,
    /// Canonical grant bytes, unpadded base64url.
    pub grant_cbor_b64url: String,
    /// WebAuthn challenge to sign, unpadded base64url.
    pub challenge_b64url: String,
    /// Relying party id for `navigator.credentials.get`.
    pub rp_id: String,
    /// Credential ids allowed to sign, unpadded base64url.
    pub allow_credentials: Vec<String>,
    /// Latest time the grant may be opened (unix seconds).
    pub open_by: u64,
}

/// Build and store a grant for `agent_id` on behalf of the calling technician.
pub async fn issue_grant(
    state: &AppState,
    claims: &Claims,
    agent_id: Uuid,
    req: &GrantRequest,
) -> Result<GrantResponse, ApiError> {
    let tech = claims.tech_id()?;
    if !SHELLS.contains(&req.shell.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "shell must be one of {}",
            SHELLS.join(", ")
        )));
    }
    let max_duration = req.max_duration_secs.unwrap_or(DEFAULT_DURATION_SECS);
    if max_duration == 0 || u64::from(max_duration) > MAX_DURATION_SECS {
        return Err(ApiError::BadRequest(format!(
            "max_duration_secs must be between 1 and {MAX_DURATION_SECS}"
        )));
    }
    let wanted_cred = req
        .credential_id_b64url
        .as_deref()
        .map(|c| from_b64url("credential_id_b64url", c))
        .transpose()?;
    let actor = claims.actor();

    let mut tx = begin_scoped(&state.pool, &Scope::Service("shell-grant"), &actor).await?;
    let agent = agent_for_telemetry(&mut tx, agent_id).await?;
    let clients = technician_clients(&mut tx, tech).await?;
    let creds = shell::list_credentials(&mut tx, tech).await?;
    drop(tx);
    // An unknown agent answers like an out-of-scope one: no existence oracle.
    let agent = agent.ok_or(ApiError::Forbidden)?;
    if creds.is_empty() || !clients.contains(&agent.client_id) {
        return Err(ApiError::Forbidden);
    }
    if agent.status != "active" {
        return Err(ApiError::Conflict("agent is not active".into()));
    }
    let cred = match (&wanted_cred, creds.as_slice()) {
        (Some(want), _) => creds.iter().find(|c| &c.cred_id == want),
        (None, [only]) => Some(only),
        (None, _) => {
            return Err(ApiError::BadRequest(
                "credential_id_b64url is required when several credentials are registered".into(),
            ));
        }
    }
    .ok_or_else(|| ApiError::BadRequest("unknown credential".into()))?;

    let mut tx = begin_scoped(&state.pool, &Scope::Clients(vec![agent.client_id]), &actor).await?;
    let manifest = current_manifest(&mut tx, state).await?;
    let grant_id = random16()?;
    let now = unix_now();
    let grant = ShellGrant {
        grant_id: KeyBytes(grant_id.to_vec()),
        agent_id: agent_id.to_string(),
        client_id: agent.client_id.to_string(),
        tech_id: tech.to_owned(),
        cred_id: KeyBytes(cred.cred_id.clone()),
        issued_at: now,
        open_by: now + OPEN_WINDOW_SECS,
        max_duration,
        shell: req.shell.clone(),
        record: true,
        e2e_pubkey: None,
    };
    grant.validate().map_err(ApiError::internal)?;
    let grant_cbor = to_canonical_vec(&grant).map_err(ApiError::internal)?;
    shell::insert_shell_session(
        &mut tx,
        NewShellSession {
            grant_id: grant_id.to_vec(),
            client_id: agent.client_id,
            agent_id,
            tech_id: tech.to_owned(),
            cred_id: cred.cred_id.clone(),
            shell: req.shell.clone(),
            max_duration: i32::try_from(max_duration).map_err(ApiError::internal)?,
            grant_cbor: grant_cbor.clone(),
        },
    )
    .await?;
    repo::insert_audit(
        &mut tx,
        &actor,
        "shell.grant",
        Some(agent.client_id),
        &format!("agent:{agent_id}"),
        &serde_json::json!({
            "session_id": sid_from_grant_id(&grant_id),
            "tech_id": tech,
            "shell": req.shell,
            "max_duration": max_duration,
        }),
    )
    .await?;
    tx.commit().await?;

    Ok(GrantResponse {
        grant_id_b64url: b64url(&grant_id),
        grant_cbor_b64url: b64url(&grant_cbor),
        challenge_b64url: b64url(&shell_challenge(&grant_cbor)),
        rp_id: manifest.console_rp_id,
        allow_credentials: vec![b64url(&cred.cred_id)],
        open_by: grant.open_by,
    })
}

/// Ask for a shell grant on an agent.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{agent_id}/shell",
    params(("agent_id" = String, Path, description = "Agent id")),
    request_body = GrantRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Grant stored; sign the challenge with the hardware key", body = GrantResponse),
        (status = 400, description = "Invalid shell, duration or credential", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "No registered credential, or the agent is outside the technician's clients", body = ErrorBody),
        (status = 409, description = "Agent is not active", body = ErrorBody),
        (status = 503, description = "No trust manifest installed", body = ErrorBody)
    )
)]
pub async fn create_grant(
    State(state): State<AppState>,
    claims: Claims,
    Path(agent_id): Path<Uuid>,
    Json(req): Json<GrantRequest>,
) -> Result<(StatusCode, Json<GrantResponse>), ApiError> {
    let resp = issue_grant(&state, &claims, agent_id, &req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

/// The authenticator's response to `navigator.credentials.get`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenRequest {
    /// `rawId` of the credential that signed, unpadded base64url.
    pub credential_id_b64url: String,
    /// `response.authenticatorData`, unpadded base64url.
    pub authenticator_data_b64url: String,
    /// `response.clientDataJSON`, unpadded base64url.
    pub client_data_json_b64url: String,
    /// `response.signature`, unpadded base64url.
    pub signature_b64url: String,
}

/// A session that was handed to the agent.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpenResponse {
    /// Session id (the grant id as lowercase hex).
    pub session_id: String,
    /// Single-use WebSocket ticket (60 s).
    pub ws_ticket: String,
    /// Relay path including the ticket; connect with `wss://<api host><ws_url>`.
    pub ws_url: String,
}

/// What [`open_session`] produced.
#[derive(Debug)]
pub struct Opened {
    /// Session id.
    pub session_id: String,
    /// WebSocket ticket.
    pub ticket: String,
    /// The signed `ShellOpen` command envelope as published.
    pub command: Vec<u8>,
}

/// Verify the assertion and hand the session to the agent (once).
pub async fn open_session(
    state: &AppState,
    claims: &Claims,
    grant_id: &[u8; 16],
    req: &OpenRequest,
) -> Result<Opened, ApiError> {
    let tech = claims.tech_id()?;
    let actor = claims.actor();
    let cred_id = from_b64url("credential_id_b64url", &req.credential_id_b64url)?;
    let assertion = Assertion {
        authenticator_data: from_b64url(
            "authenticator_data_b64url",
            &req.authenticator_data_b64url,
        )?,
        client_data_json: from_b64url("client_data_json_b64url", &req.client_data_json_b64url)?,
        signature: from_b64url("signature_b64url", &req.signature_b64url)?,
    };
    let key = state
        .command_key
        .as_deref()
        .ok_or_else(|| ApiError::Unavailable("command signing key is not configured".into()))?;

    // Which client owns the session? Only the grant's technician may see it.
    let mut tx = begin_scoped(&state.pool, &Scope::Service("shell-open"), &actor).await?;
    let found = shell::shell_session(&mut tx, grant_id).await?;
    drop(tx);
    let client_id = found
        .filter(|s| s.tech_id == tech)
        .map(|s| s.client_id)
        .ok_or_else(|| ApiError::NotFound("unknown shell grant".into()))?;

    let mut tx = begin_scoped(&state.pool, &Scope::Clients(vec![client_id]), &actor).await?;
    let row = shell::shell_session(&mut tx, grant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("unknown shell grant".into()))?;
    if row.status != "pending" {
        return Err(ApiError::Conflict("grant was already used".into()));
    }
    let grant: ShellGrant = decode_doc(&row.grant_cbor).map_err(ApiError::internal)?;
    let now = unix_now();
    if now >= grant.open_by {
        shell::update_shell_status(&mut tx, grant_id, &["pending"], "expired", Some("open_by"))
            .await?;
        tx.commit().await?;
        return Err(ApiError::Gone("grant expired before it was opened".into()));
    }
    if cred_id != row.cred_id {
        return Err(ApiError::BadRequest(
            "assertion is not from the credential named in the grant".into(),
        ));
    }
    let cred = shell::credential(&mut tx, &row.cred_id)
        .await?
        .filter(|c| c.revoked_at.is_none() && c.tech_id == tech)
        .ok_or(ApiError::Forbidden)?;
    let manifest = current_manifest(&mut tx, state).await?;
    let cose = parse_cose_key(&cred.cose_pubkey).map_err(ApiError::internal)?;
    let expected = Expected {
        challenge: shell_challenge(&row.grant_cbor),
        rp_id: &manifest.console_rp_id,
        origins: &manifest.console_origins,
        require_uv: true,
    };
    if let Err(err) = verify_assertion(&assertion, &expected, &cose) {
        tracing::warn!(tech_id = tech, %err, "shell assertion rejected");
        repo::insert_audit(
            &mut tx,
            &actor,
            "shell.assertion_rejected",
            Some(row.client_id),
            &format!("agent:{}", row.agent_id),
            &serde_json::json!({"session_id": sid_from_grant_id(grant_id), "reason": err.to_string()}),
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::BadRequest(format!("assertion rejected: {err}")));
    }

    // Single use: only one caller moves pending -> opening.
    if !shell::update_shell_status(&mut tx, grant_id, &["pending"], "opening", None).await? {
        return Err(ApiError::Conflict("grant was already used".into()));
    }

    let cmd_id = random16()?;
    let policy_hash: [u8; 32] =
        Sha256::digest(to_canonical_vec(&manifest.capability_ceiling).map_err(ApiError::internal)?)
            .into();
    let cmd = Command {
        cmd_id: KeyBytes(cmd_id.to_vec()),
        agent_id: row.agent_id.to_string(),
        client_id: row.client_id.to_string(),
        issued_at: now,
        // The command lapses with the grant: an agent that was offline when
        // the grant was opened rejects it as expired when it comes back.
        expires_at: grant.open_by.min(now + COMMAND_TTL_SECS),
        policy_hash: KeyBytes(policy_hash.to_vec()),
        body: CommandBody::ShellOpen {
            grant: KeyBytes(row.grant_cbor.clone()),
            assertion: KeyBytes(to_canonical_vec(&assertion).map_err(ApiError::internal)?),
        },
    };
    let command = sign_command(key, &cmd)?;

    let mut raw = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut raw)
        .map_err(ApiError::internal)?;
    let ticket = b64url(&raw);
    shell::insert_ws_ticket(
        &mut tx,
        &ticket_hash(&ticket),
        row.client_id,
        grant_id,
        TICKET_TTL_SECS,
    )
    .await?;
    repo::insert_audit(
        &mut tx,
        &actor,
        "shell.open",
        Some(row.client_id),
        &format!("agent:{}", row.agent_id),
        &serde_json::json!({
            "session_id": sid_from_grant_id(grant_id),
            "tech_id": tech,
            "shell": row.shell,
            "cmd_id": data_encoding::HEXLOWER.encode(&cmd_id),
        }),
    )
    .await?;

    // Publish before committing so a failed publish leaves the grant pending.
    if let Some(client) = &state.nats {
        let js = jetstream::new(client.clone());
        ensure_agent_consumer(&js, row.agent_id).await.map_err(|err| {
            tracing::error!(%err, agent_id = %row.agent_id, "cannot ensure the agent command consumer");
            ApiError::Unavailable("command stream is unavailable".into())
        })?;
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(
            async_nats::header::NATS_MESSAGE_ID,
            data_encoding::HEXLOWER.encode(&cmd_id),
        );
        let published = async {
            js.publish_with_headers(cmd_subject(row.agent_id), headers, command.clone().into())
                .await?
                .await
        }
        .await;
        if let Err(err) = published {
            tracing::error!(%err, agent_id = %row.agent_id, "shell open not published");
            return Err(ApiError::Unavailable(
                "command could not be published".into(),
            ));
        }
    } else {
        tracing::warn!("no NATS client configured; shell open recorded but not published");
    }
    tx.commit().await?;

    let session_id = sid_from_grant_id(grant_id);
    Ok(Opened {
        session_id,
        ticket,
        command,
    })
}

/// Open a granted shell with the hardware key's assertion.
#[utoipa::path(
    post,
    path = "/api/v1/shell-sessions/{grant_id}/open",
    params(("grant_id" = String, Path, description = "Grant id (unpadded base64url) or session id (hex)")),
    request_body = OpenRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "ShellOpen published; connect the relay", body = OpenResponse),
        (status = 400, description = "Malformed request or assertion rejected", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Credential revoked", body = ErrorBody),
        (status = 404, description = "Unknown grant (or not the caller's)", body = ErrorBody),
        (status = 409, description = "Grant already used", body = ErrorBody),
        (status = 410, description = "Grant expired before it was opened", body = ErrorBody),
        (status = 503, description = "Command key, manifest or command stream unavailable", body = ErrorBody)
    )
)]
pub async fn open_shell(
    State(state): State<AppState>,
    claims: Claims,
    Path(grant_id): Path<String>,
    Json(req): Json<OpenRequest>,
) -> Result<Json<OpenResponse>, ApiError> {
    let grant_id = parse_grant_id(&grant_id)?;
    let opened = open_session(&state, &claims, &grant_id, &req).await?;
    let ws_url = format!(
        "/api/v1/shell-sessions/{}/ws?ticket={}",
        opened.session_id, opened.ticket
    );
    Ok(Json(OpenResponse {
        session_id: opened.session_id,
        ws_ticket: opened.ticket,
        ws_url,
    }))
}
