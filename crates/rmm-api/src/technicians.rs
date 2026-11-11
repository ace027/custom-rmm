//! Technician WebAuthn credential registration (hardware authenticators only)
//! and the technician list draft that rmm-sign signs offline.
//!
//! Registration takes two steps. `begin` stores a random single-use challenge
//! (5 minutes) for the calling technician; `finish` consumes it, whatever the
//! outcome, then verifies the packed attestation against the configured
//! attestation roots and AAGUID allowlist (see [`crate::attestation`]). The
//! relying party id and origins come from the installed, root-verified trust
//! manifest, the same values agents use to verify shell assertions.

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use rand::TryRng;
use rmm_db::repo::{self, Tx};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::shell::{self, NewCredential};
use rmm_trust::docs::{Credential, Technician, TechnicianList, TrustManifest};
use rmm_trust::keys::{Bytes as KeyBytes, PublicKey};
use rmm_trust::store::{Clock, DocKind, SeqStore, TrustStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::types::Uuid;
use sqlx::types::chrono::Utc;
use utoipa::ToSchema;

use crate::attestation::{AttestationConfig, verify_registration};
use crate::auth::{Admin, Claims, RequireRole};
use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// How long a registration challenge stays usable.
pub const CHALLENGE_TTL_SECS: i32 = 300;
/// Challenge purpose for credential registration.
pub const PURPOSE_REGISTER: &str = "register";
/// Validity window of an exported techlist draft.
pub const TECHLIST_DRAFT_VALIDITY_SECS: u64 = 30 * 86_400;
/// Permissions granted to every technician in the draft.
pub const DRAFT_PERMS: &[&str] = &["shell"];

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

fn attestation(state: &AppState) -> Result<&AttestationConfig, ApiError> {
    state.attestation.as_deref().ok_or_else(|| {
        ApiError::Unavailable(
            "hardware attestation roots and AAGUID allowlist are not configured".into(),
        )
    })
}

fn b64url(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

fn from_b64url(field: &str, s: &str) -> Result<Vec<u8>, ApiError> {
    data_encoding::BASE64URL_NOPAD
        .decode(s.as_bytes())
        .map_err(|_| ApiError::BadRequest(format!("{field} is not unpadded base64url")))
}

/// Opaque WebAuthn user handle for a technician (no PII on the key).
pub fn user_handle(tech_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"rmm-webauthn-user:");
    h.update(tech_id.as_bytes());
    h.finalize().into()
}

/// `authenticatorSelection` of the creation options.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthenticatorSelection {
    /// Always `required`.
    pub user_verification: String,
    /// Always `discouraged`.
    pub resident_key: String,
}

/// Options for `navigator.credentials.create`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterBeginResponse {
    /// Pass back to `finish`.
    #[schema(value_type = String)]
    pub challenge_id: Uuid,
    /// The challenge, unpadded base64url.
    pub challenge_b64url: String,
    /// Relying party id (the manifest's `console_rp_id`).
    pub rp_id: String,
    /// User handle, unpadded base64url.
    pub user_id_b64url: String,
    /// User name (the technician id).
    pub user_name: String,
    /// User display name.
    pub user_display_name: String,
    /// Timeout in milliseconds.
    pub timeout_ms: u32,
    /// Always `direct`.
    pub attestation: String,
    /// Authenticator requirements.
    pub authenticator_selection: AuthenticatorSelection,
    /// COSE algorithms: -7 (ES256), -8 (EdDSA).
    pub pub_key_cred_params: Vec<i32>,
    /// Credentials already registered by this technician, unpadded base64url.
    pub exclude_credentials_b64url: Vec<String>,
}

/// Start registering a hardware credential for the calling technician.
#[utoipa::path(
    post,
    path = "/api/v1/technicians/me/credentials/register/begin",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Creation options", body = RegisterBeginResponse),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 503, description = "Attestation or trust manifest not configured", body = ErrorBody)
    )
)]
pub async fn register_begin(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<RegisterBeginResponse>, ApiError> {
    attestation(&state)?;
    let tech = claims.tech_id()?;
    let mut challenge = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut challenge)
        .map_err(ApiError::internal)?;

    let mut tx = begin_scoped(&state.pool, &Scope::Clients(vec![]), &claims.actor()).await?;
    let manifest = current_manifest(&mut tx, &state).await?;
    shell::upsert_technician(&mut tx, tech, &claims.name).await?;
    let challenge_id = shell::insert_challenge(
        &mut tx,
        tech,
        &challenge,
        PURPOSE_REGISTER,
        CHALLENGE_TTL_SECS,
    )
    .await?;
    let existing = shell::list_credentials(&mut tx, tech).await?;
    tx.commit().await?;

    Ok(Json(RegisterBeginResponse {
        challenge_id,
        challenge_b64url: b64url(&challenge),
        rp_id: manifest.console_rp_id,
        user_id_b64url: b64url(&user_handle(tech)),
        user_name: tech.to_owned(),
        user_display_name: claims.name.clone(),
        timeout_ms: u32::try_from(CHALLENGE_TTL_SECS).unwrap_or(300) * 1000,
        attestation: "direct".into(),
        authenticator_selection: AuthenticatorSelection {
            user_verification: "required".into(),
            resident_key: "discouraged".into(),
        },
        pub_key_cred_params: vec![-7, -8],
        exclude_credentials_b64url: existing.iter().map(|c| b64url(&c.cred_id)).collect(),
    }))
}

/// The authenticator's response to `navigator.credentials.create`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishRequest {
    /// `challenge_id` from `begin`.
    #[schema(value_type = String)]
    pub challenge_id: Uuid,
    /// `response.attestationObject`, unpadded base64url.
    pub attestation_object_b64url: String,
    /// `response.clientDataJSON`, unpadded base64url.
    pub client_data_json_b64url: String,
}

/// A registered credential.
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterFinishResponse {
    /// Credential id, unpadded base64url.
    pub cred_id_b64url: String,
    /// Authenticator AAGUID, lowercase hex.
    pub aaguid_hex: String,
}

/// Finish registration: verify the hardware attestation and store the credential.
#[utoipa::path(
    post,
    path = "/api/v1/technicians/me/credentials/register/finish",
    request_body = RegisterFinishRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Credential registered", body = RegisterFinishResponse),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 409, description = "Credential id already registered", body = ErrorBody),
        (status = 422, description = "Challenge unusable or attestation rejected", body = ErrorBody),
        (status = 503, description = "Attestation or trust manifest not configured", body = ErrorBody)
    )
)]
pub async fn register_finish(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<(StatusCode, Json<RegisterFinishResponse>), ApiError> {
    let cfg = attestation(&state)?;
    let tech = claims.tech_id()?;
    let actor = claims.actor();
    let att_obj = from_b64url("attestation_object_b64url", &req.attestation_object_b64url)?;
    let client_data = from_b64url("client_data_json_b64url", &req.client_data_json_b64url)?;

    // Burn the challenge first and commit, so a failed attempt cannot retry it.
    let mut tx = begin_scoped(&state.pool, &Scope::Clients(vec![]), &actor).await?;
    let manifest = current_manifest(&mut tx, &state).await?;
    let challenge = shell::consume_challenge(&mut tx, req.challenge_id, tech, PURPOSE_REGISTER)
        .await?
        .ok_or_else(|| {
            ApiError::Unprocessable("challenge is unknown, already used or expired".into())
        })?;
    tx.commit().await?;

    let cred = match verify_registration(
        &att_obj,
        &client_data,
        &challenge,
        &manifest.console_rp_id,
        &manifest.console_origins,
        &cfg.roots,
        &cfg.aaguids,
    ) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(tech_id = tech, %err, "credential registration rejected");
            let mut tx = begin_scoped(&state.pool, &Scope::Clients(vec![]), &actor).await?;
            repo::insert_audit(
                &mut tx,
                &actor,
                "webauthn.register_rejected",
                None,
                &format!("technician:{tech}"),
                &serde_json::json!({"reason": err.to_string()}),
            )
            .await?;
            tx.commit().await?;
            return Err(ApiError::Unprocessable(err.to_string()));
        }
    };

    let aaguid_hex = data_encoding::HEXLOWER.encode(&cred.aaguid);
    let cred_b64 = b64url(&cred.cred_id);
    let mut tx = begin_scoped(&state.pool, &Scope::Clients(vec![]), &actor).await?;
    let new = shell::insert_credential(
        &mut tx,
        NewCredential {
            cred_id: cred.cred_id.clone(),
            tech_id: tech.to_owned(),
            alg: cred.alg,
            cose_pubkey: cred.cose_pubkey,
            aaguid: cred.aaguid.to_vec(),
            sign_count: i64::from(cred.sign_count),
            attestation_fmt: "packed".into(),
        },
    )
    .await?;
    if !new {
        return Err(ApiError::Conflict(
            "credential id is already registered".into(),
        ));
    }
    repo::insert_audit(
        &mut tx,
        &actor,
        "webauthn.register",
        None,
        &format!("technician:{tech}"),
        &serde_json::json!({"cred_id": cred_b64, "aaguid": aaguid_hex, "alg": cred.alg}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterFinishResponse {
            cred_id_b64url: cred_b64,
            aaguid_hex,
        }),
    ))
}

/// Build the technician list draft: every technician with a live credential.
pub async fn build_techlist_draft(tx: &mut Tx<'_>, now: u64) -> Result<TechnicianList, ApiError> {
    let last_seq = repo::latest_trust_artifacts(tx)
        .await?
        .into_iter()
        .find(|(k, _, _)| k == "techlist")
        .map_or(0, |(_, seq, _)| u64::try_from(seq).unwrap_or(0));
    let techs = shell::techlist_entries(tx)
        .await?
        .into_iter()
        .map(|t| Technician {
            tech_id: t.tech_id,
            client_scope: t.client_ids.iter().map(Uuid::to_string).collect(),
            perms: DRAFT_PERMS.iter().map(|p| (*p).to_owned()).collect(),
            creds: t
                .creds
                .into_iter()
                .map(|c| Credential {
                    cred_id: KeyBytes(c.cred_id),
                    alg: c.alg,
                    cose_pubkey: KeyBytes(c.cose_pubkey),
                    aaguid: KeyBytes(c.aaguid),
                })
                .collect(),
        })
        .collect();
    Ok(TechnicianList {
        seq: last_seq + 1,
        issued_at: now,
        expires_at: now + TECHLIST_DRAFT_VALIDITY_SECS,
        techs,
    })
}

/// Export the technician list draft for offline signing with
/// `rmm-sign sign --type techlist`. `seq` is the stored techlist's plus one,
/// `issued_at` is now and `expires_at` 30 days later; review them before
/// signing. A technician's `client_scope` lists the clients assigned in
/// `msp.technician_client` (empty means none).
#[utoipa::path(
    get,
    path = "/api/v1/admin/techlist-draft",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "TechnicianList JSON draft (byte fields as lowercase hex)", body = Object),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 403, description = "Missing RMM.Admin", body = ErrorBody)
    )
)]
pub async fn techlist_draft(
    State(state): State<AppState>,
    RequireRole(claims, _): RequireRole<Admin>,
) -> Result<Json<TechnicianList>, ApiError> {
    let mut tx = begin_scoped(
        &state.pool,
        &Scope::Service("admin-techlist"),
        &claims.actor(),
    )
    .await?;
    let draft = build_techlist_draft(&mut tx, unix_now()).await?;
    tx.commit().await?;
    Ok(Json(draft))
}
