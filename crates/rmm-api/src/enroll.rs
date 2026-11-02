//! `POST /v1/enroll`: token + proof-of-possession enrollment and the
//! reattach/clone rules.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use ed25519_dalek::{Signature, VerifyingKey};
use rmm_db::repo::{self, DeviceMatch, NewAgent, NewDevice, TokenRow};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_proto::enroll::{EnrollRequest, EnrollResponse, FpStrength, TrustBundle, fingerprint};
use sha2::{Digest, Sha256};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};

use crate::state::AppState;
use crate::{ApiError, ErrorBody};

/// Largest accepted request body.
pub const MAX_BODY: usize = 16 * 1024;
/// Allowed clock difference between agent and server.
pub const MAX_SKEW_SECS: u64 = 300;
/// An agent seen more recently than this is assumed to still be alive.
pub const RECENT_HOURS: i64 = 24;

/// What to do with the device record for a new enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachDecision {
    /// Brand new device.
    New,
    /// Attach to the existing device, superseding its old agent.
    Reattach {
        /// Existing device.
        device_id: Uuid,
        /// Agent to supersede, if one is live.
        old_agent_id: Option<Uuid>,
    },
    /// New device held for review: the old one may still be running.
    PendingReview {
        /// Device this may be a clone of.
        possible_clone_of: Uuid,
    },
    /// New device flagged because the fingerprint exists in another client.
    NewFlagged {
        /// Device in the other client.
        possible_clone_of: Uuid,
    },
}

/// Choose how to attach an enrollment. Pure.
///
/// A weak fingerprint never matches. Only `active` devices in the token's
/// client can be reattached: one is reattached when the token allows it and
/// its agent has not been seen for 24 hours (or was never seen) and is not
/// revoked or held as a clone; any other active match makes the new device
/// wait for review. Same-client devices already `flagged` or `pending_review`
/// are never reattached; when they are the only same-client matches, the new
/// device also waits for review. A match in another client is never reattached.
pub fn decide(
    matches: &[DeviceMatch],
    token: &TokenRow,
    fp_strength: FpStrength,
    now: DateTime<Utc>,
) -> AttachDecision {
    if fp_strength != FpStrength::Strong {
        return AttachDecision::New;
    }
    let recent_cutoff = now.timestamp() - RECENT_HOURS * 3600;
    let same_client = || matches.iter().filter(|m| m.client_id == token.client_id);
    let mut reattach: Option<AttachDecision> = None;
    for m in same_client().filter(|m| m.device_status == "active") {
        let recent = m.last_seen.is_some_and(|t| t.timestamp() > recent_cutoff);
        let held = matches!(m.agent_status.as_deref(), Some("revoked" | "suspect_clone"));
        if recent || held || !token.allow_reattach {
            return AttachDecision::PendingReview {
                possible_clone_of: m.device_id,
            };
        }
        if reattach.is_none() {
            reattach = Some(AttachDecision::Reattach {
                device_id: m.device_id,
                old_agent_id: m.agent_id,
            });
        }
    }
    if let Some(r) = reattach {
        return r;
    }
    if let Some(m) = same_client().next() {
        return AttachDecision::PendingReview {
            possible_clone_of: m.device_id,
        };
    }
    match matches.iter().find(|m| m.client_id != token.client_id) {
        Some(m) => AttachDecision::NewFlagged {
            possible_clone_of: m.device_id,
        },
        None => AttachDecision::New,
    }
}

/// NATS public user nkey (`U...`) for a raw Ed25519 public key.
pub fn nkey_from_pubkey(pk: &[u8; 32]) -> String {
    const PREFIX_USER: u8 = 20 << 3;
    let mut raw = Vec::with_capacity(35);
    raw.push(PREFIX_USER);
    raw.extend_from_slice(pk);
    let crc = crc16_xmodem(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());
    data_encoding::BASE32_NOPAD.encode(&raw)
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn client_ip(req: &Request) -> Option<String> {
    if let Some(v) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return Some(v.trim().to_owned());
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
}

fn unix_now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

fn is_unique_violation(err: &rmm_db::DbError) -> bool {
    matches!(err, rmm_db::DbError::Sqlx(sqlx::Error::Database(d)) if d.is_unique_violation())
}

fn short_field(name: &str, v: &str, max: usize) -> Result<(), ApiError> {
    if v.len() > max {
        return Err(ApiError::BadRequest(format!("{name} too long")));
    }
    Ok(())
}

/// Enroll a new agent.
#[utoipa::path(
    post,
    path = "/v1/enroll",
    request_body(content = serde_json::Value, description = "EnrollRequest (rmm_proto::enroll)", content_type = "application/json"),
    responses(
        (status = 201, description = "Enrolled; body is an EnrollResponse", body = serde_json::Value),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Bad token or proof", body = ErrorBody),
        (status = 409, description = "Public key already enrolled", body = ErrorBody),
        (status = 429, description = "Rate limited", body = ErrorBody)
    )
)]
pub async fn enroll(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
) -> Result<(StatusCode, Json<EnrollResponse>), ApiError> {
    if let Some(ip) = client_ip(&req)
        && !state.enroll_limiter.allow(&ip)
    {
        return Err(ApiError::TooManyRequests);
    }
    let ip = client_ip(&req);
    let body = axum::body::to_bytes(req.into_body(), MAX_BODY)
        .await
        .map_err(|_| ApiError::BadRequest("body too large or unreadable".into()))?;
    let er: EnrollRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::BadRequest(format!("invalid body: {e}")))?;

    short_field("token", &er.token, 128)?;
    short_field("hostname", &er.hostname, 255)?;
    short_field("os_family", &er.os_family, 64)?;
    short_field("os_version", &er.os_version, 256)?;
    short_field("agent_version", &er.agent_version, 64)?;
    if er.ts.abs_diff(unix_now()) > MAX_SKEW_SECS {
        return Err(ApiError::BadRequest(
            "timestamp outside allowed window".into(),
        ));
    }

    // Proof of possession first: a bad proof never touches the token.
    let vk = VerifyingKey::from_bytes(&er.agent_pubkey)
        .map_err(|_| ApiError::BadRequest("invalid agent_pubkey".into()))?;
    let sig = Signature::from_slice(&er.proof).map_err(|_| ApiError::Unauthorized)?;
    vk.verify_strict(&er.signing_bytes(), &sig)
        .map_err(|_| ApiError::Unauthorized)?;

    let (fp, strength) = fingerprint(&er.hw);
    let token_hash: [u8; 32] = Sha256::digest(er.token.as_bytes()).into();

    let mut tx = begin_scoped(&state.pool, &Scope::Service("enroll"), "enroll").await?;
    if repo::agent_by_pubkey(&mut tx, &er.agent_pubkey)
        .await?
        .is_some()
    {
        // Checked before the token is consumed, so a retry costs no use.
        return Err(ApiError::Conflict("public key already enrolled".into()));
    }

    let Some(token) = repo::consume_enrollment_token(&mut tx, &token_hash).await? else {
        let detail = serde_json::json!({
            "reason": "token invalid, expired, revoked or exhausted",
            "ip": ip,
            "hostname": er.hostname,
        });
        repo::insert_audit(
            &mut tx,
            "anonymous",
            "agent.enroll_denied",
            None,
            &format!("token:{}", data_encoding::HEXLOWER.encode(&token_hash[..8])),
            &detail,
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::Unauthorized);
    };

    let matches = repo::find_devices_by_fingerprint(&mut tx, &fp).await?;
    let decision = decide(&matches, &token, strength, Utc::now());
    let strength_str = match strength {
        FpStrength::Strong => "strong",
        FpStrength::Weak => "weak",
    };
    let new_device = |status: &str, clone_of: Option<Uuid>| NewDevice {
        client_id: token.client_id,
        site_id: token.site_id,
        hw_fingerprint: fp.to_vec(),
        fp_strength: strength_str.to_owned(),
        smbios_uuid: er.hw.smbios_uuid.clone(),
        system_serial: er.hw.system_serial.clone(),
        board_serial: er.hw.board_serial.clone(),
        os_family: er.os_family.clone(),
        hostname: er.hostname.clone(),
        status: status.to_owned(),
        possible_clone_of: clone_of,
    };

    let (device_id, device_status, agent_status, mut detail) = match &decision {
        AttachDecision::New => {
            let id = repo::insert_device(&mut tx, new_device("active", None)).await?;
            (
                id,
                "active".to_owned(),
                None,
                serde_json::json!({"decision": "new"}),
            )
        }
        AttachDecision::Reattach {
            device_id,
            old_agent_id,
        } => {
            // The stored status of the matched device; decide() only
            // reattaches to an `active` one. Fail closed otherwise.
            let stored = matches
                .iter()
                .find(|m| m.device_id == *device_id)
                .map(|m| m.device_status.clone())
                .filter(|s| s == "active")
                .ok_or_else(|| ApiError::Conflict("device not eligible for reattach".into()))?;
            if let Some(old) = old_agent_id {
                repo::supersede_agent(&mut tx, *old).await?;
            }
            (
                *device_id,
                stored,
                None,
                serde_json::json!({"decision": "reattach", "superseded": old_agent_id}),
            )
        }
        AttachDecision::PendingReview { possible_clone_of } => {
            let id = repo::insert_device(
                &mut tx,
                new_device("pending_review", Some(*possible_clone_of)),
            )
            .await?;
            (
                id,
                "pending_review".to_owned(),
                Some("suspect_clone"),
                serde_json::json!({"decision": "pending_review", "possible_clone_of": possible_clone_of}),
            )
        }
        AttachDecision::NewFlagged { possible_clone_of } => {
            let id = repo::insert_device(&mut tx, new_device("flagged", Some(*possible_clone_of)))
                .await?;
            (
                id,
                "flagged".to_owned(),
                None,
                serde_json::json!({"decision": "flagged", "possible_clone_of": possible_clone_of}),
            )
        }
    };

    let agent_id = match repo::insert_agent(
        &mut tx,
        NewAgent {
            client_id: token.client_id,
            device_id,
            credential_pubkey: er.agent_pubkey,
            nkey: nkey_from_pubkey(&er.agent_pubkey),
            version: er.agent_version.clone(),
        },
    )
    .await
    {
        Ok(id) => id,
        Err(e) if is_unique_violation(&e) => {
            return Err(ApiError::Conflict("public key already enrolled".into()));
        }
        Err(e) => return Err(e.into()),
    };
    if let Some(status) = agent_status {
        repo::set_agent_status(&mut tx, agent_id, status).await?;
    }

    if let JsonValue::Object(map) = &mut detail {
        map.insert("device_id".into(), device_id.to_string().into());
        map.insert("token_id".into(), token.id.to_string().into());
        map.insert("hostname".into(), er.hostname.clone().into());
        map.insert("ip".into(), ip.into());
    }
    repo::insert_audit(
        &mut tx,
        "agent",
        "agent.enroll",
        Some(token.client_id),
        &format!("agent:{agent_id}"),
        &detail,
    )
    .await?;

    let mut trust = TrustBundle::default();
    for (kind, _seq, envelope) in repo::latest_trust_artifacts(&mut tx).await? {
        match kind.as_str() {
            "manifest" => trust.manifest = Some(envelope),
            "revocations" => trust.revocations = Some(envelope),
            "techlist" => trust.techlist = Some(envelope),
            _ => {}
        }
    }
    tx.commit().await?;

    // Best effort: the consumer is also ensured before every command is issued.
    if let Some(nats) = &state.nats
        && let Err(err) = crate::actions::ensure_agent_consumer(
            &async_nats::jetstream::new(nats.clone()),
            agent_id,
        )
        .await
    {
        tracing::warn!(%err, %agent_id, "could not create the agent command consumer");
    }

    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            agent_id,
            device_id,
            client_id: token.client_id,
            nats_url: state.nats_public_url.clone(),
            trust,
            status: device_status,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(client: Uuid, reattach: bool) -> TokenRow {
        TokenRow {
            id: Uuid::nil(),
            client_id: client,
            site_id: Uuid::nil(),
            uses: 1,
            max_uses: 1,
            allow_reattach: reattach,
        }
    }

    fn dm(client: Uuid, seen_hours_ago: Option<i64>) -> DeviceMatch {
        DeviceMatch {
            device_id: Uuid::from_u128(7),
            client_id: client,
            device_status: "active".into(),
            agent_id: Some(Uuid::from_u128(8)),
            agent_status: Some("active".into()),
            last_seen: seen_hours_ago
                .and_then(|h| DateTime::from_timestamp(Utc::now().timestamp() - h * 3600, 0)),
        }
    }

    #[test]
    fn decide_rules() {
        let c = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let now = Utc::now();
        let t = token(c, true);
        assert_eq!(
            decide(&[], &t, FpStrength::Strong, now),
            AttachDecision::New
        );
        assert_eq!(
            decide(&[dm(c, Some(1))], &t, FpStrength::Weak, now),
            AttachDecision::New
        );
        assert!(matches!(
            decide(&[dm(c, Some(25))], &t, FpStrength::Strong, now),
            AttachDecision::Reattach { .. }
        ));
        assert!(matches!(
            decide(&[dm(c, None)], &t, FpStrength::Strong, now),
            AttachDecision::Reattach { .. }
        ));
        assert!(matches!(
            decide(&[dm(c, Some(1))], &t, FpStrength::Strong, now),
            AttachDecision::PendingReview { .. }
        ));
        assert!(matches!(
            decide(
                &[dm(c, Some(48))],
                &token(c, false),
                FpStrength::Strong,
                now
            ),
            AttachDecision::PendingReview { .. }
        ));
        let mut held = dm(c, None);
        held.agent_status = Some("suspect_clone".into());
        assert!(matches!(
            decide(&[held], &t, FpStrength::Strong, now),
            AttachDecision::PendingReview { .. }
        ));
        for st in ["flagged", "pending_review"] {
            let mut d = dm(c, Some(25));
            d.device_status = st.into();
            assert_eq!(
                decide(&[d], &t, FpStrength::Strong, now),
                AttachDecision::PendingReview {
                    possible_clone_of: Uuid::from_u128(7)
                }
            );
        }
        assert_eq!(
            decide(&[dm(c, Some(25))], &t, FpStrength::Strong, now),
            AttachDecision::Reattach {
                device_id: Uuid::from_u128(7),
                old_agent_id: Some(Uuid::from_u128(8))
            }
        );
        // A flagged sibling with the same fingerprint neither blocks nor
        // receives the reattach to the active original.
        let mut flagged = dm(c, Some(25));
        flagged.device_id = Uuid::from_u128(9);
        flagged.device_status = "flagged".into();
        assert_eq!(
            decide(&[flagged, dm(c, Some(25))], &t, FpStrength::Strong, now),
            AttachDecision::Reattach {
                device_id: Uuid::from_u128(7),
                old_agent_id: Some(Uuid::from_u128(8))
            }
        );
        assert!(matches!(
            decide(&[dm(other, Some(48))], &t, FpStrength::Strong, now),
            AttachDecision::NewFlagged { .. }
        ));
    }

    #[test]
    fn nkey_roundtrip() {
        let pk = [9u8; 32];
        let s = nkey_from_pubkey(&pk);
        assert!(s.starts_with('U'));
        let kp = nkeys::KeyPair::from_public_key(&s).expect("valid nkey");
        assert_eq!(kp.public_key(), s);
    }
}
