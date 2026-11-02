//! Shell repositories: technicians, WebAuthn credentials and challenges
//! (msp.*), and shell sessions with their single-use WebSocket tickets
//! (tenant.*, RLS-scoped by the transaction).
//!
//! Queries are runtime-checked (`sqlx::query`) so they need no entry in the
//! offline `.sqlx` cache.

use sqlx::Row;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid;
use sqlx::types::chrono::{DateTime, Utc};

use crate::repo::{Result, Tx};

/// Create the technician on first use; later calls refresh the display name.
pub async fn upsert_technician(tx: &mut Tx<'_>, tech_id: &str, display_name: &str) -> Result<()> {
    sqlx::query(
        "insert into msp.technician (tech_id, display_name) values ($1, $2)
         on conflict (tech_id) do update set display_name = excluded.display_name
         where msp.technician.display_name is distinct from excluded.display_name",
    )
    .bind(tech_id)
    .bind(display_name)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Allow a technician to act on a client; false if it already could.
pub async fn add_technician_client(
    tx: &mut Tx<'_>,
    tech_id: &str,
    client_id: Uuid,
) -> Result<bool> {
    let res = sqlx::query(
        "insert into msp.technician_client (tech_id, client_id) values ($1, $2)
         on conflict do nothing",
    )
    .bind(tech_id)
    .bind(client_id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Store a fresh challenge valid for `ttl_secs` (database clock); returns its id.
pub async fn insert_challenge(
    tx: &mut Tx<'_>,
    tech_id: &str,
    challenge: &[u8],
    purpose: &str,
    ttl_secs: i32,
) -> Result<Uuid> {
    let id = sqlx::query(
        "insert into msp.webauthn_challenge (tech_id, challenge, purpose, expires_at)
         values ($1, $2, $3, now() + make_interval(secs => $4)) returning id",
    )
    .bind(tech_id)
    .bind(challenge)
    .bind(purpose)
    .bind(f64::from(ttl_secs))
    .fetch_one(&mut **tx)
    .await?
    .try_get("id")?;
    Ok(id)
}

/// Consume a challenge once: only the owning technician, for the same
/// purpose, before it expires. Returns the challenge bytes, or `None` when it
/// is unknown, someone else's, already used or expired.
pub async fn consume_challenge(
    tx: &mut Tx<'_>,
    id: Uuid,
    tech_id: &str,
    purpose: &str,
) -> Result<Option<Vec<u8>>> {
    let row = sqlx::query(
        "update msp.webauthn_challenge set used_at = now()
         where id = $1 and tech_id = $2 and purpose = $3
           and used_at is null and expires_at > now()
         returning challenge",
    )
    .bind(id)
    .bind(tech_id)
    .bind(purpose)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| r.try_get("challenge"))
        .transpose()
        .map_err(Into::into)
}

/// A credential to register.
#[derive(Debug, Clone)]
pub struct NewCredential {
    /// WebAuthn credential id.
    pub cred_id: Vec<u8>,
    /// Owning technician.
    pub tech_id: String,
    /// COSE algorithm (-7 or -8).
    pub alg: i32,
    /// COSE_Key bytes.
    pub cose_pubkey: Vec<u8>,
    /// 16-byte authenticator AAGUID.
    pub aaguid: Vec<u8>,
    /// Signature counter at registration.
    pub sign_count: i64,
    /// Attestation statement format (`packed`).
    pub attestation_fmt: String,
}

/// A stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRow {
    /// WebAuthn credential id.
    pub cred_id: Vec<u8>,
    /// Owning technician.
    pub tech_id: String,
    /// COSE algorithm.
    pub alg: i32,
    /// COSE_Key bytes.
    pub cose_pubkey: Vec<u8>,
    /// AAGUID.
    pub aaguid: Vec<u8>,
    /// Last seen signature counter.
    pub sign_count: i64,
    /// Attestation statement format.
    pub attestation_fmt: String,
    /// Registration time.
    pub created_at: DateTime<Utc>,
    /// Revocation time, if revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

const CRED_COLS: &str = "cred_id, tech_id, alg, cose_pubkey, aaguid, sign_count, \
                         attestation_fmt, created_at, revoked_at";

fn cred_row(r: &PgRow) -> Result<CredentialRow> {
    Ok(CredentialRow {
        cred_id: r.try_get("cred_id")?,
        tech_id: r.try_get("tech_id")?,
        alg: r.try_get("alg")?,
        cose_pubkey: r.try_get("cose_pubkey")?,
        aaguid: r.try_get("aaguid")?,
        sign_count: r.try_get("sign_count")?,
        attestation_fmt: r.try_get("attestation_fmt")?,
        created_at: r.try_get("created_at")?,
        revoked_at: r.try_get("revoked_at")?,
    })
}

/// Register a credential. False when the credential id is already
/// registered (to anyone): the existing row is never changed.
pub async fn insert_credential(tx: &mut Tx<'_>, c: NewCredential) -> Result<bool> {
    let res = sqlx::query(
        "insert into msp.webauthn_credential
           (cred_id, tech_id, alg, cose_pubkey, aaguid, sign_count, attestation_fmt)
         values ($1, $2, $3, $4, $5, $6, $7)
         on conflict (cred_id) do nothing",
    )
    .bind(&c.cred_id)
    .bind(&c.tech_id)
    .bind(c.alg)
    .bind(&c.cose_pubkey)
    .bind(&c.aaguid)
    .bind(c.sign_count)
    .bind(&c.attestation_fmt)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// A technician's non-revoked credentials, oldest first.
pub async fn list_credentials(tx: &mut Tx<'_>, tech_id: &str) -> Result<Vec<CredentialRow>> {
    sqlx::query(&format!(
        "select {CRED_COLS} from msp.webauthn_credential
         where tech_id = $1 and revoked_at is null order by created_at, cred_id"
    ))
    .bind(tech_id)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(cred_row)
    .collect()
}

/// The credential with this id, revoked or not.
pub async fn credential(tx: &mut Tx<'_>, cred_id: &[u8]) -> Result<Option<CredentialRow>> {
    sqlx::query(&format!(
        "select {CRED_COLS} from msp.webauthn_credential where cred_id = $1"
    ))
    .bind(cred_id)
    .fetch_optional(&mut **tx)
    .await?
    .as_ref()
    .map(cred_row)
    .transpose()
}

/// Revoke a credential; false if unknown or already revoked.
pub async fn revoke_credential(tx: &mut Tx<'_>, cred_id: &[u8]) -> Result<bool> {
    let res = sqlx::query(
        "update msp.webauthn_credential set revoked_at = now()
         where cred_id = $1 and revoked_at is null",
    )
    .bind(cred_id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// One technician as the techlist draft needs it.
#[derive(Debug, Clone)]
pub struct TechnicianEntry {
    /// Technician id.
    pub tech_id: String,
    /// Display name.
    pub display_name: String,
    /// Clients the technician may act on, sorted.
    pub client_ids: Vec<Uuid>,
    /// Non-revoked credentials, oldest first.
    pub creds: Vec<CredentialRow>,
}

/// Every technician with at least one non-revoked credential, by tech_id.
pub async fn techlist_entries(tx: &mut Tx<'_>) -> Result<Vec<TechnicianEntry>> {
    let techs = sqlx::query(
        "select t.tech_id, t.display_name,
                coalesce(array_agg(tc.client_id order by tc.client_id)
                         filter (where tc.client_id is not null), '{}') as client_ids
         from msp.technician t
         left join msp.technician_client tc on tc.tech_id = t.tech_id
         where exists (select 1 from msp.webauthn_credential c
                       where c.tech_id = t.tech_id and c.revoked_at is null)
         group by t.tech_id, t.display_name
         order by t.tech_id",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut out = Vec::with_capacity(techs.len());
    for r in &techs {
        let tech_id: String = r.try_get("tech_id")?;
        let creds = list_credentials(tx, &tech_id).await?;
        out.push(TechnicianEntry {
            display_name: r.try_get("display_name")?,
            client_ids: r.try_get("client_ids")?,
            creds,
            tech_id,
        });
    }
    Ok(out)
}

/// A shell grant to record.
#[derive(Debug, Clone)]
pub struct NewShellSession {
    /// 16-byte grant id.
    pub grant_id: Vec<u8>,
    /// Owning client.
    pub client_id: Uuid,
    /// Target agent.
    pub agent_id: Uuid,
    /// Technician.
    pub tech_id: String,
    /// Credential expected to co-sign.
    pub cred_id: Vec<u8>,
    /// Shell name.
    pub shell: String,
    /// Longest session length in seconds.
    pub max_duration: i32,
    /// Canonical ShellGrant bytes.
    pub grant_cbor: Vec<u8>,
}

/// A shell session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSessionRow {
    /// Grant id.
    pub grant_id: Vec<u8>,
    /// Owning client.
    pub client_id: Uuid,
    /// Target agent.
    pub agent_id: Uuid,
    /// Technician.
    pub tech_id: String,
    /// Credential.
    pub cred_id: Vec<u8>,
    /// Shell name.
    pub shell: String,
    /// Longest session length in seconds.
    pub max_duration: i32,
    /// Canonical ShellGrant bytes.
    pub grant_cbor: Vec<u8>,
    /// `pending`, `opening`, `open`, `closed`, `expired` or `rejected`.
    pub status: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// When it became `open`.
    pub opened_at: Option<DateTime<Utc>>,
    /// When it ended.
    pub closed_at: Option<DateTime<Utc>>,
    /// Why it ended.
    pub close_reason: Option<String>,
    /// Recording file path.
    pub recording_path: Option<String>,
    /// SHA-256 of the recording.
    pub recording_sha256: Option<Vec<u8>>,
    /// Recording size in bytes.
    pub recording_bytes: Option<i64>,
}

fn session_row(r: &PgRow) -> Result<ShellSessionRow> {
    Ok(ShellSessionRow {
        grant_id: r.try_get("grant_id")?,
        client_id: r.try_get("client_id")?,
        agent_id: r.try_get("agent_id")?,
        tech_id: r.try_get("tech_id")?,
        cred_id: r.try_get("cred_id")?,
        shell: r.try_get("shell")?,
        max_duration: r.try_get("max_duration")?,
        grant_cbor: r.try_get("grant_cbor")?,
        status: r.try_get("status")?,
        created_at: r.try_get("created_at")?,
        opened_at: r.try_get("opened_at")?,
        closed_at: r.try_get("closed_at")?,
        close_reason: r.try_get("close_reason")?,
        recording_path: r.try_get("recording_path")?,
        recording_sha256: r.try_get("recording_sha256")?,
        recording_bytes: r.try_get("recording_bytes")?,
    })
}

/// Record a `pending` shell grant.
pub async fn insert_shell_session(tx: &mut Tx<'_>, s: NewShellSession) -> Result<()> {
    sqlx::query(
        "insert into tenant.shell_session
           (grant_id, client_id, agent_id, tech_id, cred_id, shell, max_duration, grant_cbor)
         values ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&s.grant_id)
    .bind(s.client_id)
    .bind(s.agent_id)
    .bind(&s.tech_id)
    .bind(&s.cred_id)
    .bind(&s.shell)
    .bind(s.max_duration)
    .bind(&s.grant_cbor)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The session with this grant id, if visible to the transaction's scope.
pub async fn shell_session(tx: &mut Tx<'_>, grant_id: &[u8]) -> Result<Option<ShellSessionRow>> {
    sqlx::query("select * from tenant.shell_session where grant_id = $1")
        .bind(grant_id)
        .fetch_optional(&mut **tx)
        .await?
        .as_ref()
        .map(session_row)
        .transpose()
}

/// Move a session to `to` only if its status is one of `from`. Entering
/// `open` stamps `opened_at`; entering `closed`, `expired` or `rejected`
/// stamps `closed_at` and stores `reason`. False if nothing changed.
pub async fn update_shell_status(
    tx: &mut Tx<'_>,
    grant_id: &[u8],
    from: &[&str],
    to: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let from: Vec<String> = from.iter().map(|s| (*s).to_owned()).collect();
    let res = sqlx::query(
        "update tenant.shell_session set
           status = $3,
           opened_at = case when $3 = 'open' then now() else opened_at end,
           closed_at = case when $3 in ('closed', 'expired', 'rejected') then now() else closed_at end,
           close_reason = case when $3 in ('closed', 'expired', 'rejected') then $4 else close_reason end
         where grant_id = $1 and status = any($2)",
    )
    .bind(grant_id)
    .bind(from)
    .bind(to)
    .bind(reason)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Store the hash of a WebSocket ticket for a session, valid for `ttl_secs`.
pub async fn insert_ws_ticket(
    tx: &mut Tx<'_>,
    ticket_hash: &[u8; 32],
    client_id: Uuid,
    grant_id: &[u8],
    ttl_secs: i32,
) -> Result<()> {
    sqlx::query(
        "insert into tenant.shell_ws_ticket (ticket_hash, client_id, grant_id, expires_at)
         values ($1, $2, $3, now() + make_interval(secs => $4))",
    )
    .bind(&ticket_hash[..])
    .bind(client_id)
    .bind(grant_id)
    .bind(f64::from(ttl_secs))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Consume a ticket once; returns `(grant_id, client_id)` the first time
/// within its validity and `None` ever after.
pub async fn consume_ws_ticket(
    tx: &mut Tx<'_>,
    ticket_hash: &[u8; 32],
) -> Result<Option<(Vec<u8>, Uuid)>> {
    let row = sqlx::query(
        "update tenant.shell_ws_ticket set used_at = now()
         where ticket_hash = $1 and used_at is null and expires_at > now()
         returning grant_id, client_id",
    )
    .bind(&ticket_hash[..])
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        Some(r) => Ok(Some((r.try_get("grant_id")?, r.try_get("client_id")?))),
        None => Ok(None),
    }
}

/// Record the finished recording of a session; false if not visible.
pub async fn set_recording(
    tx: &mut Tx<'_>,
    grant_id: &[u8],
    path: &str,
    sha256: &[u8; 32],
    bytes: i64,
) -> Result<bool> {
    let res = sqlx::query(
        "update tenant.shell_session
         set recording_path = $2, recording_sha256 = $3, recording_bytes = $4
         where grant_id = $1",
    )
    .bind(grant_id)
    .bind(path)
    .bind(&sha256[..])
    .bind(bytes)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// A session past retention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldRecording {
    /// Grant id.
    pub grant_id: Vec<u8>,
    /// Owning client.
    pub client_id: Uuid,
    /// Recording file path, if one was written.
    pub recording_path: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Sessions created before `cutoff`, oldest first, at most `limit`.
pub async fn recordings_older_than(
    tx: &mut Tx<'_>,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<OldRecording>> {
    let rows = sqlx::query(
        "select grant_id, client_id, recording_path, created_at from tenant.shell_session
         where created_at < $1 order by created_at, grant_id limit $2",
    )
    .bind(cutoff)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(OldRecording {
                grant_id: r.try_get("grant_id")?,
                client_id: r.try_get("client_id")?,
                recording_path: r.try_get("recording_path")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}

/// Delete a session and its tickets (retention); false if not visible.
pub async fn delete_shell_session(tx: &mut Tx<'_>, grant_id: &[u8]) -> Result<bool> {
    let res = sqlx::query("delete from tenant.shell_session where grant_id = $1")
        .bind(grant_id)
        .execute(&mut **tx)
        .await?;
    Ok(res.rows_affected() == 1)
}
