//! Repositories. Every function takes a scoped transaction, never the pool.

use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};
use sqlx::{Postgres, Transaction};

use crate::DbError;

/// Result alias for repository calls.
pub type Result<T> = std::result::Result<T, DbError>;

/// Transaction handle accepted by repositories.
pub type Tx<'a> = Transaction<'a, Postgres>;

/// Parameters for a new enrollment token.
#[derive(Debug, Clone)]
pub struct NewToken {
    /// Owning client.
    pub client_id: Uuid,
    /// Site devices enroll into.
    pub site_id: Uuid,
    /// SHA-256 of the token secret.
    pub token_hash: [u8; 32],
    /// Expiry instant.
    pub expires_at: DateTime<Utc>,
    /// Maximum number of consumptions.
    pub max_uses: i32,
    /// Whether the token may reattach an existing device.
    pub allow_reattach: bool,
    /// Technician that created it.
    pub created_by: String,
}

/// An enrollment token after consumption.
#[derive(Debug, Clone)]
pub struct TokenRow {
    /// Token id.
    pub id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Target site.
    pub site_id: Uuid,
    /// Uses including this consumption.
    pub uses: i32,
    /// Maximum uses.
    pub max_uses: i32,
    /// Whether reattach is allowed.
    pub allow_reattach: bool,
}

/// A device matching a fingerprint, with its newest non-superseded agent.
#[derive(Debug, Clone)]
pub struct DeviceMatch {
    /// Device id.
    pub device_id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Newest non-superseded agent, if any.
    pub agent_id: Option<Uuid>,
    /// Status of that agent.
    pub agent_status: Option<String>,
    /// Last time that agent was seen.
    pub last_seen: Option<DateTime<Utc>>,
}

/// Parameters for a new device.
#[derive(Debug, Clone)]
pub struct NewDevice {
    /// Owning client.
    pub client_id: Uuid,
    /// Site.
    pub site_id: Uuid,
    /// Hardware fingerprint.
    pub hw_fingerprint: Vec<u8>,
    /// `strong` or `weak`.
    pub fp_strength: String,
    /// SMBIOS UUID.
    pub smbios_uuid: Option<String>,
    /// System serial.
    pub system_serial: Option<String>,
    /// Baseboard serial.
    pub board_serial: Option<String>,
    /// OS family.
    pub os_family: String,
    /// Hostname.
    pub hostname: String,
    /// `active`, `pending_review` or `flagged`.
    pub status: String,
    /// Device this may be a clone of.
    pub possible_clone_of: Option<Uuid>,
}

/// Parameters for a new agent.
#[derive(Debug, Clone)]
pub struct NewAgent {
    /// Owning client.
    pub client_id: Uuid,
    /// Device.
    pub device_id: Uuid,
    /// Ed25519 public key.
    pub credential_pubkey: [u8; 32],
    /// NATS nkey encoding of the public key.
    pub nkey: String,
    /// Agent version.
    pub version: String,
}

/// Agent row returned by status changes.
#[derive(Debug, Clone)]
pub struct AgentRow {
    /// Agent id.
    pub id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Device.
    pub device_id: Uuid,
    /// Status after the change.
    pub status: String,
    /// NATS nkey.
    pub nkey: String,
}

/// Everything authd needs to decide a connection.
#[derive(Debug, Clone)]
pub struct AgentAuthRow {
    /// Agent id.
    pub agent_id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Device.
    pub device_id: Uuid,
    /// Agent status.
    pub status: String,
    /// Client status.
    pub client_status: String,
    /// NATS nkey.
    pub nkey: String,
}

/// Create a client.
pub async fn create_client(tx: &mut Tx<'_>, name: &str) -> Result<Uuid> {
    let id = sqlx::query_scalar!(
        r#"insert into tenant.client (name) values ($1) returning id"#,
        name
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Create a site.
pub async fn create_site(
    tx: &mut Tx<'_>,
    client_id: Uuid,
    name: &str,
    timezone: &str,
) -> Result<Uuid> {
    let id = sqlx::query_scalar!(
        r#"insert into tenant.site (client_id, name, timezone) values ($1, $2, $3) returning id"#,
        client_id,
        name,
        timezone
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Store a new enrollment token (hash only).
pub async fn create_enrollment_token(tx: &mut Tx<'_>, t: NewToken) -> Result<Uuid> {
    let id = sqlx::query_scalar!(
        r#"insert into tenant.enrollment_token
             (client_id, site_id, token_hash, expires_at, max_uses, allow_reattach, created_by)
           values ($1, $2, $3, $4, $5, $6, $7) returning id"#,
        t.client_id,
        t.site_id,
        &t.token_hash[..],
        t.expires_at,
        t.max_uses,
        t.allow_reattach,
        t.created_by
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Atomically consume one use of a valid token; `None` if unusable.
pub async fn consume_enrollment_token(
    tx: &mut Tx<'_>,
    token_hash: &[u8; 32],
) -> Result<Option<TokenRow>> {
    let row = sqlx::query_as!(
        TokenRow,
        r#"update tenant.enrollment_token
             set uses = uses + 1
           where token_hash = $1 and uses < max_uses and not revoked and expires_at > now()
           returning id, client_id, site_id, uses, max_uses, allow_reattach"#,
        &token_hash[..]
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

/// Devices with this fingerprint and their newest non-superseded agent.
pub async fn find_devices_by_fingerprint(tx: &mut Tx<'_>, fp: &[u8]) -> Result<Vec<DeviceMatch>> {
    let rows = sqlx::query_as!(
        DeviceMatch,
        r#"select d.id as "device_id!", d.client_id as "client_id!",
                  a.id as "agent_id?", a.status as "agent_status?", a.last_seen as "last_seen?"
           from tenant.device d
           left join lateral (
               select id, status, last_seen from tenant.agent
               where device_id = d.id and status <> 'superseded'
               order by enrolled_at desc limit 1
           ) a on true
           where d.hw_fingerprint = $1
           order by d.created_at"#,
        fp
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows)
}

/// Insert a device.
pub async fn insert_device(tx: &mut Tx<'_>, d: NewDevice) -> Result<Uuid> {
    let id = sqlx::query_scalar!(
        r#"insert into tenant.device
             (client_id, site_id, hw_fingerprint, fp_strength, smbios_uuid, system_serial,
              board_serial, os_family, hostname, status, possible_clone_of)
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) returning id"#,
        d.client_id,
        d.site_id,
        d.hw_fingerprint,
        d.fp_strength,
        d.smbios_uuid,
        d.system_serial,
        d.board_serial,
        d.os_family,
        d.hostname,
        d.status,
        d.possible_clone_of
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Insert an agent.
pub async fn insert_agent(tx: &mut Tx<'_>, a: NewAgent) -> Result<Uuid> {
    let id = sqlx::query_scalar!(
        r#"insert into tenant.agent (client_id, device_id, credential_pubkey, nkey, version)
           values ($1, $2, $3, $4, $5) returning id"#,
        a.client_id,
        a.device_id,
        &a.credential_pubkey[..],
        a.nkey,
        a.version
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

/// Mark an agent superseded (after a reattach).
pub async fn supersede_agent(tx: &mut Tx<'_>, agent_id: Uuid) -> Result<Option<AgentRow>> {
    set_agent_status(tx, agent_id, "superseded").await
}

/// Set an agent's status; `None` if it does not exist or is out of scope.
pub async fn set_agent_status(
    tx: &mut Tx<'_>,
    agent_id: Uuid,
    status: &str,
) -> Result<Option<AgentRow>> {
    let row = sqlx::query_as!(
        AgentRow,
        r#"update tenant.agent set status = $2 where id = $1
           returning id, client_id, device_id, status, nkey"#,
        agent_id,
        status
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

/// Look up an agent by its credential public key.
pub async fn agent_by_pubkey(tx: &mut Tx<'_>, pubkey: &[u8; 32]) -> Result<Option<AgentAuthRow>> {
    let row = sqlx::query_as!(
        AgentAuthRow,
        r#"select a.id as agent_id, a.client_id, a.device_id, a.status,
                  c.status as client_status, a.nkey
           from tenant.agent a join tenant.client c on c.id = a.client_id
           where a.credential_pubkey = $1"#,
        &pubkey[..]
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

/// Record that an agent was just seen.
pub async fn touch_last_seen(tx: &mut Tx<'_>, agent_id: Uuid) -> Result<()> {
    sqlx::query!(
        "update tenant.agent set last_seen = now() where id = $1",
        agent_id
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Store a trust artifact; returns false if `(kind, seq)` already exists.
pub async fn put_trust_artifact(
    tx: &mut Tx<'_>,
    kind: &str,
    seq: i64,
    content_id: &[u8],
    envelope: &[u8],
    uploaded_by: &str,
) -> Result<bool> {
    let res = sqlx::query!(
        r#"insert into msp.trust_artifact (kind, seq, content_id, envelope, uploaded_by)
           values ($1, $2, $3, $4, $5) on conflict do nothing"#,
        kind,
        seq,
        content_id,
        envelope,
        uploaded_by
    )
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Highest-seq artifact for each kind as `(kind, seq, envelope)`.
pub async fn latest_trust_artifacts(tx: &mut Tx<'_>) -> Result<Vec<(String, i64, Vec<u8>)>> {
    let rows = sqlx::query!(
        r#"select distinct on (kind) kind, seq, envelope
           from msp.trust_artifact order by kind, seq desc"#
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.kind, r.seq, r.envelope))
        .collect())
}

/// Append an audit event.
pub async fn insert_audit(
    tx: &mut Tx<'_>,
    actor: &str,
    action: &str,
    client_id: Option<Uuid>,
    target: &str,
    detail: &JsonValue,
) -> Result<()> {
    sqlx::query!(
        r#"insert into msp.audit_event (actor, action, client_id, target, detail)
           values ($1, $2, $3, $4, $5)"#,
        actor,
        action,
        client_id,
        target,
        detail
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}
