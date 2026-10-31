//! Repositories. Every function takes a scoped transaction, never the pool.

use sqlx::postgres::PgRow;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};
use sqlx::{Postgres, Row, Transaction};

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
    /// The device's own status: `active`, `pending_review` or `flagged`.
    pub device_status: String,
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
                  d.status as "device_status!",
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

// The queries below are runtime-checked (`sqlx::query`) so they need no entry
// in the offline `.sqlx` cache.

const AGENT_RETURNING: &str = "returning id, client_id, device_id, status, nkey";

fn agent_row(r: &PgRow) -> Result<AgentRow> {
    Ok(AgentRow {
        id: r.try_get("id")?,
        client_id: r.try_get("client_id")?,
        device_id: r.try_get("device_id")?,
        status: r.try_get("status")?,
        nkey: r.try_get("nkey")?,
    })
}

/// Move an agent to `to`, only if its current status is one of `from`.
/// `None` if the agent does not exist, is out of scope or is in another state.
pub async fn transition_agent_status(
    tx: &mut Tx<'_>,
    agent_id: Uuid,
    from: &[&str],
    to: &str,
) -> Result<Option<AgentRow>> {
    let from: Vec<String> = from.iter().map(|s| (*s).to_owned()).collect();
    let row = sqlx::query(&format!(
        "update tenant.agent set status = $3 where id = $1 and status = any($2) {AGENT_RETURNING}"
    ))
    .bind(agent_id)
    .bind(from)
    .bind(to)
    .fetch_optional(&mut **tx)
    .await?;
    row.as_ref().map(agent_row).transpose()
}

/// Result of approving a held device.
#[derive(Debug, Clone)]
pub struct Approval {
    /// Owning client.
    pub client_id: Uuid,
    /// Agents of the device that became `active`.
    pub activated: Vec<AgentRow>,
    /// Agents of the original device that became `superseded`.
    pub superseded: Vec<AgentRow>,
}

/// Approve a `pending_review` or `flagged` device: the device and its
/// `suspect_clone` agents become `active`, and the live agents of the device
/// it may be a clone of (same client only) become `superseded`. `None` if the
/// device is unknown, out of scope or not held.
pub async fn approve_device(tx: &mut Tx<'_>, device_id: Uuid) -> Result<Option<Approval>> {
    let Some(dev) = sqlx::query(
        "update tenant.device set status = 'active'
         where id = $1 and status in ('pending_review', 'flagged')
         returning client_id, possible_clone_of",
    )
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let client_id: Uuid = dev.try_get("client_id")?;
    let clone_of: Option<Uuid> = dev.try_get("possible_clone_of")?;
    let activated = sqlx::query(&format!(
        "update tenant.agent set status = 'active'
         where device_id = $1 and status = 'suspect_clone' {AGENT_RETURNING}"
    ))
    .bind(device_id)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(agent_row)
    .collect::<Result<Vec<_>>>()?;
    let superseded = match clone_of {
        Some(old) => sqlx::query(&format!(
            "update tenant.agent set status = 'superseded'
             where device_id = $1 and client_id = $2 and status in ('active', 'suspect_clone')
             {AGENT_RETURNING}"
        ))
        .bind(old)
        .bind(client_id)
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .map(agent_row)
        .collect::<Result<Vec<_>>>()?,
        None => Vec::new(),
    };
    Ok(Some(Approval {
        client_id,
        activated,
        superseded,
    }))
}

/// Reject a `pending_review` or `flagged` device: its live agents become
/// `revoked`. Returns `(client_id, revoked agents)`; `None` if the device is
/// unknown, out of scope or not held.
pub async fn reject_device(
    tx: &mut Tx<'_>,
    device_id: Uuid,
) -> Result<Option<(Uuid, Vec<AgentRow>)>> {
    let Some(dev) = sqlx::query(
        "select client_id from tenant.device
         where id = $1 and status in ('pending_review', 'flagged')",
    )
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let client_id: Uuid = dev.try_get("client_id")?;
    let revoked = sqlx::query(&format!(
        "update tenant.agent set status = 'revoked'
         where device_id = $1 and status in ('active', 'suspect_clone') {AGENT_RETURNING}"
    ))
    .bind(device_id)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(agent_row)
    .collect::<Result<Vec<_>>>()?;
    Ok(Some((client_id, revoked)))
}

/// Set a client's status (`active` or `disabled`); false if unknown.
pub async fn set_client_status(tx: &mut Tx<'_>, client_id: Uuid, status: &str) -> Result<bool> {
    let res = sqlx::query("update tenant.client set status = $2 where id = $1")
        .bind(client_id)
        .bind(status)
        .execute(&mut **tx)
        .await?;
    Ok(res.rows_affected() == 1)
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

/// Number of audit events with this action and target.
pub async fn count_audit(tx: &mut Tx<'_>, action: &str, target: &str) -> Result<i64> {
    let n = sqlx::query("select count(*) from msp.audit_event where action = $1 and target = $2")
        .bind(action)
        .bind(target)
        .fetch_one(&mut **tx)
        .await?
        .try_get(0)?;
    Ok(n)
}
