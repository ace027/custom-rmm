//! Action repositories: the signed-definition catalog and action runs.

use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};

use crate::repo::{Result, Tx};

/// A stored catalog definition.
#[derive(Debug, Clone)]
pub struct DefinitionRow {
    /// SHA-256 of the definition payload.
    pub content_id: Vec<u8>,
    /// Dotted action name.
    pub id: String,
    /// Definition version.
    pub version: i32,
    /// Capability group.
    pub capability: String,
    /// The signed envelope bytes.
    pub envelope: Vec<u8>,
}

/// Parameters for a new action run.
#[derive(Debug, Clone)]
pub struct NewActionRun {
    /// Command id (also the primary key).
    pub cmd_id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Target agent.
    pub agent_id: Uuid,
    /// Device of the agent.
    pub device_id: Uuid,
    /// Content id of the definition invoked.
    pub definition_content_id: Vec<u8>,
    /// Parameters as supplied.
    pub params: JsonValue,
    /// Actor that requested the run.
    pub requested_by: String,
}

/// An action run.
#[derive(Debug, Clone)]
pub struct ActionRunRow {
    /// Command id.
    pub cmd_id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Target agent.
    pub agent_id: Uuid,
    /// Device of the agent.
    pub device_id: Uuid,
    /// Content id of the definition invoked.
    pub definition_content_id: Vec<u8>,
    /// Parameters as supplied.
    pub params: JsonValue,
    /// Actor that requested the run.
    pub requested_by: String,
    /// `queued`, `succeeded`, `failed`, `rolled_back`, `rejected` or `expired`.
    pub status: String,
    /// Rejection reason, when rejected.
    pub reason: Option<String>,
    /// Per-stage outcomes.
    pub stages: JsonValue,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Completion time, once the agent reported.
    pub finished_at: Option<DateTime<Utc>>,
}

/// Store a definition keyed by content id; false if it was already stored.
pub async fn put_definition(
    tx: &mut Tx<'_>,
    content_id: &[u8],
    id: &str,
    version: i32,
    capability: &str,
    envelope: &[u8],
    uploaded_by: &str,
) -> Result<bool> {
    let res = sqlx::query!(
        r#"insert into msp.action_definition (content_id, id, version, capability, envelope, uploaded_by)
           values ($1, $2, $3, $4, $5, $6) on conflict do nothing"#,
        content_id,
        id,
        version,
        capability,
        envelope,
        uploaded_by
    )
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// The definition with this content id.
pub async fn definition_by_content_id(
    tx: &mut Tx<'_>,
    content_id: &[u8],
) -> Result<Option<DefinitionRow>> {
    let row = sqlx::query_as!(
        DefinitionRow,
        r#"select content_id, id, version, capability, envelope
           from msp.action_definition where content_id = $1"#,
        content_id
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

/// Record a queued run.
pub async fn insert_action_run(tx: &mut Tx<'_>, r: NewActionRun) -> Result<()> {
    sqlx::query!(
        r#"insert into tenant.action_run
             (cmd_id, client_id, agent_id, device_id, definition_content_id, params, requested_by)
           values ($1, $2, $3, $4, $5, $6, $7)"#,
        r.cmd_id,
        r.client_id,
        r.agent_id,
        r.device_id,
        r.definition_content_id,
        r.params,
        r.requested_by
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Record the agent-signed outcome of a run. False when the run was already
/// finished (or is not visible): nothing is updated then.
pub async fn finish_action_run(
    tx: &mut Tx<'_>,
    cmd_id: Uuid,
    status: &str,
    reason: Option<&str>,
    stages: &JsonValue,
    result_envelope: &[u8],
    finished_at: DateTime<Utc>,
) -> Result<bool> {
    let res = sqlx::query!(
        r#"update tenant.action_run
           set status = $2, reason = $3, stages = $4, result_envelope = $5, finished_at = $6
           where cmd_id = $1 and status = 'queued'"#,
        cmd_id,
        status,
        reason,
        stages,
        result_envelope,
        finished_at
    )
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// The run with this command id, if visible to the transaction's scope.
pub async fn action_run(tx: &mut Tx<'_>, cmd_id: Uuid) -> Result<Option<ActionRunRow>> {
    let row = sqlx::query_as!(
        ActionRunRow,
        r#"select cmd_id, client_id, agent_id, device_id, definition_content_id, params,
                  requested_by, status, reason, stages, created_at, finished_at
           from tenant.action_run where cmd_id = $1"#,
        cmd_id
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

/// What result verification needs to know about an agent.
#[derive(Debug, Clone)]
pub struct AgentCredential {
    /// Agent id.
    pub agent_id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Agent status.
    pub status: String,
    /// The agent's Ed25519 public key.
    pub credential_pubkey: Vec<u8>,
}

/// The agent's credential public key and status, in any status.
pub async fn agent_credential(tx: &mut Tx<'_>, agent_id: Uuid) -> Result<Option<AgentCredential>> {
    let row = sqlx::query_as!(
        AgentCredential,
        r#"select id as agent_id, client_id, status, credential_pubkey
           from tenant.agent where id = $1"#,
        agent_id
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}
