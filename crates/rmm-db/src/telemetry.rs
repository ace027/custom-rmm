//! Telemetry repositories: heartbeat, inventory, device events and metrics.

use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};

use crate::repo::{Result, Tx};

/// Typed inventory fields plus the raw document and its hash.
#[derive(Debug, Clone)]
pub struct InventoryUpdate {
    /// OS version string.
    pub os_version: Option<String>,
    /// CPU model name.
    pub cpu_model: Option<String>,
    /// Logical core count.
    pub cpu_cores: Option<i32>,
    /// Installed RAM in bytes.
    pub ram_bytes: Option<i64>,
    /// Total disk bytes.
    pub disk_total_bytes: Option<i64>,
    /// Free disk bytes.
    pub disk_free_bytes: Option<i64>,
    /// Last boot instant.
    pub last_boot: Option<DateTime<Utc>>,
    /// Full inventory document.
    pub inventory: JsonValue,
    /// SHA-256 of the canonical inventory.
    pub inventory_hash: [u8; 32],
}

/// One metric sample.
#[derive(Debug, Clone)]
pub struct MetricRow {
    /// Sample time.
    pub time: DateTime<Utc>,
    /// Owning client.
    pub client_id: Uuid,
    /// Device the sample belongs to.
    pub device_id: Uuid,
    /// Metric name.
    pub metric: String,
    /// Sample value.
    pub value: f64,
}

/// What ingest needs to know about an agent.
#[derive(Debug, Clone)]
pub struct AgentTelemetryRow {
    /// Agent id.
    pub agent_id: Uuid,
    /// Owning client.
    pub client_id: Uuid,
    /// Device id.
    pub device_id: Uuid,
    /// Agent status.
    pub status: String,
}

/// A device event.
#[derive(Debug, Clone)]
pub struct DeviceEventRow {
    /// Event id.
    pub id: i64,
    /// Owning client.
    pub client_id: Uuid,
    /// Device id.
    pub device_id: Uuid,
    /// Event time.
    pub at: DateTime<Utc>,
    /// Event type.
    pub r#type: String,
    /// State before.
    pub before: Option<JsonValue>,
    /// State after.
    pub after: Option<JsonValue>,
}

/// Look up an agent by id.
pub async fn agent_for_telemetry(
    tx: &mut Tx<'_>,
    agent_id: Uuid,
) -> Result<Option<AgentTelemetryRow>> {
    let row = sqlx::query_as!(
        AgentTelemetryRow,
        "select id as agent_id, client_id, device_id, status from tenant.agent where id = $1",
        agent_id
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

/// Record that the agent was seen at `at`.
pub async fn touch_heartbeat(tx: &mut Tx<'_>, agent_id: Uuid, at: DateTime<Utc>) -> Result<()> {
    sqlx::query!(
        "update tenant.agent set last_seen = $2 where id = $1",
        agent_id,
        at
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

struct Current {
    os_version: Option<String>,
    cpu_model: Option<String>,
    cpu_cores: Option<i32>,
    ram_bytes: Option<i64>,
    disk_total_bytes: Option<i64>,
    #[allow(dead_code)] // selected to keep the query shape; never diffed (volatile)
    disk_free_bytes: Option<i64>,
    last_boot: Option<DateTime<Utc>>,
    inventory_hash: Option<Vec<u8>>,
}

/// Apply an inventory. Returns `None` when the hash is unchanged (or the device
/// is not visible), else the names of the changed typed fields; one
/// `inventory.changed` event is written.
pub async fn apply_inventory(
    tx: &mut Tx<'_>,
    client_id: Uuid,
    device_id: Uuid,
    inv: &InventoryUpdate,
    at: DateTime<Utc>,
) -> Result<Option<Vec<String>>> {
    let cur = sqlx::query_as!(
        Current,
        "select os_version, cpu_model, cpu_cores, ram_bytes, disk_total_bytes, disk_free_bytes, \
         last_boot, inventory_hash from tenant.device where id = $1 and client_id = $2 for update",
        device_id,
        client_id
    )
    .fetch_optional(&mut **tx)
    .await?;
    let Some(cur) = cur else {
        return Ok(None);
    };
    if cur.inventory_hash.as_deref() == Some(&inv.inventory_hash[..]) {
        return Ok(None);
    }

    let mut changed: Vec<String> = Vec::new();
    let mut before: Vec<(String, JsonValue)> = Vec::new();
    let mut after: Vec<(String, JsonValue)> = Vec::new();
    macro_rules! field {
        ($name:ident) => {
            if cur.$name != inv.$name {
                changed.push(stringify!($name).to_owned());
                before.push((
                    stringify!($name).to_owned(),
                    JsonValue::from(cur.$name.clone()),
                ));
                after.push((
                    stringify!($name).to_owned(),
                    JsonValue::from(inv.$name.clone()),
                ));
            }
        };
    }
    field!(os_version);
    field!(cpu_model);
    field!(cpu_cores);
    field!(ram_bytes);
    field!(disk_total_bytes);
    // disk_free_bytes is volatile: updated below but never diffed into an event.
    if cur.last_boot != inv.last_boot {
        changed.push("last_boot".to_owned());
        before.push(("last_boot".to_owned(), ts_json(cur.last_boot)));
        after.push(("last_boot".to_owned(), ts_json(inv.last_boot)));
    }

    sqlx::query!(
        "update tenant.device set os_version = $2, cpu_model = $3, cpu_cores = $4, ram_bytes = $5, \
         disk_total_bytes = $6, disk_free_bytes = $7, last_boot = $8, inventory = $9, \
         inventory_hash = $10, inventory_at = $11 where id = $1",
        device_id,
        inv.os_version,
        inv.cpu_model,
        inv.cpu_cores,
        inv.ram_bytes,
        inv.disk_total_bytes,
        inv.disk_free_bytes,
        inv.last_boot,
        inv.inventory,
        &inv.inventory_hash[..],
        at
    )
    .execute(&mut **tx)
    .await?;

    if changed.is_empty() {
        return Ok(Some(changed));
    }

    sqlx::query!(
        "insert into tenant.device_event (client_id, device_id, at, type, before, after) \
         values ($1, $2, $3, 'inventory.changed', $4, $5)",
        client_id,
        device_id,
        at,
        JsonValue::Object(before.into_iter().collect()),
        JsonValue::Object(after.into_iter().collect())
    )
    .execute(&mut **tx)
    .await?;
    Ok(Some(changed))
}

fn ts_json(t: Option<DateTime<Utc>>) -> JsonValue {
    t.map_or(JsonValue::Null, |t| JsonValue::from(t.to_rfc3339()))
}

/// Insert metric samples with one multi-row statement; returns rows inserted.
pub async fn insert_metrics(tx: &mut Tx<'_>, rows: &[MetricRow]) -> Result<u64> {
    if rows.is_empty() {
        return Ok(0);
    }
    let times: Vec<DateTime<Utc>> = rows.iter().map(|r| r.time).collect();
    let clients: Vec<Uuid> = rows.iter().map(|r| r.client_id).collect();
    let devices: Vec<Uuid> = rows.iter().map(|r| r.device_id).collect();
    let names: Vec<String> = rows.iter().map(|r| r.metric.clone()).collect();
    let values: Vec<f64> = rows.iter().map(|r| r.value).collect();
    let res = sqlx::query!(
        "insert into ts_private.metrics (time, client_id, device_id, metric, value) \
         select * from unnest($1::timestamptz[], $2::uuid[], $3::uuid[], $4::text[], $5::float8[])",
        &times,
        &clients,
        &devices,
        &names,
        &values
    )
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected())
}

/// Newest events of a device first.
pub async fn device_events(
    tx: &mut Tx<'_>,
    device_id: Uuid,
    limit: i64,
) -> Result<Vec<DeviceEventRow>> {
    let rows = sqlx::query_as!(
        DeviceEventRow,
        r#"select id, client_id, device_id, at, type as "type!", before, after
           from tenant.device_event where device_id = $1 order by at desc, id desc limit $2"#,
        device_id,
        limit
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows)
}
