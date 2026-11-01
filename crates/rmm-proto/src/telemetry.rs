//! Telemetry wire types published by the agent and consumed by ingest.
//!
//! Payloads carry no client or agent id: identity comes only from the NATS
//! subject `telemetry.<client>.<agent>.<kind>`.
//!
//! Encoding: [`encode`]/[`decode`] use plain CBOR via `ciborium` because
//! [`Sample::value`] is a float and `canonical` forbids floats. Only
//! [`Inventory::hash`] uses the deterministic canonical encoding (the type
//! has no floats).

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::canonical;

/// Wire schema version carried in every payload (`v`).
pub const SCHEMA_VERSION: u8 = 1;

/// Subject kind for heartbeats (core NATS).
pub const KIND_HEARTBEAT: &str = "hb";
/// Subject kind for inventory (JetStream).
pub const KIND_INVENTORY: &str = "inv";
/// Subject kind for metric batches (JetStream).
pub const KIND_METRIC: &str = "metric";

/// Metric name: CPU usage in percent.
pub const METRIC_CPU_USAGE_PCT: &str = "cpu.usage_pct";
/// Metric name: used memory in bytes.
pub const METRIC_MEM_USED_BYTES: &str = "mem.used_bytes";
/// Metric name: total memory in bytes.
pub const METRIC_MEM_TOTAL_BYTES: &str = "mem.total_bytes";
/// Metric name prefix for free disk bytes; the mount point follows the colon.
pub const METRIC_DISK_FREE_PREFIX: &str = "disk.free_bytes:";
/// Metric name: uptime in seconds.
pub const METRIC_UPTIME_S: &str = "uptime_s";

/// Telemetry encode/decode failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryError {
    /// Serialization failed.
    #[error("encode: {0}")]
    Encode(String),
    /// Bytes are not a valid payload of the requested type.
    #[error("decode: {0}")]
    Decode(String),
}

/// Liveness message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    /// Schema version.
    pub v: u8,
    /// UUIDv7 message id (JetStream dedupe id where applicable).
    pub msg_id: Uuid,
    /// Send time, unix milliseconds.
    pub sent_at: i64,
    /// Agent build version.
    pub agent_version: String,
    /// Seconds since boot.
    pub uptime_s: u64,
}

/// One mounted volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    /// Mount point or drive letter.
    pub mount: String,
    /// Total size in bytes.
    pub total_bytes: u64,
    /// Free bytes.
    pub free_bytes: u64,
}

/// Hardware and OS inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// Schema version.
    pub v: u8,
    /// UUIDv7 message id.
    pub msg_id: Uuid,
    /// Send time, unix milliseconds.
    pub sent_at: i64,
    /// OS family (`windows`, `linux`, ...).
    pub os_family: String,
    /// Human-readable OS version.
    pub os_version: String,
    /// Host name.
    pub hostname: String,
    /// CPU model string.
    pub cpu_model: Option<String>,
    /// Logical CPU count.
    pub cpu_cores: Option<u32>,
    /// Installed RAM in bytes.
    pub ram_bytes: Option<u64>,
    /// Mounted volumes.
    pub volumes: Vec<Volume>,
    /// Last boot, unix seconds.
    pub last_boot: Option<i64>,
}

impl Inventory {
    /// SHA-256 of the canonical CBOR with `msg_id` and `sent_at` zeroed, so
    /// it changes only when the inventory facts change.
    pub fn hash(&self) -> [u8; 32] {
        let mut c = self.clone();
        c.msg_id = Uuid::nil();
        c.sent_at = 0;
        // Inventory contains only strings, integers, options and vectors, so
        // canonical encoding cannot fail; an empty input still yields a stable hash.
        let bytes = canonical::to_canonical_vec(&c).unwrap_or_default();
        Sha256::digest(&bytes).into()
    }
}

/// One metric sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    /// Sample time, unix milliseconds.
    pub t: i64,
    /// Metric name.
    pub metric: String,
    /// Metric value (finite).
    pub value: f64,
}

/// A batch of metric samples.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricBatch {
    /// Schema version.
    pub v: u8,
    /// UUIDv7 message id.
    pub msg_id: Uuid,
    /// Send time, unix milliseconds.
    pub sent_at: i64,
    /// Samples.
    pub samples: Vec<Sample>,
}

/// Encode a payload as CBOR.
pub fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, TelemetryError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).map_err(|e| TelemetryError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode a payload; unknown fields are an error.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, TelemetryError> {
    ciborium::de::from_reader(bytes).map_err(|e| TelemetryError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv() -> Inventory {
        Inventory {
            v: SCHEMA_VERSION,
            msg_id: Uuid::now_v7(),
            sent_at: 1_700_000_000_000,
            os_family: "linux".into(),
            os_version: "Debian".into(),
            hostname: "h".into(),
            cpu_model: Some("cpu".into()),
            cpu_cores: Some(4),
            ram_bytes: Some(1 << 30),
            volumes: vec![Volume {
                mount: "/".into(),
                total_bytes: 100,
                free_bytes: 40,
            }],
            last_boot: Some(1_700_000_000),
        }
    }

    #[test]
    fn round_trips() {
        let hb = Heartbeat {
            v: SCHEMA_VERSION,
            msg_id: Uuid::now_v7(),
            sent_at: 5,
            agent_version: "0.1.0".into(),
            uptime_s: 9,
        };
        assert_eq!(
            decode::<Heartbeat>(&encode(&hb).expect("enc")).expect("dec"),
            hb
        );
        let i = inv();
        assert_eq!(
            decode::<Inventory>(&encode(&i).expect("enc")).expect("dec"),
            i
        );
        let m = MetricBatch {
            v: SCHEMA_VERSION,
            msg_id: Uuid::now_v7(),
            sent_at: 5,
            samples: vec![Sample {
                t: 4,
                metric: METRIC_CPU_USAGE_PCT.into(),
                value: 12.5,
            }],
        };
        assert_eq!(
            decode::<MetricBatch>(&encode(&m).expect("enc")).expect("dec"),
            m
        );
    }

    #[test]
    fn unknown_field_rejected() {
        #[derive(Serialize)]
        struct Extra {
            v: u8,
            msg_id: Uuid,
            sent_at: i64,
            agent_version: String,
            uptime_s: u64,
            client_id: String,
        }
        let bytes = encode(&Extra {
            v: 1,
            msg_id: Uuid::now_v7(),
            sent_at: 0,
            agent_version: "x".into(),
            uptime_s: 0,
            client_id: "c".into(),
        })
        .expect("enc");
        assert!(decode::<Heartbeat>(&bytes).is_err());
    }

    #[test]
    fn hash_ignores_id_and_time_but_not_facts() {
        let a = inv();
        let mut b = a.clone();
        b.msg_id = Uuid::now_v7();
        b.sent_at += 1000;
        assert_eq!(a.hash(), b.hash());
        b.ram_bytes = Some(2 << 30);
        assert_ne!(a.hash(), b.hash());
    }
}
