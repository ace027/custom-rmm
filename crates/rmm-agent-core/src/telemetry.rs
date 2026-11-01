//! Agent-side telemetry publisher: heartbeat, metrics and inventory.
//!
//! Heartbeats use core NATS publish; metrics and inventory use JetStream with
//! `Nats-Msg-Id` set to the message's UUIDv7 and wait for the ack. Failures
//! are logged and the loop continues (offline queueing is a later phase).

use std::time::Duration;

use rand::TryRng;
use rmm_platform::Platform;
use rmm_platform::collect::{self, InventoryFacts};
use rmm_proto::telemetry::{
    self, Heartbeat, Inventory, KIND_HEARTBEAT, KIND_INVENTORY, KIND_METRIC, MetricBatch,
    SCHEMA_VERSION, Sample, TelemetryError,
};
use tokio::time::Instant;
pub use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::identity::Identity;

/// Environment variable read by [`Intervals::from_env_debug`] (debug builds only).
pub const INTERVALS_ENV: &str = "RMM_AGENT_TELEMETRY_INTERVALS";

const DEFAULT_HB: Duration = Duration::from_secs(30);
const DEFAULT_METRIC: Duration = Duration::from_secs(60);
const DEFAULT_INV: Duration = Duration::from_secs(6 * 60 * 60);
/// How often the inventory is re-checked for changes.
const INV_CHECK: Duration = Duration::from_secs(5 * 60);
/// Smallest accepted interval from the environment.
const MIN_INTERVAL_S: f64 = 0.01;
/// Largest accepted interval from the environment (one day).
const MAX_INTERVAL_S: f64 = 86_400.0;
/// How long to wait for a JetStream ack.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
/// Jitter fraction applied to every interval.
const JITTER: f64 = 0.10;

/// Publishing cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intervals {
    /// Heartbeat period.
    pub hb: Duration,
    /// Metric batch period.
    pub metric: Duration,
    /// Forced inventory re-send period; the change check runs every
    /// `min(inv, 5 min)`.
    pub inv: Duration,
}

impl Default for Intervals {
    fn default() -> Self {
        Self {
            hb: DEFAULT_HB,
            metric: DEFAULT_METRIC,
            inv: DEFAULT_INV,
        }
    }
}

impl Intervals {
    /// Parse `hb=2,metric=0.05,inv=5` (decimal seconds, clamped to at least
    /// 0.01 s). Unknown keys and malformed values keep the default.
    pub fn parse(s: &str) -> Self {
        let mut out = Self::default();
        for part in s.split(',') {
            let Some((key, val)) = part.split_once('=') else {
                continue;
            };
            let Ok(secs) = val.trim().parse::<f64>() else {
                continue;
            };
            if !secs.is_finite() {
                continue;
            }
            let d = Duration::from_secs_f64(secs.clamp(MIN_INTERVAL_S, MAX_INTERVAL_S));
            match key.trim() {
                "hb" => out.hb = d,
                "metric" => out.metric = d,
                "inv" => out.inv = d,
                _ => {}
            }
        }
        out
    }

    /// Intervals from `RMM_AGENT_TELEMETRY_INTERVALS` in debug builds; the
    /// defaults in release builds.
    pub fn from_env_debug() -> Self {
        if cfg!(debug_assertions) {
            std::env::var(INTERVALS_ENV)
                .map(|v| Self::parse(&v))
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Period of the inventory change check.
    pub fn inv_check(&self) -> Duration {
        self.inv.min(INV_CHECK)
    }
}

/// Telemetry subject for this identity and kind (`hb`, `inv`, `metric`).
pub fn subject(identity: &Identity, kind: &str) -> String {
    rmm_proto::subjects::telemetry(
        &identity.client_id.to_string(),
        &identity.agent_id.to_string(),
        kind,
    )
}

/// Scale `d` by a factor in `[0.9, 1.1]` chosen from `unit` in `[0, 1]`.
pub fn jitter_with(d: Duration, unit: f64) -> Duration {
    let unit = if unit.is_finite() {
        unit.clamp(0.0, 1.0)
    } else {
        0.5
    };
    d.mul_f64(1.0 - JITTER + 2.0 * JITTER * unit)
}

/// `d` with +-10% random jitter.
pub fn jitter(d: Duration) -> Duration {
    let mut r = [0u8; 4];
    let _ = rand::rngs::SysRng.try_fill_bytes(&mut r);
    jitter_with(d, f64::from(u32::from_le_bytes(r)) / f64::from(u32::MAX))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Build a heartbeat.
pub fn build_heartbeat(uptime_s: u64) -> Heartbeat {
    Heartbeat {
        v: SCHEMA_VERSION,
        msg_id: Uuid::now_v7(),
        sent_at: now_ms(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_s,
    }
}

/// Build an inventory message from collected facts.
pub fn build_inventory(f: InventoryFacts) -> Inventory {
    Inventory {
        v: SCHEMA_VERSION,
        msg_id: Uuid::now_v7(),
        sent_at: now_ms(),
        os_family: f.os_family,
        os_version: f.os_version,
        hostname: f.hostname,
        cpu_model: f.cpu_model,
        cpu_cores: f.cpu_cores,
        ram_bytes: f.ram_bytes,
        volumes: f.volumes,
        last_boot: f.last_boot,
    }
}

/// Build a metric batch, dropping NaN and infinite values; `None` if nothing
/// is left to send.
pub fn build_batch(samples: Vec<(String, f64)>) -> Option<MetricBatch> {
    let t = now_ms();
    let samples: Vec<Sample> = samples
        .into_iter()
        .filter(|(_, v)| v.is_finite())
        .map(|(metric, value)| Sample { t, metric, value })
        .collect();
    (!samples.is_empty()).then(|| MetricBatch {
        v: SCHEMA_VERSION,
        msg_id: Uuid::now_v7(),
        sent_at: t,
        samples,
    })
}

struct Publisher {
    client: async_nats::Client,
    js: async_nats::jetstream::Context,
}

impl Publisher {
    async fn heartbeat(&self, subject: String, hb: &Heartbeat) {
        match telemetry::encode(hb) {
            Ok(bytes) => {
                if let Err(e) = self.client.publish(subject, bytes.into()).await {
                    tracing::warn!("heartbeat publish failed: {e}");
                }
            }
            Err(e) => tracing::warn!("heartbeat encode failed: {e}"),
        }
    }

    /// JetStream publish with dedupe id; returns whether it was acked.
    async fn acked(&self, subject: String, msg_id: Uuid, payload: Vec<u8>) -> bool {
        let publish = async_nats::jetstream::message::PublishMessage::build()
            .message_id(msg_id.to_string())
            .payload(payload.into());
        let fut = match self.js.send_publish(subject.clone(), publish).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(%subject, "jetstream publish failed: {e}");
                return false;
            }
        };
        match tokio::time::timeout(ACK_TIMEOUT, fut).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                tracing::warn!(%subject, "jetstream ack failed: {e}");
                false
            }
            Err(_) => {
                tracing::warn!(%subject, "jetstream ack timed out");
                false
            }
        }
    }
}

/// Publish heartbeat, metrics and inventory until `shutdown` is cancelled.
/// Publish errors are logged and never end the loop.
pub async fn run_telemetry(
    client: async_nats::Client,
    identity: &Identity,
    platform: impl Platform + Send,
    intervals: Intervals,
    shutdown: CancellationToken,
) -> Result<(), TelemetryError> {
    let publisher = Publisher {
        js: async_nats::jetstream::new(client.clone()),
        client,
    };
    let hb_subject = subject(identity, KIND_HEARTBEAT);
    let inv_subject = subject(identity, KIND_INVENTORY);
    let metric_subject = subject(identity, KIND_METRIC);

    let start = Instant::now();
    let mut next_hb = start;
    let mut next_inv = start;
    let mut next_metric = start + jitter(intervals.metric);
    let mut last_inv: Option<([u8; 32], Instant)> = None;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep_until(next_hb) => {
                let uptime = tokio::task::spawn_blocking(collect::uptime_s).await.unwrap_or(0);
                publisher.heartbeat(hb_subject.clone(), &build_heartbeat(uptime)).await;
                next_hb = Instant::now() + jitter(intervals.hb);
            }
            () = tokio::time::sleep_until(next_metric) => {
                let samples = tokio::task::spawn_blocking(collect::sample).await.unwrap_or_default();
                if let Some(batch) = build_batch(samples) {
                    match telemetry::encode(&batch) {
                        Ok(bytes) => {
                            publisher.acked(metric_subject.clone(), batch.msg_id, bytes).await;
                        }
                        Err(e) => tracing::warn!("metric encode failed: {e}"),
                    }
                }
                next_metric = Instant::now() + jitter(intervals.metric);
            }
            () = tokio::time::sleep_until(next_inv) => {
                if let Ok(mut facts) = tokio::task::spawn_blocking(collect::inventory).await {
                    let (family, version) = platform.os_info();
                    facts.os_family = family;
                    facts.os_version = version;
                    if let Ok(name) = platform.hostname() {
                        facts.hostname = name;
                    }
                    let inv = build_inventory(facts);
                    let hash = inv.hash();
                    let due = match &last_inv {
                        None => true,
                        Some((h, at)) => *h != hash || at.elapsed() >= intervals.inv,
                    };
                    if due {
                        match telemetry::encode(&inv) {
                            Ok(bytes) => {
                                if publisher.acked(inv_subject.clone(), inv.msg_id, bytes).await {
                                    last_inv = Some((hash, Instant::now()));
                                }
                            }
                            Err(e) => tracing::warn!("inventory encode failed: {e}"),
                        }
                    }
                }
                next_inv = Instant::now() + jitter(intervals.inv_check());
            }
        }
    }
}
