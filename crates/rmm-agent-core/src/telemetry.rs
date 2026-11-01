//! Agent-side telemetry publisher: heartbeat, metrics and inventory.
//!
//! Heartbeats use core NATS publish and are never queued. Metrics and
//! inventory are written to the encrypted outbox first ([`crate::store`]); a
//! drain task publishes them through JetStream with `Nats-Msg-Id` set to the
//! message's UUIDv7, deletes a row only after its ack, backs off 1 s to 30 s on
//! failure and drains at once when the connection comes back. Ingest dedupes
//! by `msg_id`, so a re-publish after a lost ack is harmless.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand::TryRng;
use rmm_platform::Platform;
use rmm_platform::collect::{self, InventoryFacts};
use rmm_proto::telemetry::{
    self, Heartbeat, Inventory, KIND_HEARTBEAT, KIND_INVENTORY, KIND_METRIC, MetricBatch,
    SCHEMA_VERSION, Sample, TelemetryError,
};
use tokio::sync::Notify;
use tokio::time::Instant;
pub use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::identity::Identity;
use crate::store::{OutboxItem, Store, StoreError};

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
/// Outbox priority of inventory messages (drains first).
pub const PRIORITY_INVENTORY: u8 = 1;
/// Outbox priority of metric batches (dropped first when the outbox is full).
pub const PRIORITY_METRIC: u8 = 2;
/// Most outbox rows published concurrently by one drain step.
pub const MAX_IN_FLIGHT: usize = 200;
/// First retry delay of the drain task.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Longest retry delay of the drain task.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
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

/// Where the drain task publishes queued messages (JetStream in production, a
/// scripted fake in tests).
pub trait Sink: Send + Sync + 'static {
    /// Publish `items` in order; entry `i` of the result is true only if item
    /// `i` was acknowledged by the server.
    fn publish_batch(&self, items: &[OutboxItem]) -> impl Future<Output = Vec<bool>> + Send;
}

/// What one [`drain_once`] step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainOutcome {
    /// Rows acknowledged and deleted.
    pub sent: usize,
    /// Rows that were not acknowledged and stay queued.
    pub failed: usize,
    /// The outbox had nothing to send.
    pub empty: bool,
}

fn join_err(e: &tokio::task::JoinError) -> StoreError {
    StoreError::Io(format!("store task: {e}"))
}

/// Publish up to [`MAX_IN_FLIGHT`] queued rows (priority, then seq order) and
/// delete the acknowledged ones. Unacknowledged rows stay for the next step
/// with the same `msg_id`.
pub async fn drain_once<S: Sink>(store: &Arc<Store>, sink: &S) -> Result<DrainOutcome, StoreError> {
    let peek_store = Arc::clone(store);
    let items = tokio::task::spawn_blocking(move || peek_store.outbox_peek(MAX_IN_FLIGHT))
        .await
        .map_err(|e| join_err(&e))??;
    if items.is_empty() {
        return Ok(DrainOutcome {
            empty: true,
            ..DrainOutcome::default()
        });
    }
    let results = sink.publish_batch(&items).await;
    let acked: Vec<i64> = items
        .iter()
        .zip(results.iter().copied().chain(std::iter::repeat(false)))
        .filter_map(|(it, ok)| ok.then_some(it.seq))
        .collect();
    let sent = acked.len();
    let del_store = Arc::clone(store);
    tokio::task::spawn_blocking(move || {
        acked
            .into_iter()
            .try_for_each(|seq| del_store.outbox_delete(seq))
    })
    .await
    .map_err(|e| join_err(&e))??;
    Ok(DrainOutcome {
        sent,
        failed: items.len() - sent,
        empty: false,
    })
}

/// Drain the outbox until `shutdown`. Sleeps on `wake` (a row was queued) when
/// empty; after a failure waits `min..=max` (doubling) but `reconnect` cuts
/// the wait short and resets it.
pub async fn drain_loop<S: Sink>(
    store: Arc<Store>,
    sink: S,
    wake: Arc<Notify>,
    reconnect: Arc<Notify>,
    shutdown: CancellationToken,
    (min, max): (Duration, Duration),
) {
    let mut backoff = min;
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        match drain_once(&store, &sink).await {
            Ok(o) if o.empty => {
                backoff = min;
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = wake.notified() => {}
                    () = reconnect.notified() => {}
                }
            }
            Ok(o) if o.failed == 0 => backoff = min,
            outcome => {
                match outcome {
                    Ok(o) => {
                        if o.sent > 0 {
                            backoff = min;
                        }
                        tracing::warn!(sent = o.sent, failed = o.failed, "outbox drain incomplete");
                    }
                    Err(e) => tracing::error!("outbox drain failed: {e}"),
                }
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = reconnect.notified() => backoff = min,
                    () = tokio::time::sleep(backoff) => backoff = (backoff * 2).min(max),
                }
            }
        }
    }
}

/// JetStream sink: publishes with `Nats-Msg-Id` and waits for every ack.
struct JetStreamSink {
    client: async_nats::Client,
    js: async_nats::jetstream::Context,
}

impl Sink for JetStreamSink {
    async fn publish_batch(&self, items: &[OutboxItem]) -> Vec<bool> {
        // Do not hand rows to the client's offline buffer: they would only
        // time out, and the drain task retries on reconnect anyway.
        if self.client.connection_state() != async_nats::connection::State::Connected {
            return vec![false; items.len()];
        }
        let mut pending = Vec::with_capacity(items.len());
        for it in items {
            let publish = async_nats::jetstream::message::PublishMessage::build()
                .message_id(Uuid::from_bytes(it.msg_id).to_string())
                .payload(it.payload.clone().into());
            match self.js.send_publish(it.subject.clone(), publish).await {
                Ok(fut) => pending.push(Some(fut)),
                Err(e) => {
                    tracing::warn!(subject = %it.subject, "jetstream publish failed: {e}");
                    pending.push(None);
                }
            }
        }
        let deadline = Instant::now() + ACK_TIMEOUT;
        let mut out = Vec::with_capacity(pending.len());
        for fut in pending {
            let ok = match fut {
                Some(f) => match tokio::time::timeout_at(deadline, f).await {
                    Ok(Ok(_)) => true,
                    Ok(Err(e)) => {
                        tracing::warn!("jetstream ack failed: {e}");
                        false
                    }
                    Err(_) => {
                        tracing::warn!("jetstream ack timed out");
                        false
                    }
                },
                None => false,
            };
            out.push(ok);
        }
        out
    }
}

struct Publisher {
    client: async_nats::Client,
    store: Arc<Store>,
    wake: Arc<Notify>,
    dropped_seen: AtomicU64,
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

    /// Queue a message in the encrypted outbox and wake the drain task.
    /// Returns whether it is stored.
    async fn enqueue(&self, subject: String, priority: u8, msg_id: Uuid, payload: Vec<u8>) -> bool {
        let store = Arc::clone(&self.store);
        let pushed = tokio::task::spawn_blocking(move || {
            store.outbox_push(msg_id.into_bytes(), &subject, priority, &payload)
        })
        .await;
        let dropped = self.store.dropped_count();
        if self.dropped_seen.swap(dropped, Ordering::Relaxed) != dropped {
            tracing::warn!(
                dropped_total = dropped,
                "outbox full: oldest metrics dropped"
            );
        }
        match pushed {
            Ok(Ok(stored)) => {
                self.wake.notify_one();
                stored
            }
            Ok(Err(e)) => {
                tracing::error!("outbox write failed: {e}");
                false
            }
            Err(e) => {
                tracing::error!("outbox write task failed: {e}");
                false
            }
        }
    }
}

/// Publish heartbeat, metrics and inventory until `shutdown` is cancelled.
/// Metrics and inventory go through `store`'s outbox; `reconnect` must be
/// notified whenever the NATS connection (re)connects. Publish errors are
/// logged and never end the loop.
pub async fn run_telemetry(
    client: async_nats::Client,
    identity: &Identity,
    platform: impl Platform + Send,
    intervals: Intervals,
    store: Arc<Store>,
    reconnect: Arc<Notify>,
    shutdown: CancellationToken,
) -> Result<(), TelemetryError> {
    let wake = Arc::new(Notify::new());
    let drain = tokio::spawn(drain_loop(
        Arc::clone(&store),
        JetStreamSink {
            js: async_nats::jetstream::new(client.clone()),
            client: client.clone(),
        },
        Arc::clone(&wake),
        reconnect,
        shutdown.clone(),
        (BACKOFF_MIN, BACKOFF_MAX),
    ));
    let publisher = Publisher {
        client,
        store,
        wake,
        dropped_seen: AtomicU64::new(0),
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
            () = shutdown.cancelled() => {
                let _ = drain.await;
                return Ok(());
            }
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
                            publisher
                                .enqueue(metric_subject.clone(), PRIORITY_METRIC, batch.msg_id, bytes)
                                .await;
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
                                if publisher
                                    .enqueue(inv_subject.clone(), PRIORITY_INVENTORY, inv.msg_id, bytes)
                                    .await
                                {
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
