//! The `ingest` subcommand: telemetry from JetStream into Postgres.
//!
//! Agents publish to `telemetry.<client>.<agent>.<kind>` (kinds `hb`, `inv`,
//! `metric`); authd's per-agent JWT makes that subject unforgeable, so the
//! client and agent ids come only from the subject and payloads carry none.
//! Ingest owns the `TELEM` stream and the durable pull consumer `ingest`,
//! fetches batches of up to 500 messages or 1 s, and writes each batch in one
//! service-scoped transaction as role `rmm_ingest`.
//!
//! Per message: a bad subject, an undecodable payload, an unknown or inactive
//! agent, or a subject client that is not the agent's client is terminated
//! (and counted); everything written is acknowledged after the commit; a
//! database failure naks the whole batch with a 5 s delay.
//!
//! This module only uses `crate`-independent code so the integration tests
//! can compile it directly (the package has no library target).

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_nats::jetstream::{self, AckKind, consumer, stream};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use futures_util::StreamExt;
use rmm_db::DbError;
use rmm_db::repo::Tx;
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::telemetry::{self, AgentTelemetryRow, InventoryUpdate, MetricRow};
use rmm_proto::telemetry::{
    Heartbeat, Inventory, MetricBatch, SCHEMA_VERSION, decode as decode_payload,
};
use serde_json::Value;
use uuid::Uuid;

/// Name of the JetStream stream holding all telemetry.
pub const STREAM: &str = "TELEM";
/// Name of the durable pull consumer.
pub const CONSUMER: &str = "ingest";
/// Most messages handled per transaction.
pub const BATCH_MAX: usize = 500;
/// Longest wait while filling a batch.
const BATCH_WAIT: Duration = Duration::from_secs(1);
/// Delay before a naked message is redelivered.
const NAK_DELAY: Duration = Duration::from_secs(5);
/// How long an agent lookup is reused.
const CACHE_TTL: Duration = Duration::from_secs(60);
/// Samples older than this are dropped.
const MAX_SAMPLE_AGE_MS: i64 = 7 * 24 * 3600 * 1000;
/// Samples further in the future than this are dropped.
const MAX_SAMPLE_FUTURE_MS: i64 = 5 * 60 * 1000;
/// Longest accepted metric name.
const MAX_METRIC_NAME: usize = 200;
/// How often the database and the consumer are probed.
const CHECK_EVERY: Duration = Duration::from_secs(10);
/// How old the last good database contact may be for /healthz to pass.
const DB_MAX_AGE_SECS: u64 = 30;
/// Dedupe records older than this are deleted.
const DEDUPE_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
/// How often the dedupe table is pruned.
const PRUNE_EVERY: Duration = Duration::from_secs(3600);
/// Role the ingest pool switches to on every connection.
const DB_ROLE: &str = "rmm_ingest";

/// What a telemetry subject carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Heartbeat.
    Hb,
    /// Inventory.
    Inv,
    /// Metric batch.
    Metric,
}

/// Split `telemetry.<client>.<agent>.<kind>` into its parts. Exactly four
/// tokens, both ids valid UUIDs, kind one of `hb`, `inv`, `metric`.
pub fn parse_subject(subject: &str) -> Option<(Uuid, Uuid, Kind)> {
    let mut tokens = subject.split('.');
    if tokens.next()? != "telemetry" {
        return None;
    }
    let uuid = |t: &str| (t.len() == 36).then(|| Uuid::parse_str(t).ok()).flatten();
    let client = uuid(tokens.next()?)?;
    let agent = uuid(tokens.next()?)?;
    let kind = match tokens.next()? {
        "hb" => Kind::Hb,
        "inv" => Kind::Inv,
        "metric" => Kind::Metric,
        _ => return None,
    };
    if tokens.next().is_some() {
        return None;
    }
    Some((client, agent, kind))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Unix milliseconds as a `SystemTime` (which converts into the database
/// timestamp type); `None` when negative or out of range.
fn ms_to_time(ms: i64) -> Option<SystemTime> {
    let ms = u64::try_from(ms).ok()?;
    UNIX_EPOCH.checked_add(Duration::from_millis(ms))
}

/// Whether a sample time is neither too old nor too far ahead.
fn in_window(t_ms: i64, now_ms: i64) -> bool {
    t_ms >= now_ms.saturating_sub(MAX_SAMPLE_AGE_MS)
        && t_ms <= now_ms.saturating_add(MAX_SAMPLE_FUTURE_MS)
}

/// Liveness inputs for /healthz.
#[derive(Debug, Default)]
pub struct Health {
    /// The NATS connection is up.
    pub nats_up: AtomicBool,
    /// The durable consumer exists.
    pub consumer_ok: AtomicBool,
    /// Unix time of the last successful database write or check (0 = never).
    pub db_ok_at: AtomicU64,
}

impl Health {
    /// Healthy when NATS is connected, the consumer exists and the database
    /// answered within the last 30 s.
    pub fn healthy(&self, now: u64) -> bool {
        let db = self.db_ok_at.load(Ordering::Relaxed);
        self.nats_up.load(Ordering::Relaxed)
            && self.consumer_ok.load(Ordering::Relaxed)
            && db != 0
            && now.saturating_sub(db) <= DB_MAX_AGE_SECS
    }

    fn db_ok(&self) {
        self.db_ok_at.store(unix_now(), Ordering::Relaxed);
    }

    fn db_failed(&self) {
        self.db_ok_at.store(0, Ordering::Relaxed);
    }
}

async fn health_handler(State(h): State<Arc<Health>>) -> StatusCode {
    if h.healthy(unix_now()) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn health_router(h: Arc<Health>) -> Router {
    Router::new()
        .route("/healthz", get(health_handler))
        .with_state(h)
}

/// Counters logged every 60 s.
#[derive(Debug, Default)]
pub struct Stats {
    /// Heartbeats applied.
    pub heartbeats: AtomicU64,
    /// Inventories that changed something.
    pub inventory_changed: AtomicU64,
    /// Inventories identical to the stored one (or for an invisible device).
    pub inventory_unchanged: AtomicU64,
    /// Metric rows inserted.
    pub metric_rows: AtomicU64,
    /// Samples dropped (too old, too new, not finite, bad name).
    pub samples_dropped: AtomicU64,
    /// Messages on a subject that does not parse.
    pub bad_subject: AtomicU64,
    /// Messages whose payload does not decode.
    pub malformed: AtomicU64,
    /// Messages for an agent that does not exist.
    pub unknown_agent: AtomicU64,
    /// Messages for an agent that is not active.
    pub inactive_agent: AtomicU64,
    /// Messages whose subject client is not the agent's client.
    pub identity_mismatch: AtomicU64,
    /// Batches that failed on the database (and were naked).
    pub db_errors: AtomicU64,
    /// Inventory and metric messages acked without writing (msg_id seen before).
    pub duplicates: AtomicU64,
}

impl Stats {
    fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Read one counter.
    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    fn log(&self) {
        tracing::info!(
            heartbeats = Self::get(&self.heartbeats),
            inventory_changed = Self::get(&self.inventory_changed),
            inventory_unchanged = Self::get(&self.inventory_unchanged),
            metric_rows = Self::get(&self.metric_rows),
            samples_dropped = Self::get(&self.samples_dropped),
            bad_subject = Self::get(&self.bad_subject),
            malformed = Self::get(&self.malformed),
            unknown_agent = Self::get(&self.unknown_agent),
            inactive_agent = Self::get(&self.inactive_agent),
            identity_mismatch = Self::get(&self.identity_mismatch),
            db_errors = Self::get(&self.db_errors),
            duplicates = Self::get(&self.duplicates),
            "ingest counters"
        );
    }
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type BeginFn = Box<dyn Fn() -> BoxFut<Result<Tx<'static>, DbError>> + Send + Sync>;
type PingFn = Box<dyn Fn() -> BoxFut<Result<i32, DbError>> + Send + Sync>;

/// Database access without naming the pool type (sqlx is not a direct
/// dependency of this crate).
pub struct Db {
    begin: BeginFn,
    ping: PingFn,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Db")
    }
}

/// Add a server-side statement timeout to a Postgres URL.
fn with_statement_timeout(url: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}options[statement_timeout]=10000")
}

impl Db {
    /// A database from two closures (tests use this to inject failures).
    pub fn new(begin: BeginFn, ping: PingFn) -> Self {
        Self { begin, ping }
    }

    /// Connect as the restricted `rmm_ingest` role.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let pool = rmm_db::scope::connect_as(&with_statement_timeout(url), DB_ROLE).await?;
        let (p1, p2) = (pool.clone(), pool);
        Ok(Self::new(
            Box::new(move || {
                let pool = p1.clone();
                Box::pin(
                    async move { begin_scoped(&pool, &Scope::Service("ingest"), "ingest").await },
                )
            }),
            Box::new(move || {
                let pool = p2.clone();
                Box::pin(async move { rmm_db::ping(&pool).await })
            }),
        ))
    }

    async fn begin(&self) -> Result<Tx<'static>, DbError> {
        (self.begin)().await
    }

    async fn ping(&self) -> Result<i32, DbError> {
        (self.ping)().await
    }
}

/// One message to process: its subject and payload.
#[derive(Debug, Clone, Copy)]
pub struct Incoming<'a> {
    /// NATS subject.
    pub subject: &'a str,
    /// CBOR payload.
    pub payload: &'a [u8],
}

/// What to do with each message of a batch, by index into the input.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BatchOutcome {
    /// Handled and committed: acknowledge.
    pub acked: Vec<usize>,
    /// Never going to succeed: terminate.
    pub termed: Vec<usize>,
    /// Could not be handled now: negative-acknowledge with a delay.
    pub naked: Vec<usize>,
}

enum Parsed {
    Hb(Heartbeat),
    Inv(Box<Inventory>),
    Metric(MetricBatch),
}

impl Parsed {
    /// The message id used for durable dedupe (inventory and metrics only).
    fn msg_id(&self) -> Option<Uuid> {
        match self {
            Self::Hb(_) => None,
            Self::Inv(i) => Some(i.msg_id),
            Self::Metric(m) => Some(m.msg_id),
        }
    }
}

struct Item {
    idx: usize,
    client: Uuid,
    agent: Uuid,
    parsed: Parsed,
}

fn has_nul(s: &str) -> bool {
    s.contains('\0')
}

fn decode_item(kind: Kind, payload: &[u8]) -> Option<Parsed> {
    match kind {
        Kind::Hb => {
            let hb: Heartbeat = decode_payload(payload).ok()?;
            (hb.v == SCHEMA_VERSION && !has_nul(&hb.agent_version)).then_some(Parsed::Hb(hb))
        }
        Kind::Inv => {
            let inv: Inventory = decode_payload(payload).ok()?;
            let clean = ![&inv.os_family, &inv.os_version, &inv.hostname]
                .into_iter()
                .any(|s| has_nul(s))
                && !inv.cpu_model.as_deref().is_some_and(has_nul)
                && !inv.volumes.iter().any(|v| has_nul(&v.mount));
            (inv.v == SCHEMA_VERSION && clean).then(|| Parsed::Inv(Box::new(inv)))
        }
        Kind::Metric => {
            let m: MetricBatch = decode_payload(payload).ok()?;
            (m.v == SCHEMA_VERSION).then_some(Parsed::Metric(m))
        }
    }
}

fn clamp_u64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Map a decoded inventory to the typed columns and the stored document
/// (the full inventory without `msg_id` and `sent_at`).
pub fn inventory_update(inv: &Inventory, now_ms: i64) -> InventoryUpdate {
    let mut doc = serde_json::to_value(inv).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut doc {
        m.remove("msg_id");
        m.remove("sent_at");
    }
    let total = inv
        .volumes
        .iter()
        .fold(0i64, |a, v| a.saturating_add(clamp_u64(v.total_bytes)));
    let free = inv
        .volumes
        .iter()
        .fold(0i64, |a, v| a.saturating_add(clamp_u64(v.free_bytes)));
    let last_boot = inv
        .last_boot
        .and_then(|s| s.checked_mul(1000))
        .filter(|ms| *ms <= now_ms.saturating_add(MAX_SAMPLE_FUTURE_MS))
        .and_then(ms_to_time)
        .map(Into::into);
    InventoryUpdate {
        os_version: Some(inv.os_version.clone()),
        cpu_model: inv.cpu_model.clone(),
        cpu_cores: inv.cpu_cores.and_then(|c| i32::try_from(c).ok()),
        ram_bytes: inv.ram_bytes.map(clamp_u64),
        disk_total_bytes: Some(total),
        disk_free_bytes: Some(free),
        last_boot,
        inventory: doc,
        inventory_hash: inv.hash(),
    }
}

/// The rows of a metric batch for `agent`, and how many samples were dropped.
/// Client and device come from the agent lookup; the payload has none.
pub fn metric_rows(
    agent: &AgentTelemetryRow,
    batch: &MetricBatch,
    now_ms: i64,
) -> (Vec<MetricRow>, u64) {
    let mut rows = Vec::with_capacity(batch.samples.len());
    let mut dropped = 0u64;
    for s in &batch.samples {
        let time = in_window(s.t, now_ms)
            .then(|| ms_to_time(s.t))
            .flatten()
            .filter(|_| {
                s.value.is_finite()
                    && !s.metric.is_empty()
                    && s.metric.len() <= MAX_METRIC_NAME
                    && !has_nul(&s.metric)
            });
        match time {
            Some(t) => rows.push(MetricRow {
                time: t.into(),
                client_id: agent.client_id,
                device_id: agent.device_id,
                metric: s.metric.clone(),
                value: s.value,
            }),
            None => dropped += 1,
        }
    }
    (rows, dropped)
}

/// Decodes batches and writes them; owns the agent cache and the counters.
#[derive(Debug)]
pub struct Processor {
    db: Db,
    cache: Mutex<HashMap<Uuid, (Instant, AgentTelemetryRow)>>,
    /// Counters.
    pub stats: Stats,
    /// Liveness inputs.
    pub health: Arc<Health>,
}

impl Processor {
    /// A processor writing through `db`.
    pub fn new(db: Db, health: Arc<Health>) -> Self {
        Self {
            db,
            cache: Mutex::new(HashMap::new()),
            stats: Stats::default(),
            health,
        }
    }

    fn cached(&self, agent: Uuid) -> Option<AgentTelemetryRow> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .get(&agent)
            .filter(|(at, _)| at.elapsed() < CACHE_TTL)
            .map(|(_, row)| row.clone())
    }

    fn remember(&self, row: &AgentTelemetryRow) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() > 10_000 {
            cache.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
        }
        cache.insert(row.agent_id, (Instant::now(), row.clone()));
    }

    /// Delete dedupe records older than the retention.
    pub async fn prune(&self) -> Result<u64, DbError> {
        let mut tx = self.db.begin().await?;
        let cutoff = SystemTime::now()
            .checked_sub(DEDUPE_RETENTION)
            .unwrap_or(UNIX_EPOCH);
        let n = telemetry::prune_ingested(&mut tx, cutoff.into()).await?;
        tx.commit().await?;
        Ok(n)
    }

    /// Handle one batch. Identity (client and agent) comes from the subject
    /// and is checked against the agent row; all writes share one
    /// transaction, so a database failure naks every message that needed it.
    pub async fn process_batch(&self, msgs: &[Incoming<'_>]) -> BatchOutcome {
        let now_ms = now_ms();
        let mut out = BatchOutcome::default();
        let mut items = Vec::with_capacity(msgs.len());
        for (idx, m) in msgs.iter().enumerate() {
            let Some((client, agent, kind)) = parse_subject(m.subject) else {
                Stats::bump(&self.stats.bad_subject);
                out.termed.push(idx);
                continue;
            };
            match decode_item(kind, m.payload) {
                Some(parsed) => items.push(Item {
                    idx,
                    client,
                    agent,
                    parsed,
                }),
                None => {
                    Stats::bump(&self.stats.malformed);
                    out.termed.push(idx);
                }
            }
        }
        if items.is_empty() {
            return out;
        }
        match self.write(&items, now_ms).await {
            Ok(verdicts) => {
                self.health.db_ok();
                for (idx, ack) in verdicts {
                    if ack {
                        out.acked.push(idx);
                    } else {
                        out.termed.push(idx);
                    }
                }
            }
            Err(err) => {
                Stats::bump(&self.stats.db_errors);
                self.health.db_failed();
                tracing::warn!(%err, messages = items.len(), "batch failed, naking");
                out.naked.extend(items.iter().map(|i| i.idx));
            }
        }
        out.acked.sort_unstable();
        out.termed.sort_unstable();
        out
    }

    /// One transaction for the whole batch; `(index, ack)` per message, where
    /// `false` means terminate.
    async fn write(&self, items: &[Item], now_ms: i64) -> Result<Vec<(usize, bool)>, DbError> {
        let mut tx = self.db.begin().await?;
        let mut agents: HashMap<Uuid, Option<AgentTelemetryRow>> = HashMap::new();
        for it in items {
            if agents.contains_key(&it.agent) {
                continue;
            }
            let row = match self.cached(it.agent) {
                Some(r) => Some(r),
                None => {
                    let r = telemetry::agent_for_telemetry(&mut tx, it.agent).await?;
                    if let Some(r) = r.as_ref().filter(|r| r.status == "active") {
                        self.remember(r);
                    }
                    r
                }
            };
            agents.insert(it.agent, row);
        }

        let at = ms_to_time(now_ms);
        let mut verdicts = Vec::with_capacity(items.len());
        let mut valid: Vec<(&Item, &AgentTelemetryRow)> = Vec::with_capacity(items.len());
        for it in items {
            let Some(Some(agent)) = agents.get(&it.agent) else {
                Stats::bump(&self.stats.unknown_agent);
                verdicts.push((it.idx, false));
                continue;
            };
            if agent.status != "active" {
                Stats::bump(&self.stats.inactive_agent);
                verdicts.push((it.idx, false));
                continue;
            }
            if agent.client_id != it.client {
                Stats::bump(&self.stats.identity_mismatch);
                tracing::warn!(subject_client = %it.client, agent = %it.agent, "subject client is not the agent's client");
                verdicts.push((it.idx, false));
                continue;
            }
            valid.push((it, agent));
        }

        // Durable dedupe: claim the msg_id of every inventory and metric
        // message in this transaction; an id that was already recorded (an
        // earlier batch, or earlier in this one) is acked without writing.
        let ids: Vec<Uuid> = valid
            .iter()
            .filter_map(|(it, _)| it.parsed.msg_id())
            .collect();
        let mut claimed = telemetry::claim_msg_ids(&mut tx, &ids).await?;

        let mut rows: Vec<MetricRow> = Vec::new();
        let mut dropped = 0u64;
        let mut heartbeats = 0u64;
        let mut duplicates = 0u64;
        let (mut changed, mut unchanged) = (0u64, 0u64);
        for (it, agent) in valid {
            if let Some(id) = it.parsed.msg_id() {
                // `remove` makes a repeat of the same id in this batch a duplicate.
                if !claimed.remove(&id) {
                    duplicates += 1;
                    verdicts.push((it.idx, true));
                    continue;
                }
            }
            match &it.parsed {
                Parsed::Hb(hb) => {
                    let sent = if in_window(hb.sent_at, now_ms) {
                        ms_to_time(hb.sent_at)
                    } else {
                        at
                    };
                    if let Some(t) = sent.or(at) {
                        telemetry::touch_heartbeat(&mut tx, agent.agent_id, t.into()).await?;
                        heartbeats += 1;
                    }
                }
                Parsed::Inv(inv) => {
                    let update = inventory_update(inv, now_ms);
                    if let Some(t) = at {
                        let res = telemetry::apply_inventory(
                            &mut tx,
                            agent.client_id,
                            agent.device_id,
                            &update,
                            t.into(),
                        )
                        .await?;
                        if res.is_some() {
                            changed += 1;
                        } else {
                            unchanged += 1;
                        }
                    }
                }
                Parsed::Metric(batch) => {
                    let (r, d) = metric_rows(agent, batch, now_ms);
                    rows.extend(r);
                    dropped += d;
                }
            }
            verdicts.push((it.idx, true));
        }
        let inserted = telemetry::insert_metrics(&mut tx, &rows).await?;
        tx.commit().await?;

        let add = |c: &AtomicU64, n: u64| {
            c.fetch_add(n, Ordering::Relaxed);
        };
        add(&self.stats.heartbeats, heartbeats);
        add(&self.stats.inventory_changed, changed);
        add(&self.stats.inventory_unchanged, unchanged);
        add(&self.stats.metric_rows, inserted);
        add(&self.stats.samples_dropped, dropped);
        add(&self.stats.duplicates, duplicates);
        Ok(verdicts)
    }
}

/// ingest settings from the environment.
#[derive(Debug)]
struct Config {
    nats_url: String,
    nats_user: String,
    nats_password: String,
    database_url: String,
    listen: String,
}

fn env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutdown signal received");
}

async fn serve_health(listen: &str, health: Arc<Health>) -> Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("bad listen address {listen}"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, health_router(health))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn is_up(c: &async_nats::Client) -> bool {
    c.connection_state() == async_nats::connection::State::Connected
}

/// The `TELEM` stream settings.
fn stream_config() -> stream::Config {
    stream::Config {
        name: STREAM.to_owned(),
        subjects: vec!["telemetry.>".to_owned()],
        storage: stream::StorageType::File,
        max_age: Duration::from_secs(3 * 24 * 3600),
        discard: stream::DiscardPolicy::Old,
        duplicate_window: Duration::from_secs(120),
        ..Default::default()
    }
}

/// The durable pull consumer settings.
fn consumer_config() -> consumer::pull::Config {
    consumer::pull::Config {
        durable_name: Some(CONSUMER.to_owned()),
        ack_policy: consumer::AckPolicy::Explicit,
        ack_wait: Duration::from_secs(30),
        max_deliver: 5,
        ..Default::default()
    }
}

/// Create or update the stream and the consumer.
async fn ensure_consumer(
    js: &jetstream::Context,
) -> Result<consumer::Consumer<consumer::pull::Config>> {
    js.create_or_update_stream(stream_config())
        .await
        .context("create or update stream TELEM")?;
    let stream = js.get_stream(STREAM).await.context("get stream TELEM")?;
    let consumer = stream
        .create_consumer(consumer_config())
        .await
        .context("create consumer ingest")?;
    Ok(consumer)
}

/// Probe the database and the consumer, mirroring both into [`Health`].
async fn check_loop(client: async_nats::Client, js: jetstream::Context, proc: Arc<Processor>) {
    loop {
        let health = &proc.health;
        health.nats_up.store(is_up(&client), Ordering::Relaxed);
        let consumer_ok = match js.get_stream(STREAM).await {
            Ok(s) => s.consumer_info(CONSUMER).await.is_ok(),
            Err(_) => false,
        };
        health.consumer_ok.store(consumer_ok, Ordering::Relaxed);
        match tokio::time::timeout(Duration::from_secs(5), proc.db.ping()).await {
            Ok(Ok(_)) => health.db_ok(),
            Ok(Err(err)) => {
                health.db_failed();
                tracing::warn!(%err, "database check failed");
            }
            Err(_) => {
                health.db_failed();
                tracing::warn!("database check timed out");
            }
        }
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

/// Prune the dedupe table once an hour.
async fn prune_loop(proc: Arc<Processor>) {
    loop {
        match proc.prune().await {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "pruned ingest dedupe records"),
            Err(err) => tracing::warn!(%err, "ingest dedupe prune failed"),
        }
        tokio::time::sleep(PRUNE_EVERY).await;
    }
}

async fn log_loop(proc: Arc<Processor>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        proc.stats.log();
    }
}

/// Fetch, process and acknowledge batches forever.
async fn consume_loop(consumer: consumer::Consumer<consumer::pull::Config>, proc: Arc<Processor>) {
    loop {
        let mut batch = match consumer
            .batch()
            .max_messages(BATCH_MAX)
            .expires(BATCH_WAIT)
            .messages()
            .await
        {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(%err, "fetch failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let mut msgs = Vec::new();
        while let Some(m) = batch.next().await {
            match m {
                Ok(m) => msgs.push(m),
                Err(err) => tracing::warn!(%err, "fetch error"),
            }
        }
        if msgs.is_empty() {
            continue;
        }
        let incoming: Vec<Incoming<'_>> = msgs
            .iter()
            .map(|m| Incoming {
                subject: m.subject.as_str(),
                payload: &m.payload,
            })
            .collect();
        let outcome = proc.process_batch(&incoming).await;
        let lists = [
            (&outcome.acked, AckKind::Ack),
            (&outcome.termed, AckKind::Term),
            (&outcome.naked, AckKind::Nak(Some(NAK_DELAY))),
        ];
        for (idxs, kind) in lists {
            for &i in idxs {
                if let Err(err) = msgs[i].ack_with(kind).await {
                    tracing::warn!(%err, "ack failed");
                }
            }
        }
    }
}

/// Connect everything (retrying with backoff) and consume until the process
/// is stopped.
async fn worker(cfg: Arc<Config>, health: Arc<Health>) {
    let mut backoff = Duration::from_millis(500);
    let next = |b: Duration| (b * 2).min(Duration::from_secs(10));
    let client = loop {
        let attempt = async_nats::ConnectOptions::with_user_and_password(
            cfg.nats_user.clone(),
            cfg.nats_password.clone(),
        )
        .name("rmm-ingest")
        .no_echo()
        .retry_on_initial_connect()
        .connect(cfg.nats_url.as_str())
        .await;
        match attempt {
            Ok(c) => break c,
            Err(err) => {
                tracing::warn!(%err, "nats connect failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = next(backoff);
            }
        }
    };
    let js = jetstream::new(client.clone());
    let consumer = loop {
        match ensure_consumer(&js).await {
            Ok(c) => break c,
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "jetstream setup failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = next(backoff);
            }
        }
    };
    health.consumer_ok.store(true, Ordering::Relaxed);
    health.nats_up.store(is_up(&client), Ordering::Relaxed);
    let db = loop {
        match Db::connect(&cfg.database_url).await {
            Ok(db) => break db,
            Err(err) => {
                tracing::warn!(%err, "database connect failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = next(backoff);
            }
        }
    };
    tracing::info!("ingest consuming");
    let proc = Arc::new(Processor::new(db, health));
    tokio::spawn(check_loop(client, js, proc.clone()));
    tokio::spawn(log_loop(proc.clone()));
    tokio::spawn(prune_loop(proc.clone()));
    consume_loop(consumer, proc).await;
}

/// Run ingest until a shutdown signal. Reads `RMM_NATS_URL`, `RMM_NATS_USER`
/// (default `ingest`), `RMM_NATS_PASSWORD`, `RMM_DATABASE_URL` and
/// `RMM_HEALTH_LISTEN` (default `0.0.0.0:8081`).
pub async fn run() -> Result<()> {
    let cfg = Arc::new(Config {
        nats_url: env_required("RMM_NATS_URL")?,
        nats_user: env_or("RMM_NATS_USER", "ingest"),
        nats_password: env_required("RMM_NATS_PASSWORD")?,
        database_url: env_required("RMM_DATABASE_URL")?,
        listen: env_or("RMM_HEALTH_LISTEN", "0.0.0.0:8081"),
    });
    let health = Arc::new(Health::default());
    let task = tokio::spawn(worker(cfg.clone(), health.clone()));
    let result = serve_health(&cfg.listen, health).await;
    task.abort();
    result
}
