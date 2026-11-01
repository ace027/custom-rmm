//! Agent-signed action results from the `RESULT` stream into `action_run`.
//!
//! Agents publish an `rmm.result/1` envelope on `result.<client>.<agent>`;
//! authd's per-agent JWT makes that subject unforgeable. A message is applied
//! only when: the subject parses, the agent exists and is `active` or
//! `revoked` (a revoked agent's last results still count) in the subject's
//! client, the envelope is signed by that agent's stored credential key, the
//! result names the subject agent, and an `action_run` of that agent with the
//! same command and definition exists. Everything else is terminated and
//! counted. A repeat for a finished run is acknowledged without a second
//! update; a database failure naks the message.
//!
//! The module is a child of `ingest` (it shares `Db`, `Health` and the
//! batch types) so the integration tests can compile it through that module.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_nats::jetstream::{self, AckKind, consumer, stream};
use futures_util::StreamExt;
use rmm_db::DbError;
use rmm_db::actions;
use rmm_db::repo;
use rmm_recipe::result::{ActionResult, Outcome, TYPE_RESULT};
use rmm_trust::envelope::Envelope;
use rmm_trust::keys::PublicKey;
use uuid::Uuid;

use super::{BATCH_MAX, BatchOutcome, Db, Health, Incoming};

/// Name of the JetStream stream holding action results.
pub const STREAM: &str = "RESULT";
/// Name of the durable pull consumer.
pub const CONSUMER: &str = "results";
/// Results are kept this long.
const MAX_AGE: Duration = Duration::from_secs(14 * 24 * 3600);
/// Longest wait while filling a batch.
const BATCH_WAIT: Duration = Duration::from_secs(1);
/// Delay before a naked message is redelivered.
const NAK_DELAY: Duration = Duration::from_secs(5);
/// How often the consumer is probed.
const CHECK_EVERY: Duration = Duration::from_secs(10);

/// Counters logged every 60 s.
#[derive(Debug, Default)]
pub struct ResultStats {
    /// Results recorded.
    pub applied: AtomicU64,
    /// Results for an already finished run (acked, not applied again).
    pub duplicates: AtomicU64,
    /// Messages on a subject that does not parse.
    pub bad_subject: AtomicU64,
    /// Messages that are not a valid result envelope.
    pub malformed: AtomicU64,
    /// Messages for an agent that does not exist.
    pub unknown_agent: AtomicU64,
    /// Messages for an agent that is neither active nor revoked.
    pub inactive_agent: AtomicU64,
    /// Messages not signed by the subject agent's key.
    pub bad_signature: AtomicU64,
    /// Results naming another agent, client or definition than the run.
    pub mismatch: AtomicU64,
    /// Results for a command that was never issued.
    pub unknown_cmd: AtomicU64,
    /// Messages naked because the database failed.
    pub db_errors: AtomicU64,
}

impl ResultStats {
    fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Read one counter.
    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    fn log(&self) {
        tracing::info!(
            applied = Self::get(&self.applied),
            duplicates = Self::get(&self.duplicates),
            bad_subject = Self::get(&self.bad_subject),
            malformed = Self::get(&self.malformed),
            unknown_agent = Self::get(&self.unknown_agent),
            inactive_agent = Self::get(&self.inactive_agent),
            bad_signature = Self::get(&self.bad_signature),
            mismatch = Self::get(&self.mismatch),
            unknown_cmd = Self::get(&self.unknown_cmd),
            db_errors = Self::get(&self.db_errors),
            "result counters"
        );
    }
}

/// Split `result.<client>.<agent>` into the two ids.
pub fn parse_subject(subject: &str) -> Option<(Uuid, Uuid)> {
    let mut tokens = subject.split('.');
    if tokens.next()? != "result" {
        return None;
    }
    let uuid = |t: &str| (t.len() == 36).then(|| Uuid::parse_str(t).ok()).flatten();
    let client = uuid(tokens.next()?)?;
    let agent = uuid(tokens.next()?)?;
    if tokens.next().is_some() {
        return None;
    }
    Some((client, agent))
}

/// A well-formed result envelope, not yet checked against any agent.
struct Decoded {
    envelope: Envelope,
    result: ActionResult,
}

fn decode(payload: &[u8]) -> Option<Decoded> {
    let envelope = Envelope::from_bytes(payload).ok()?;
    if envelope.r#type != TYPE_RESULT {
        return None;
    }
    let result = ActionResult::from_envelope_payload(&envelope.payload.0).ok()?;
    result.validate().ok()?;
    let clean = result.stages.iter().all(|s| !s.detail.contains('\0'));
    clean.then_some(Decoded { envelope, result })
}

/// Whether the envelope carries exactly one signature, by `pubkey`, that verifies.
fn signed_by(env: &Envelope, pubkey: &[u8]) -> bool {
    let Ok(raw) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(key) = PublicKey::from_bytes(&raw) else {
        return false;
    };
    matches!(env.sigs.as_slice(), [entry] if env.verify_sig(entry, &key).is_ok())
}

fn status_of(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Succeeded => "succeeded",
        Outcome::Failed => "failed",
        Outcome::RolledBack => "rolled_back",
        Outcome::Rejected => "rejected",
    }
}

/// What to do with one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Ack,
    Term,
}

/// Verifies and records results.
#[derive(Debug)]
pub struct ResultProcessor {
    db: Db,
    /// Counters.
    pub stats: ResultStats,
}

impl ResultProcessor {
    /// A processor writing through `db`.
    pub fn new(db: Db) -> Self {
        Self {
            db,
            stats: ResultStats::default(),
        }
    }

    /// Handle a batch; each message is verified and recorded in its own
    /// transaction. A database failure naks only that message.
    pub async fn process_batch(&self, msgs: &[Incoming<'_>]) -> BatchOutcome {
        let mut out = BatchOutcome::default();
        for (idx, m) in msgs.iter().enumerate() {
            match self.process_one(m).await {
                Ok(Verdict::Ack) => out.acked.push(idx),
                Ok(Verdict::Term) => out.termed.push(idx),
                Err(err) => {
                    ResultStats::bump(&self.stats.db_errors);
                    tracing::warn!(%err, "result not recorded, naking");
                    out.naked.push(idx);
                }
            }
        }
        out
    }

    async fn process_one(&self, m: &Incoming<'_>) -> Result<Verdict, DbError> {
        let s = &self.stats;
        let Some((client, agent_id)) = parse_subject(m.subject) else {
            ResultStats::bump(&s.bad_subject);
            return Ok(Verdict::Term);
        };
        let Some(Decoded { envelope, result }) = decode(m.payload) else {
            ResultStats::bump(&s.malformed);
            return Ok(Verdict::Term);
        };
        let Ok(cmd_id) = Uuid::from_slice(&result.cmd_id.0) else {
            ResultStats::bump(&s.malformed);
            return Ok(Verdict::Term);
        };

        let mut tx = self.db.begin().await?;
        let Some(agent) = actions::agent_credential(&mut tx, agent_id).await? else {
            ResultStats::bump(&s.unknown_agent);
            return Ok(Verdict::Term);
        };
        if agent.client_id != client || !matches!(agent.status.as_str(), "active" | "revoked") {
            ResultStats::bump(&s.inactive_agent);
            return Ok(Verdict::Term);
        }
        if !signed_by(&envelope, &agent.credential_pubkey) {
            ResultStats::bump(&s.bad_signature);
            tracing::warn!(%agent_id, %cmd_id, "result is not signed by the subject agent's key");
            return Ok(Verdict::Term);
        }
        if result.agent_id != agent_id.to_string() {
            ResultStats::bump(&s.mismatch);
            tracing::warn!(%agent_id, %cmd_id, claimed = %result.agent_id, "result names another agent");
            return Ok(Verdict::Term);
        }
        let Some(run) = actions::action_run(&mut tx, cmd_id).await? else {
            ResultStats::bump(&s.unknown_cmd);
            return Ok(Verdict::Term);
        };
        if run.agent_id != agent_id
            || run.client_id != client
            || run.definition_content_id != result.definition_content_id.0
        {
            ResultStats::bump(&s.mismatch);
            tracing::warn!(%agent_id, %cmd_id, "result does not match the issued command");
            return Ok(Verdict::Term);
        }

        let status = status_of(result.outcome);
        let reason = result
            .reason
            .and_then(|r| serde_json::to_value(r).ok())
            .and_then(|v| v.as_str().map(str::to_owned));
        let stages = serde_json::to_value(&result.stages).unwrap_or_default();
        // The agent's clock decides when the run finished; an unrepresentable
        // time falls back to now.
        let finished_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(result.finished_at))
            .unwrap_or_else(SystemTime::now);
        let recorded = actions::finish_action_run(
            &mut tx,
            cmd_id,
            status,
            reason.as_deref(),
            &stages,
            m.payload,
            finished_at.into(),
        )
        .await?;
        if !recorded {
            ResultStats::bump(&s.duplicates);
            return Ok(Verdict::Ack);
        }
        repo::insert_audit(
            &mut tx,
            &format!("agent:{agent_id}"),
            "action.result",
            Some(client),
            &format!("action_run:{cmd_id}"),
            &serde_json::json!({
                "cmd_id": cmd_id,
                "outcome": status,
                "reason": reason,
                "definition_content_id": data_encoding::HEXLOWER.encode(&run.definition_content_id),
            }),
        )
        .await?;
        tx.commit().await?;
        ResultStats::bump(&s.applied);
        Ok(Verdict::Ack)
    }
}

/// The `RESULT` stream settings.
fn stream_config() -> stream::Config {
    stream::Config {
        name: STREAM.to_owned(),
        subjects: vec!["result.>".to_owned()],
        storage: stream::StorageType::File,
        max_age: MAX_AGE,
        discard: stream::DiscardPolicy::Old,
        ..Default::default()
    }
}

/// The durable pull consumer settings.
fn consumer_config() -> consumer::pull::Config {
    consumer::pull::Config {
        durable_name: Some(CONSUMER.to_owned()),
        ack_policy: consumer::AckPolicy::Explicit,
        ack_wait: Duration::from_secs(30),
        // Unlimited: a database outage must not exhaust the delivery budget;
        // permanently bad messages are terminated explicitly instead.
        max_deliver: -1,
        ..Default::default()
    }
}

async fn ensure_consumer(
    js: &jetstream::Context,
) -> Result<consumer::Consumer<consumer::pull::Config>> {
    js.create_or_update_stream(stream_config())
        .await
        .context("create or update stream RESULT")?;
    let stream = js.get_stream(STREAM).await.context("get stream RESULT")?;
    stream
        .create_consumer(consumer_config())
        .await
        .context("create consumer results")
}

/// Mirror the consumer's existence into [`Health`] and log counters.
async fn check_loop(js: jetstream::Context, proc: Arc<ResultProcessor>, health: Arc<Health>) {
    let mut ticks = 0u32;
    loop {
        let ok = match js.get_stream(STREAM).await {
            Ok(s) => s.consumer_info(CONSUMER).await.is_ok(),
            Err(_) => false,
        };
        health.results_failed.store(!ok, Ordering::Relaxed);
        ticks += 1;
        if ticks.is_multiple_of(6) {
            proc.stats.log();
        }
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

/// Fetch, process and acknowledge batches forever.
async fn consume_loop(
    consumer: consumer::Consumer<consumer::pull::Config>,
    proc: Arc<ResultProcessor>,
) {
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
                tracing::warn!(%err, "result fetch failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let mut msgs = Vec::new();
        while let Some(m) = batch.next().await {
            match m {
                Ok(m) => msgs.push(m),
                Err(err) => tracing::warn!(%err, "result fetch error"),
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
                    tracing::warn!(%err, "result ack failed");
                }
            }
        }
    }
}

/// Create the stream and consumer (retrying with backoff), then consume
/// until the task is aborted. `health.results_failed` follows the consumer.
pub async fn run(js: jetstream::Context, db: Db, health: Arc<Health>) {
    let mut backoff = Duration::from_millis(500);
    let consumer = loop {
        match ensure_consumer(&js).await {
            Ok(c) => break c,
            Err(err) => {
                health.results_failed.store(true, Ordering::Relaxed);
                tracing::warn!(error = %format!("{err:#}"), "result stream setup failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        }
    };
    health.results_failed.store(false, Ordering::Relaxed);
    tracing::info!("results consuming");
    let proc = Arc::new(ResultProcessor::new(db));
    tokio::spawn(check_loop(js, proc.clone(), health));
    consume_loop(consumer, proc).await;
}
