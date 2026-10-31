//! The `authd` subcommand: NATS auth callout for agents.
//!
//! Agents connect with their device key as user nkey. NATS forwards every
//! connection that is not a static service user to `$SYS.REQ.USER.AUTH`;
//! authd checks the nonce signature, looks the agent up in the database and
//! replies with a signed authorization response that carries a scoped,
//! WebSocket-only, one hour user JWT. Any failure is a deny with a generic
//! message. authd also kicks connections of agents the API revokes.
//!
//! The callout subscription uses a minimal NATS protocol reader ([`wire`])
//! because receiving from an `async_nats::Subscriber` needs the
//! `futures` `Stream` trait, which is not a dependency of this crate. The
//! SYS connection (connz and kick requests) uses `async_nats`.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use nkeys::KeyPair;
use rmm_db::DbError;
use rmm_db::repo::{self, AgentAuthRow, Tx};
use rmm_db::scope::Scope;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, mpsc};

use crate::natsjwt::{self, AuthRequest};

/// Subject NATS sends authorization requests to.
pub const AUTH_SUBJECT: &str = "$SYS.REQ.USER.AUTH";
/// Subject the API publishes revocations to.
pub const REVOKED_SUBJECT: &str = "rmm.internal.agent.revoked";
/// Budget for the database part of one decision.
const DB_TIMEOUT: Duration = Duration::from_secs(2);
/// How often the database is probed for /healthz.
const DB_CHECK_EVERY: Duration = Duration::from_secs(15);
/// How old the last good database probe may be for /healthz to pass.
const DB_CHECK_MAX_AGE_SECS: u64 = 30;
/// Callout requests handled concurrently; more are denied at once.
const MAX_IN_FLIGHT: usize = 256;
/// Generic message returned to denied clients.
const DENY_MESSAGE: &str = "not authorized";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Liveness inputs for /healthz.
#[derive(Debug, Default)]
pub struct Health {
    callout_up: AtomicBool,
    sys_up: AtomicBool,
    /// Unix time of the last successful database probe (0 = never).
    db_ok_at: AtomicU64,
}

impl Health {
    /// Healthy when both NATS connections are up and the database answered
    /// within the last 30 s.
    pub fn healthy(&self, now: u64) -> bool {
        let db = self.db_ok_at.load(Ordering::Relaxed);
        self.callout_up.load(Ordering::Relaxed)
            && self.sys_up.load(Ordering::Relaxed)
            && db != 0
            && now.saturating_sub(db) <= DB_CHECK_MAX_AGE_SECS
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

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Database access without naming the pool type (sqlx is not a direct
/// dependency of this crate).
struct Db {
    begin: Box<dyn Fn() -> BoxFut<Result<Tx<'static>, DbError>> + Send + Sync>,
    ping: Box<dyn Fn() -> BoxFut<Result<i32, DbError>> + Send + Sync>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Db")
    }
}

/// Add a 2 s server-side statement timeout to a Postgres URL.
fn with_statement_timeout(url: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}options[statement_timeout]=2000")
}

/// Connect (retrying forever) and then probe the database every 15 s.
async fn db_task(url: String, cell: Arc<OnceLock<Db>>, health: Arc<Health>) {
    let url = with_statement_timeout(&url);
    let mut backoff = Duration::from_millis(500);
    let pool = loop {
        match rmm_db::scope::connect_as(&url, "rmm_authd").await {
            Ok(p) => break p,
            Err(err) => {
                tracing::warn!(%err, "database connect failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        }
    };
    let (p1, p2) = (pool.clone(), pool);
    let db = Db {
        begin: Box::new(move || {
            let pool = p1.clone();
            Box::pin(async move {
                rmm_db::scope::begin_scoped(&pool, &Scope::Service("authd"), "authd").await
            })
        }),
        ping: Box::new(move || {
            let pool = p2.clone();
            Box::pin(async move { rmm_db::ping(&pool).await })
        }),
    };
    let db = cell.get_or_init(|| db);
    tracing::info!("database connected");
    loop {
        match tokio::time::timeout(DB_TIMEOUT, (db.ping)()).await {
            Ok(Ok(_)) => health.db_ok_at.store(unix_now(), Ordering::Relaxed),
            Ok(Err(err)) => tracing::warn!(%err, "database check failed"),
            Err(_) => tracing::warn!("database check timed out"),
        }
        tokio::time::sleep(DB_CHECK_EVERY).await;
    }
}

/// Outcome of a callout decision.
#[derive(Debug)]
enum Decision {
    Allow(AgentAuthRow),
    Deny(String),
}

/// Keep attacker-influenced strings in audit rows short.
fn clip(s: &str) -> String {
    s.chars().take(64).collect()
}

/// The checks that need no database: proof of key possession and transport.
fn precheck(req: &AuthRequest) -> std::result::Result<[u8; 32], String> {
    let key = natsjwt::verify_nonce_signature(req).map_err(|e| e.to_string())?;
    let ct = &req.client_info.conn_type;
    if !ct.is_empty() && !ct.eq_ignore_ascii_case("websocket") {
        return Err(format!("connection type {} not allowed", clip(ct)));
    }
    Ok(key)
}

/// Look up the agent, record the decision and commit, in one transaction.
async fn decide_in_db(
    db: &Db,
    req: &AuthRequest,
    pre: std::result::Result<[u8; 32], String>,
) -> std::result::Result<Decision, DbError> {
    let mut tx = (db.begin)().await?;
    let nkey_target = format!("nkey:{}", clip(&req.connect_opts.nkey));
    let (decision, client_id, target) = match pre {
        Err(reason) => (Decision::Deny(reason), None, nkey_target),
        Ok(key) => match repo::agent_by_pubkey(&mut tx, &key).await? {
            None => (Decision::Deny("unknown agent".into()), None, nkey_target),
            Some(a) => {
                let target = format!("agent:{}", a.agent_id);
                let client = Some(a.client_id);
                let d = if a.status != "active" {
                    Decision::Deny(format!("agent status {}", a.status))
                } else if a.client_status != "active" {
                    Decision::Deny(format!("client status {}", a.client_status))
                } else if a.nkey != req.connect_opts.nkey {
                    Decision::Deny("stored nkey does not match".into())
                } else {
                    repo::touch_last_seen(&mut tx, a.agent_id).await?;
                    Decision::Allow(a)
                };
                (d, client, target)
            }
        },
    };
    let (action, reason) = match &decision {
        Decision::Allow(_) => ("nats.auth.allow", None),
        Decision::Deny(r) => ("nats.auth.deny", Some(r.clone())),
    };
    let detail = json!({
        "reason": reason,
        "host": clip(&req.client_info.host),
        "conn_type": clip(&req.client_info.conn_type),
        "cid": req.client_info.cid,
        "name": clip(&req.connect_opts.name),
        "server_id": clip(&req.server_id),
    });
    repo::insert_audit(&mut tx, "authd", action, client_id, &target, &detail).await?;
    tx.commit().await?;
    Ok(decision)
}

/// Decide one request; any error is a deny.
async fn decide(db: Option<&Db>, req: &AuthRequest) -> Decision {
    let pre = precheck(req);
    let Some(db) = db else {
        return Decision::Deny("database not connected".into());
    };
    match tokio::time::timeout(DB_TIMEOUT, decide_in_db(db, req, pre)).await {
        Ok(Ok(d)) => d,
        Ok(Err(err)) => Decision::Deny(format!("database error: {err}")),
        Err(_) => Decision::Deny("database timeout".into()),
    }
}

/// Handle one raw callout request; returns the signed response, or `None`
/// when the request cannot even be decoded (the server then times out and
/// denies).
async fn handle_request(payload: &[u8], issuer: &KeyPair, db: Option<&Db>) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(payload).ok()?;
    let req = match natsjwt::decode_authorization_request(text) {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(%err, "undecodable authorization request");
            return None;
        }
    };
    let response = match decide(db, &req).await {
        Decision::Allow(agent) => {
            tracing::info!(agent_id = %agent.agent_id, client_id = %agent.client_id, cid = req.client_info.cid, "nats auth allow");
            let claims = natsjwt::user_claims(&req.user_nkey, &agent, unix_now());
            let user_jwt = natsjwt::encode_jwt(&claims, issuer);
            natsjwt::authorization_response(&req.user_nkey, &req.server_id, Some(user_jwt), None)
        }
        Decision::Deny(reason) => {
            tracing::warn!(%reason, nkey = %clip(&req.connect_opts.nkey), host = %clip(&req.client_info.host), cid = req.client_info.cid, "nats auth deny");
            natsjwt::authorization_response(
                &req.user_nkey,
                &req.server_id,
                None,
                Some(DENY_MESSAGE.into()),
            )
        }
    };
    Some(natsjwt::encode_jwt(&response, issuer).into_bytes())
}

/// Connection ids of `nkey` per server, from a connz ping.
fn connz_matches(resp: &Value) -> Option<(String, Vec<u64>)> {
    let server = resp
        .pointer("/server/id")
        .or_else(|| resp.pointer("/data/server_id"))?
        .as_str()?
        .to_owned();
    let cids = resp
        .pointer("/data/connections")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|c| c.get("cid").and_then(Value::as_u64))
                .collect()
        })
        .unwrap_or_default();
    Some((server, cids))
}

async fn sys_request(sys: &async_nats::Client, subject: String, body: Value) -> Result<Value> {
    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        sys.request(subject, body.to_string().into()),
    )
    .await
    .context("sys request timed out")?
    .context("sys request")?;
    serde_json::from_slice(&msg.payload).context("sys response json")
}

/// Kick every connection authenticated with `nkey`; returns how many.
async fn kick_once(sys: &async_nats::Client, nkey: &str) -> Result<usize> {
    let resp = sys_request(
        sys,
        "$SYS.REQ.SERVER.PING.CONNZ".into(),
        json!({"user": nkey, "limit": 1024}),
    )
    .await?;
    let Some((server, cids)) = connz_matches(&resp) else {
        bail!("unexpected connz response");
    };
    for cid in &cids {
        let r = sys_request(
            sys,
            format!("$SYS.REQ.SERVER.{server}.KICK"),
            json!({"cid": cid}),
        )
        .await?;
        if let Some(e) = r.get("error") {
            tracing::warn!(cid, error = %e, "kick failed");
        }
    }
    Ok(cids.len())
}

/// Handle a revocation notice: kick now and once more after a second, to
/// catch a connection that was mid-authorization when the agent was revoked.
async fn handle_revoked(payload: &[u8], sys: &async_nats::Client) {
    let Ok(v) = serde_json::from_slice::<Value>(payload) else {
        tracing::warn!("bad revocation message");
        return;
    };
    let nkey = v.get("nkey").and_then(Value::as_str).unwrap_or("");
    if natsjwt::public_key_bytes(nkey, natsjwt::PREFIX_USER).is_err() {
        tracing::warn!("revocation message without a valid user nkey");
        return;
    }
    let agent_id = v.get("agent_id").and_then(Value::as_str).unwrap_or("");
    for pass in 0..2 {
        if pass > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        match kick_once(sys, nkey).await {
            Ok(n) => {
                tracing::info!(agent_id = %clip(agent_id), kicked = n, "revoked agent connections kicked")
            }
            Err(err) => tracing::warn!(%err, agent_id = %clip(agent_id), "kick failed"),
        }
    }
}

/// Shared state of the callout loop.
#[derive(Debug)]
struct Callout {
    issuer: KeyPair,
    db: Arc<OnceLock<Db>>,
    sys: async_nats::Client,
    permits: Arc<Semaphore>,
}

const SID_AUTH: u64 = 1;
const SID_REVOKED: u64 = 2;

/// One callout connection lifetime; returns when it drops.
async fn callout_session(cfg: &Config, state: &Arc<Callout>, health: &Health) -> Result<()> {
    let (mut reader, mut writer) = wire::connect(
        &cfg.nats_url,
        &cfg.nats_user,
        &cfg.nats_password,
        "rmm-authd",
    )
    .await?;
    let mut setup = Vec::new();
    setup.extend(wire::sub_frame(AUTH_SUBJECT, "authd", SID_AUTH)?);
    setup.extend(wire::sub_frame(REVOKED_SUBJECT, "authd", SID_REVOKED)?);
    setup.extend_from_slice(b"PING\r\n");
    wire::write(&mut writer, &setup).await?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    let mut writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            wire::write(&mut writer, &frame).await?;
        }
        anyhow::Ok(())
    });
    health.callout_up.store(true, Ordering::Relaxed);
    tracing::info!("callout subscription active");

    let result = loop {
        let ev = tokio::select! {
            ev = reader.next() => ev,
            r = &mut writer_task => break match r {
                Ok(Err(e)) => Err(e),
                _ => Err(anyhow::anyhow!("writer stopped")),
            },
        };
        let msg = match ev {
            Ok(wire::Event::Ping) => {
                if tx.send(b"PONG\r\n".to_vec()).await.is_err() {
                    break Err(anyhow::anyhow!("writer stopped"));
                }
                continue;
            }
            Ok(wire::Event::Other) => continue,
            Ok(wire::Event::Msg(m)) => m,
            Err(e) => break Err(e),
        };
        match msg.sid {
            SID_AUTH => {
                let Some(reply) = msg.reply else { continue };
                let Ok(permit) = state.permits.clone().try_acquire_owned() else {
                    tracing::warn!("too many callout requests in flight; dropping one");
                    continue;
                };
                let (state, tx) = (state.clone(), tx.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let resp = handle_request(&msg.payload, &state.issuer, state.db.get()).await;
                    if let Some(resp) = resp
                        && let Ok(frame) = wire::pub_frame(&reply, &resp)
                    {
                        let _ = tx.send(frame).await;
                    }
                });
            }
            SID_REVOKED => {
                let sys = state.sys.clone();
                tokio::spawn(async move { handle_revoked(&msg.payload, &sys).await });
            }
            _ => {}
        }
    };
    health.callout_up.store(false, Ordering::Relaxed);
    writer_task.abort();
    result
}

async fn callout_task(cfg: Arc<Config>, state: Arc<Callout>, health: Arc<Health>) {
    let mut backoff = Duration::from_millis(500);
    loop {
        let started = std::time::Instant::now();
        if let Err(err) = callout_session(&cfg, &state, &health).await {
            tracing::warn!(err = %format!("{err:#}"), "callout connection lost, reconnecting");
        }
        if started.elapsed() > Duration::from_secs(30) {
            backoff = Duration::from_millis(500);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

async fn sys_watch(sys: async_nats::Client, health: Arc<Health>) {
    loop {
        let up = sys.connection_state() == async_nats::connection::State::Connected;
        if health.sys_up.swap(up, Ordering::Relaxed) != up {
            tracing::info!(connected = up, "sys connection state changed");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// authd settings from the environment.
#[derive(Debug)]
struct Config {
    nats_url: String,
    nats_user: String,
    nats_password: String,
    sys_user: String,
    sys_password: String,
    database_url: String,
    listen: String,
}

/// Parse an account issuer seed (`SA...`).
pub fn issuer_from_seed(seed: &str) -> Result<KeyPair> {
    let kp = KeyPair::from_seed(seed.trim()).map_err(|_| anyhow::anyhow!("invalid nkey seed"))?;
    if natsjwt::public_key_bytes(&kp.public_key(), natsjwt::PREFIX_ACCOUNT).is_err() {
        bail!("RMM_AUTHD_ISSUER_SEED must be an account seed (SA...)");
    }
    Ok(kp)
}

/// Run authd until a shutdown signal.
pub async fn run() -> Result<()> {
    let cfg = Arc::new(Config {
        nats_url: crate::env_required("RMM_NATS_URL")?,
        nats_user: crate::env_or("RMM_NATS_USER", "authd"),
        nats_password: crate::env_required("RMM_NATS_PASSWORD")?,
        sys_user: crate::env_or("RMM_NATS_SYS_USER", "sys"),
        sys_password: crate::env_required("RMM_NATS_SYS_PASSWORD")?,
        database_url: crate::env_required("RMM_DATABASE_URL")?,
        listen: crate::env_or("RMM_HEALTH_LISTEN", "0.0.0.0:8082"),
    });
    let issuer = issuer_from_seed(&crate::env_required("RMM_AUTHD_ISSUER_SEED")?)?;
    tracing::info!(issuer = %issuer.public_key(), "authd starting");

    let sys = async_nats::ConnectOptions::with_user_and_password(
        cfg.sys_user.clone(),
        cfg.sys_password.clone(),
    )
    .name("rmm-authd-sys")
    .retry_on_initial_connect()
    .connect(cfg.nats_url.as_str())
    .await
    .context("sys nats connect")?;

    let health = Arc::new(Health::default());
    let db = Arc::new(OnceLock::new());
    let state = Arc::new(Callout {
        issuer,
        db: db.clone(),
        sys: sys.clone(),
        permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
    });
    let tasks = [
        tokio::spawn(db_task(cfg.database_url.clone(), db, health.clone())),
        tokio::spawn(callout_task(cfg.clone(), state, health.clone())),
        tokio::spawn(sys_watch(sys, health.clone())),
    ];
    let result = crate::serve(&cfg.listen, health_router(health)).await;
    for t in tasks {
        t.abort();
    }
    result
}

/// Minimal NATS client protocol over plain TCP: CONNECT with user and
/// password, SUB, PUB and reading MSG/HMSG frames.
mod wire {
    use anyhow::{Context, Result, bail};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

    const MAX_LINE: u64 = 64 * 1024;
    const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

    /// A delivered message.
    #[derive(Debug)]
    pub struct Msg {
        pub sid: u64,
        pub reply: Option<String>,
        pub payload: Vec<u8>,
    }

    /// Something read from the server.
    #[derive(Debug)]
    pub enum Event {
        Msg(Msg),
        Ping,
        Other,
    }

    /// Read side of a connection.
    #[derive(Debug)]
    pub struct Reader(BufReader<OwnedReadHalf>);

    /// `host:port` from `nats://host[:port]`; TLS URLs are refused.
    pub fn addr(url: &str) -> Result<String> {
        let rest = url
            .strip_prefix("nats://")
            .context("only nats:// URLs are supported for the callout connection")?;
        let rest = rest.trim_end_matches('/');
        let hostport = rest.rsplit('@').next().unwrap_or(rest);
        if hostport.is_empty() || hostport.contains('/') {
            bail!("bad NATS URL");
        }
        Ok(if hostport.contains(':') {
            hostport.to_owned()
        } else {
            format!("{hostport}:4222")
        })
    }

    fn token_ok(s: &str) -> bool {
        !s.is_empty()
            && !s
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    }

    /// `SUB <subject> <queue> <sid>` frame.
    pub fn sub_frame(subject: &str, queue: &str, sid: u64) -> Result<Vec<u8>> {
        if !token_ok(subject) || !token_ok(queue) {
            bail!("invalid subject or queue");
        }
        Ok(format!("SUB {subject} {queue} {sid}\r\n").into_bytes())
    }

    /// `PUB <subject> <len>` frame with payload.
    pub fn pub_frame(subject: &str, payload: &[u8]) -> Result<Vec<u8>> {
        if !token_ok(subject) {
            bail!("invalid subject");
        }
        let mut f = format!("PUB {subject} {}\r\n", payload.len()).into_bytes();
        f.extend_from_slice(payload);
        f.extend_from_slice(b"\r\n");
        Ok(f)
    }

    pub async fn write(w: &mut OwnedWriteHalf, frame: &[u8]) -> Result<()> {
        w.write_all(frame).await.context("nats write")?;
        w.flush().await.context("nats flush")
    }

    impl Reader {
        async fn line(&mut self) -> Result<String> {
            let mut buf = Vec::new();
            let n = (&mut self.0)
                .take(MAX_LINE)
                .read_until(b'\n', &mut buf)
                .await
                .context("nats read")?;
            if n == 0 {
                bail!("nats connection closed");
            }
            if buf.last() != Some(&b'\n') {
                bail!("nats protocol line too long");
            }
            let s = String::from_utf8(buf).context("nats line not utf-8")?;
            Ok(s.trim_end_matches(['\r', '\n']).to_owned())
        }

        async fn body(&mut self, len: usize) -> Result<Vec<u8>> {
            if len > MAX_PAYLOAD {
                bail!("nats payload too large");
            }
            let mut buf = vec![0u8; len + 2];
            self.0.read_exact(&mut buf).await.context("nats read")?;
            if !buf.ends_with(b"\r\n") {
                bail!("nats payload not terminated");
            }
            buf.truncate(len);
            Ok(buf)
        }

        /// Next protocol event.
        pub async fn next(&mut self) -> Result<Event> {
            let line = self.line().await?;
            let mut parts = line.split_ascii_whitespace();
            let op = parts.next().unwrap_or("").to_ascii_uppercase();
            let args: Vec<&str> = parts.collect();
            let num = |s: &str| s.parse::<usize>().context("bad length");
            match op.as_str() {
                "MSG" => {
                    let (sid, reply, len) = match args.as_slice() {
                        [_, sid, len] => (sid, None, num(len)?),
                        [_, sid, reply, len] => (sid, Some((*reply).to_owned()), num(len)?),
                        _ => bail!("bad MSG line"),
                    };
                    let payload = self.body(len).await?;
                    Ok(Event::Msg(Msg {
                        sid: sid.parse().context("bad sid")?,
                        reply,
                        payload,
                    }))
                }
                "HMSG" => {
                    let (sid, reply, hlen, tlen) = match args.as_slice() {
                        [_, sid, h, t] => (sid, None, num(h)?, num(t)?),
                        [_, sid, reply, h, t] => (sid, Some((*reply).to_owned()), num(h)?, num(t)?),
                        _ => bail!("bad HMSG line"),
                    };
                    if hlen > tlen {
                        bail!("bad HMSG lengths");
                    }
                    let mut payload = self.body(tlen).await?;
                    payload.drain(..hlen);
                    Ok(Event::Msg(Msg {
                        sid: sid.parse().context("bad sid")?,
                        reply,
                        payload,
                    }))
                }
                "PING" => Ok(Event::Ping),
                "-ERR" => bail!("nats error: {}", args.join(" ")),
                _ => Ok(Event::Other),
            }
        }
    }

    /// Connect, authenticate with user and password and wait for the PONG
    /// that confirms the CONNECT was accepted.
    pub async fn connect(
        url: &str,
        user: &str,
        password: &str,
        name: &str,
    ) -> Result<(Reader, OwnedWriteHalf)> {
        let addr = addr(url)?;
        let stream =
            tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
                .await
                .context("nats connect timed out")?
                .with_context(|| format!("connect {addr}"))?;
        stream.set_nodelay(true).ok();
        let (r, mut w) = stream.into_split();
        let mut reader = Reader(BufReader::new(r));
        let info = reader.line().await?;
        let json = info
            .strip_prefix("INFO ")
            .context("expected INFO from server")?;
        let info: serde_json::Value = serde_json::from_str(json).context("bad INFO json")?;
        if info
            .get("tls_required")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            bail!("server requires TLS, which the callout connection does not support");
        }
        let connect = serde_json::json!({
            "verbose": false,
            "pedantic": false,
            "tls_required": false,
            "user": user,
            "pass": password,
            "name": name,
            "lang": "rust-rmm-authd",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": 1,
            "headers": true,
            "echo": false,
        });
        write(&mut w, format!("CONNECT {connect}\r\nPING\r\n").as_bytes()).await?;
        let wait = async {
            loop {
                let line = reader.line().await?;
                match line.split_ascii_whitespace().next().unwrap_or("") {
                    "PONG" => return anyhow::Ok(()),
                    "-ERR" => bail!("nats rejected connect: {line}"),
                    "PING" => write(&mut w, b"PONG\r\n").await?,
                    _ => {}
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), wait)
            .await
            .context("nats connect handshake timed out")??;
        Ok((reader, w))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn url_and_frames() {
            assert_eq!(addr("nats://nats:4222").ok().as_deref(), Some("nats:4222"));
            assert_eq!(addr("nats://nats").ok().as_deref(), Some("nats:4222"));
            assert!(addr("tls://nats:4222").is_err());
            assert!(pub_frame("a b", b"x").is_err());
            assert!(pub_frame("a\r\nPUB", b"x").is_err());
            assert_eq!(
                pub_frame("r.1", b"hi").ok(),
                Some(b"PUB r.1 2\r\nhi\r\n".to_vec())
            );
            assert_eq!(
                sub_frame("$SYS.REQ.USER.AUTH", "authd", 1).ok(),
                Some(b"SUB $SYS.REQ.USER.AUTH authd 1\r\n".to_vec())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn health_requires_everything_and_fresh_db() {
        let h = Health::default();
        assert!(!h.healthy(1000));
        h.callout_up.store(true, Ordering::Relaxed);
        h.sys_up.store(true, Ordering::Relaxed);
        assert!(!h.healthy(1000), "db never checked");
        h.db_ok_at.store(1000, Ordering::Relaxed);
        assert!(h.healthy(1010));
        assert!(!h.healthy(1031), "db check too old");
        h.sys_up.store(false, Ordering::Relaxed);
        assert!(!h.healthy(1010));
    }

    #[test]
    fn statement_timeout_is_added() {
        assert_eq!(
            with_statement_timeout("postgres://u@h/db"),
            "postgres://u@h/db?options[statement_timeout]=2000"
        );
        assert_eq!(
            with_statement_timeout("postgres://u@h/db?sslmode=disable"),
            "postgres://u@h/db?sslmode=disable&options[statement_timeout]=2000"
        );
    }

    #[test]
    fn issuer_must_be_account() {
        let acct = KeyPair::new_account();
        assert!(issuer_from_seed(&acct.seed().unwrap()).is_ok());
        let user = KeyPair::new_user();
        assert!(issuer_from_seed(&user.seed().unwrap()).is_err());
        assert!(issuer_from_seed("garbage").is_err());
    }

    #[test]
    fn connz_parsing() {
        let v =
            json!({"server": {"id": "NABC"}, "data": {"connections": [{"cid": 4}, {"cid": 9}]}});
        assert_eq!(connz_matches(&v), Some(("NABC".to_owned(), vec![4, 9])));
        let none = json!({"server": {"id": "NABC"}, "data": {"connections": null}});
        assert_eq!(connz_matches(&none), Some(("NABC".to_owned(), vec![])));
    }

    #[tokio::test]
    async fn no_database_means_deny() {
        let req = AuthRequest::default();
        assert!(matches!(decide(None, &req).await, Decision::Deny(_)));
    }

    #[tokio::test]
    async fn deny_response_has_no_jwt() {
        let server = KeyPair::new_server();
        let user = KeyPair::new_user();
        let issuer = KeyPair::new_account();
        let claims = json!({
            "sub": user.public_key(),
            "aud": "nats-authorization-request",
            "nats": {
                "type": "authorization_request",
                "version": 2,
                "user_nkey": user.public_key(),
                "server_id": {"id": server.public_key(), "name": "t"},
                "client_info": {"host": "1.2.3.4", "id": 7, "nonce": "abc", "type": "websocket"},
                "connect_opts": {"nkey": user.public_key(), "sig": "AAAA"}
            }
        });
        let jwt = natsjwt::encode_jwt(&claims, &server);
        let resp = handle_request(jwt.as_bytes(), &issuer, None).await.unwrap();
        let resp = String::from_utf8(resp).unwrap();
        let v = natsjwt::decode_verified(&resp, natsjwt::PREFIX_ACCOUNT).unwrap();
        assert_eq!(v["aud"], server.public_key());
        assert_eq!(v["sub"], user.public_key());
        assert_eq!(v["nats"]["error"], DENY_MESSAGE);
        assert!(v["nats"].get("jwt").is_none());
    }
}
