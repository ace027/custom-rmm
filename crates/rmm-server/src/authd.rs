//! The `authd` subcommand: NATS auth callout for agents.
//!
//! Agents connect with their device key as user nkey. NATS forwards every
//! connection that is not a static service user to `$SYS.REQ.USER.AUTH`;
//! authd checks the nonce signature, looks the agent up in the database and
//! replies with a signed authorization response that carries a scoped,
//! WebSocket-only, one hour user JWT. Any failure is a deny with a generic
//! message. authd also kicks connections of agents the API revokes.
//!
//! Two NATS connections: user `authd` (account RMM) receives callout
//! requests and revocation notices; user `sys` (account SYS) runs the connz
//! and kick requests.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use futures_util::StreamExt;
use nkeys::KeyPair;
use rmm_db::DbError;
use rmm_db::repo::{self, AgentAuthRow, Tx};
use rmm_db::scope::Scope;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

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

/// Connect as the restricted `rmm_authd` role and wrap the pool in a [`Db`].
async fn connect_db(url: &str) -> std::result::Result<Db, DbError> {
    let pool = rmm_db::scope::connect_as(&with_statement_timeout(url), "rmm_authd").await?;
    let (p1, p2) = (pool.clone(), pool);
    Ok(Db {
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
    })
}

/// Connect (retrying forever) and then probe the database every 15 s.
async fn db_task(url: String, cell: Arc<OnceLock<Db>>, health: Arc<Health>) {
    let mut backoff = Duration::from_millis(500);
    let db = loop {
        match connect_db(&url).await {
            Ok(db) => break db,
            Err(err) => {
                tracing::warn!(%err, "database connect failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        }
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

/// Kick every connection authenticated as `user`; returns how many.
async fn kick_once(sys: &async_nats::Client, user: &str) -> Result<usize> {
    let resp = sys_request(
        sys,
        "$SYS.REQ.SERVER.PING.CONNZ".into(),
        json!({"user": user, "limit": 1024}),
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

/// The agent id of a revocation notice `{agent_id, nkey}`.
fn revoked_agent(payload: &[u8]) -> Option<uuid::Uuid> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    v.get("agent_id")?.as_str()?.parse().ok()
}

/// Handle a revocation notice: kick now and once more after a second, to
/// catch a connection that was mid-authorization when the agent was revoked.
/// Connections are found by the user name authd put in their JWT (connz
/// reports callout users by name, not by the client's nkey).
async fn handle_revoked(payload: &[u8], sys: &async_nats::Client) {
    let Some(agent_id) = revoked_agent(payload) else {
        tracing::warn!("revocation message without a valid agent_id");
        return;
    };
    let user = natsjwt::agent_user_name(agent_id);
    for pass in 0..2 {
        if pass > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        match kick_once(sys, &user).await {
            Ok(n) => tracing::info!(%agent_id, kicked = n, "revoked agent connections kicked"),
            Err(err) => tracing::warn!(%err, %agent_id, "kick failed"),
        }
    }
}

/// Shared state of the callout loop.
#[derive(Debug)]
struct Callout {
    issuer: KeyPair,
    db: Arc<OnceLock<Db>>,
    permits: Arc<Semaphore>,
}

/// Answer callout requests until the subscription ends. async-nats
/// reconnects and resubscribes on its own, so this normally runs forever.
async fn serve_callout(
    client: async_nats::Client,
    mut sub: async_nats::Subscriber,
    state: Arc<Callout>,
) {
    while let Some(msg) = sub.next().await {
        let Some(reply) = msg.reply.clone() else {
            continue;
        };
        let Ok(permit) = state.permits.clone().try_acquire_owned() else {
            // The server times the request out and denies the client.
            tracing::warn!("too many callout requests in flight; dropping one");
            continue;
        };
        let (state, client) = (state.clone(), client.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let resp = handle_request(&msg.payload, &state.issuer, state.db.get()).await;
            if let Some(resp) = resp
                && let Err(err) = client.publish(reply, resp.into()).await
            {
                tracing::warn!(%err, "callout reply failed");
            }
        });
    }
    tracing::error!("callout subscription ended");
}

/// Kick agents named in revocation notices until the subscription ends.
async fn serve_revoked(mut sub: async_nats::Subscriber, sys: async_nats::Client) {
    while let Some(msg) = sub.next().await {
        let sys = sys.clone();
        tokio::spawn(async move { handle_revoked(&msg.payload, &sys).await });
    }
    tracing::error!("revocation subscription ended");
}

fn is_up(c: &async_nats::Client) -> bool {
    c.connection_state() == async_nats::connection::State::Connected
}

/// Mirror both NATS connection states into [`Health`].
async fn nats_watch(callout: async_nats::Client, sys: async_nats::Client, health: Arc<Health>) {
    loop {
        for (name, client, flag) in [
            ("callout", &callout, &health.callout_up),
            ("sys", &sys, &health.sys_up),
        ] {
            let up = is_up(client);
            if flag.swap(up, Ordering::Relaxed) != up {
                tracing::info!(
                    connection = name,
                    connected = up,
                    "nats connection state changed"
                );
            }
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

    let connect = |user: &str, password: &str, name: &str| {
        async_nats::ConnectOptions::with_user_and_password(user.to_owned(), password.to_owned())
            .name(name)
            .no_echo()
            .retry_on_initial_connect()
            .connect(cfg.nats_url.as_str())
    };
    let callout = connect(&cfg.nats_user, &cfg.nats_password, "rmm-authd")
        .await
        .context("callout nats connect")?;
    let sys = connect(&cfg.sys_user, &cfg.sys_password, "rmm-authd-sys")
        .await
        .context("sys nats connect")?;
    let auth_sub = callout
        .queue_subscribe(AUTH_SUBJECT, "authd".into())
        .await
        .context("subscribe to callout requests")?;
    let revoked_sub = callout
        .queue_subscribe(REVOKED_SUBJECT, "authd".into())
        .await
        .context("subscribe to revocations")?;

    let health = Arc::new(Health::default());
    let db = Arc::new(OnceLock::new());
    let state = Arc::new(Callout {
        issuer,
        db: db.clone(),
        permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
    });
    let tasks = [
        tokio::spawn(db_task(cfg.database_url.clone(), db, health.clone())),
        tokio::spawn(serve_callout(callout.clone(), auth_sub, state)),
        tokio::spawn(serve_revoked(revoked_sub, sys.clone())),
        tokio::spawn(nats_watch(callout, sys, health.clone())),
    ];
    let result = crate::serve(&cfg.listen, health_router(health)).await;
    for t in tasks {
        t.abort();
    }
    result
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

    #[test]
    fn revocation_notice_needs_a_uuid() {
        let id = uuid::Uuid::from_u128(7);
        let ok = json!({"agent_id": id.to_string(), "nkey": "U"}).to_string();
        assert_eq!(revoked_agent(ok.as_bytes()), Some(id));
        assert_eq!(revoked_agent(br#"{"agent_id":"agent:x > *"}"#), None);
        assert_eq!(revoked_agent(b"not json"), None);
        assert_eq!(natsjwt::agent_user_name(id), format!("agent:{id}"));
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

    // --- database-backed decision tests -------------------------------
    //
    // rmm-server has no direct sqlx dependency, so these run against the
    // database named by DATABASE_URL (migrated in place, unique names per
    // run) rather than through `sqlx::test`. Skipped when it is unset.

    use natsjwt::{ClientInfo, ConnectOpts, PREFIX_USER};
    use rmm_db::repo::{NewAgent, NewDevice};
    use uuid::Uuid;

    /// Superuser-ish access for seeding and for reading audit rows back.
    async fn admin_db(url: &str) -> Db {
        let pool = rmm_db::connect(url).await.unwrap();
        rmm_db::migrate(&pool).await.unwrap();
        Db {
            begin: Box::new(move || {
                let pool = pool.clone();
                Box::pin(async move {
                    rmm_db::scope::begin_scoped(&pool, &Scope::Service("authd-test"), "test").await
                })
            }),
            ping: Box::new(|| Box::pin(async { Ok(1) })),
        }
    }

    struct Seeded {
        agent_id: Uuid,
        client_id: Uuid,
        key: KeyPair,
    }

    async fn seed_client(admin: &Db) -> (Uuid, Uuid) {
        let mut tx = (admin.begin)().await.unwrap();
        let client = repo::create_client(&mut tx, &format!("authd-{}", Uuid::new_v4()))
            .await
            .unwrap();
        let site = repo::create_site(&mut tx, client, "main", "UTC")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (client, site)
    }

    /// An active agent in the given client; `stored_nkey` overrides the nkey
    /// the database holds for it.
    async fn seed_agent(
        admin: &Db,
        client: Uuid,
        site: Uuid,
        stored_nkey: Option<String>,
    ) -> Seeded {
        let key = KeyPair::new_user();
        let pk = natsjwt::public_key_bytes(&key.public_key(), PREFIX_USER).unwrap();
        let mut tx = (admin.begin)().await.unwrap();
        let device = repo::insert_device(
            &mut tx,
            NewDevice {
                client_id: client,
                site_id: site,
                hw_fingerprint: Uuid::new_v4().as_bytes().to_vec(),
                fp_strength: "strong".into(),
                smbios_uuid: None,
                system_serial: None,
                board_serial: None,
                os_family: "linux".into(),
                hostname: "host".into(),
                status: "active".into(),
                possible_clone_of: None,
            },
        )
        .await
        .unwrap();
        let agent_id = repo::insert_agent(
            &mut tx,
            NewAgent {
                client_id: client,
                device_id: device,
                credential_pubkey: pk,
                nkey: stored_nkey.unwrap_or_else(|| key.public_key()),
                version: "0.1.0".into(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Seeded {
            agent_id,
            client_id: client,
            key,
        }
    }

    /// A request for `key` as the server would forward it.
    fn request(key: &KeyPair, conn_type: &str, good_sig: bool) -> AuthRequest {
        let nonce = "nonce-1234";
        let other = KeyPair::new_user();
        let signer = if good_sig { key } else { &other };
        let sig = signer.sign(nonce.as_bytes()).unwrap();
        AuthRequest {
            user_nkey: KeyPair::new_user().public_key(),
            server_id: "NSERVER".into(),
            client_info: ClientInfo {
                host: "10.0.0.5".into(),
                nonce: nonce.into(),
                cid: 42,
                kind: "Client".into(),
                conn_type: conn_type.into(),
            },
            connect_opts: ConnectOpts {
                nkey: key.public_key(),
                sig: data_encoding::BASE64URL_NOPAD.encode(&sig),
                name: "rmm-agent/0.1".into(),
            },
        }
    }

    async fn audits(admin: &Db, action: &str, target: &str) -> i64 {
        let mut tx = (admin.begin)().await.unwrap();
        let n = repo::count_audit(&mut tx, action, target).await.unwrap();
        tx.commit().await.unwrap();
        n
    }

    async fn set_status(admin: &Db, agent: Uuid, from: &[&str], to: &str) {
        let mut tx = (admin.begin)().await.unwrap();
        let row = repo::transition_agent_status(&mut tx, agent, from, to)
            .await
            .unwrap();
        assert!(row.is_some());
        tx.commit().await.unwrap();
    }

    fn denied(d: &Decision, needle: &str) {
        match d {
            Decision::Deny(r) => assert!(r.contains(needle), "deny reason {r:?} lacks {needle:?}"),
            Decision::Allow(_) => panic!("expected deny containing {needle:?}"),
        }
    }

    #[tokio::test]
    async fn decisions_against_the_database() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL not set; skipping database decision test");
            return;
        };
        let admin = admin_db(&url).await;
        let authd = connect_db(&url).await.unwrap();
        let (client, site) = seed_client(&admin).await;

        // Active agent: allowed, audited, last_seen touched by the allow path.
        let ok = seed_agent(&admin, client, site, None).await;
        match decide(Some(&authd), &request(&ok.key, "websocket", true)).await {
            Decision::Allow(a) => {
                assert_eq!(a.agent_id, ok.agent_id);
                assert_eq!(a.client_id, ok.client_id);
            }
            Decision::Deny(r) => panic!("active agent denied: {r}"),
        }
        let target = format!("agent:{}", ok.agent_id);
        assert_eq!(audits(&admin, "nats.auth.allow", &target).await, 1);
        assert_eq!(audits(&admin, "nats.auth.deny", &target).await, 0);
        // An empty connection type (older servers) is also accepted.
        assert!(matches!(
            decide(Some(&authd), &request(&ok.key, "", true)).await,
            Decision::Allow(_)
        ));

        // Revoked and suspect_clone agents are refused and audited.
        for (status, needle) in [
            ("revoked", "agent status revoked"),
            ("suspect_clone", "suspect_clone"),
        ] {
            let a = seed_agent(&admin, client, site, None).await;
            set_status(&admin, a.agent_id, &["active"], status).await;
            denied(
                &decide(Some(&authd), &request(&a.key, "websocket", true)).await,
                needle,
            );
            let target = format!("agent:{}", a.agent_id);
            assert_eq!(
                audits(&admin, "nats.auth.deny", &target).await,
                1,
                "{status}"
            );
            assert_eq!(
                audits(&admin, "nats.auth.allow", &target).await,
                0,
                "{status}"
            );
        }

        // Superseded agents are refused too.
        let sup = seed_agent(&admin, client, site, None).await;
        set_status(&admin, sup.agent_id, &["active"], "superseded").await;
        denied(
            &decide(Some(&authd), &request(&sup.key, "websocket", true)).await,
            "superseded",
        );

        // Agent of a disabled client is refused.
        let (client2, site2) = seed_client(&admin).await;
        let susp = seed_agent(&admin, client2, site2, None).await;
        {
            let mut tx = (admin.begin)().await.unwrap();
            assert!(
                repo::set_client_status(&mut tx, client2, "disabled")
                    .await
                    .unwrap()
            );
            tx.commit().await.unwrap();
        }
        denied(
            &decide(Some(&authd), &request(&susp.key, "websocket", true)).await,
            "client status disabled",
        );
        let target = format!("agent:{}", susp.agent_id);
        assert_eq!(audits(&admin, "nats.auth.deny", &target).await, 1);

        // Stored nkey differs from the presented one.
        let other = KeyPair::new_user().public_key();
        let mism = seed_agent(&admin, client, site, Some(other)).await;
        denied(
            &decide(Some(&authd), &request(&mism.key, "websocket", true)).await,
            "nkey does not match",
        );
        let target = format!("agent:{}", mism.agent_id);
        assert_eq!(audits(&admin, "nats.auth.deny", &target).await, 1);

        // Unknown key: denied, audited against the presented nkey.
        let stranger = KeyPair::new_user();
        denied(
            &decide(Some(&authd), &request(&stranger, "websocket", true)).await,
            "unknown agent",
        );
        let target = format!("nkey:{}", clip(&stranger.public_key()));
        assert_eq!(audits(&admin, "nats.auth.deny", &target).await, 1);

        // Bad signature and wrong transport never reach an allow, even for an
        // active agent, and are audited.
        let a = seed_agent(&admin, client, site, None).await;
        let nkey_target = format!("nkey:{}", clip(&a.key.public_key()));
        denied(
            &decide(Some(&authd), &request(&a.key, "websocket", false)).await,
            "signature",
        );
        assert_eq!(audits(&admin, "nats.auth.deny", &nkey_target).await, 1);
        denied(
            &decide(Some(&authd), &request(&a.key, "nats", true)).await,
            "connection type",
        );
        assert_eq!(audits(&admin, "nats.auth.deny", &nkey_target).await, 2);
        assert_eq!(
            audits(&admin, "nats.auth.allow", &format!("agent:{}", a.agent_id)).await,
            0
        );
    }
}
