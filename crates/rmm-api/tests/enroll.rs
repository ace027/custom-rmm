//! Database-backed tests for enrollment, tokens, revocation and trust upload.
//! Each `sqlx::test` gets a fresh database with the migrations applied; the
//! router runs as the restricted `rmm_api` role.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmm_api::auth::{AuthConfig, Authenticator, DEV_ISSUER, rsa_private_der_from_pem};
use rmm_api::{AppState, TrustRoots};
use rmm_db::repo::{self, NewToken};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_proto::canonical::to_canonical_vec;
use rmm_proto::enroll::{EnrollRequest, EnrollResponse, HwFacts};
use rmm_trust::docs::TrustManifest;
use rmm_trust::envelope::{ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_MANIFEST};
use rmm_trust::keys::{Bytes, PublicKey, Sig64};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Uuid;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tower::ServiceExt;

const AUD: &str = "api://rmm-test";
const ROOT_SEED: [u8; 32] = [7; 32];

fn now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap()
}

struct Ctx {
    pool: PgPool,
    app: Router,
    client: Uuid,
    site: Uuid,
}

fn dev_auth() -> Authenticator {
    Authenticator::from_config(AuthConfig {
        tenant_id: None,
        audience: AUD.into(),
        allow_dev: true,
        dev_pubkey_pem: Some(DEV_PUB.as_bytes().to_vec()),
    })
    .unwrap()
}

fn bearer(roles: &[&str]) -> String {
    let c = json!({"iss": DEV_ISSUER, "aud": AUD, "exp": now() + 600, "sub": "dev-admin",
        "oid": "oid-1", "name": "Dev", "roles": roles});
    let key = EncodingKey::from_rsa_der(&rsa_private_der_from_pem(DEV_KEY.as_bytes()).unwrap());
    format!(
        "Bearer {}",
        encode(&Header::new(Algorithm::RS256), &c, &key).unwrap()
    )
}

fn admin() -> String {
    bearer(&["RMM.Admin"])
}

fn root_key() -> SigningKey {
    SigningKey::from_bytes(&ROOT_SEED)
}

async fn setup(pool: PgPool) -> Ctx {
    let api_pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE rmm_api").execute(conn).await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let roots = TrustRoots {
        keys: vec![root_key().verifying_key().to_bytes()],
        threshold: 1,
    };
    let state = AppState::new(
        api_pool,
        dev_auth(),
        None,
        roots,
        "wss://nats.test/nats".into(),
    );
    let mut tx = begin_scoped(&pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    let client = repo::create_client(&mut tx, "Acme").await.unwrap();
    let site = repo::create_site(&mut tx, client, "HQ", "UTC")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    Ctx {
        pool,
        app: rmm_api::router(state),
        client,
        site,
    }
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, body.to_vec())
}

async fn make_token(ctx: &Ctx, client: Uuid, site: Uuid, max_uses: i32, reattach: bool) -> String {
    let body = json!({"client_id": client, "site_id": site, "expires_in_hours": 24,
        "max_uses": max_uses, "allow_reattach": reattach});
    let req = Request::post("/api/v1/enrollment-tokens")
        .header("authorization", admin())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, bytes) = call(&ctx.app, req).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["token"].as_str().unwrap().to_owned()
}

fn strong_hw(serial: &str) -> HwFacts {
    HwFacts {
        smbios_uuid: Some("12345678-1234-1234-1234-123456789abc".into()),
        system_serial: Some(serial.into()),
        board_serial: Some("BOARD-9".into()),
        manufacturer: Some("Acme".into()),
        model: Some("X1".into()),
    }
}

fn weak_hw() -> HwFacts {
    HwFacts {
        smbios_uuid: None,
        system_serial: Some("0".into()),
        board_serial: None,
        manufacturer: None,
        model: None,
    }
}

fn signed_request(token: &str, seed: u8, hw: HwFacts, ts: u64) -> EnrollRequest {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let mut r = EnrollRequest {
        token: token.to_owned(),
        agent_pubkey: sk.verifying_key().to_bytes(),
        hw,
        os_family: "windows".into(),
        os_version: "11".into(),
        hostname: "pc-1".into(),
        agent_version: "0.1.0".into(),
        ts,
        proof: vec![],
    };
    r.proof = sk.sign(&r.signing_bytes()).to_bytes().to_vec();
    r
}

async fn post_enroll(ctx: &Ctx, r: &EnrollRequest) -> (StatusCode, Vec<u8>) {
    let req = Request::post("/v1/enroll")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(r).unwrap()))
        .unwrap();
    call(&ctx.app, req).await
}

async fn enroll_ok(ctx: &Ctx, r: &EnrollRequest) -> EnrollResponse {
    let (status, body) = post_enroll(ctx, r).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).unwrap()
}

async fn count(pool: &PgPool, sql: &str, id: Uuid) -> i64 {
    sqlx::query(sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        .get::<i64, _>(0)
}

async fn token_uses(pool: &PgPool, client: Uuid) -> i32 {
    sqlx::query("select uses from tenant.enrollment_token where client_id = $1")
        .bind(client)
        .fetch_one(pool)
        .await
        .unwrap()
        .get(0)
}

async fn audit_count(pool: &PgPool, action: &str) -> i64 {
    sqlx::query("select count(*) from msp.audit_event where action = $1")
        .bind(action)
        .fetch_one(pool)
        .await
        .unwrap()
        .get(0)
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn token_creation_validates_and_requires_admin(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, false).await;
    assert!(tok.starts_with("rmmenr_"));
    assert_eq!(tok.len(), 7 + 32);

    let post = |auth: String, body: Value| {
        Request::post("/api/v1/enrollment-tokens")
            .header("authorization", auth)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let base = json!({"client_id": ctx.client, "site_id": ctx.site, "expires_in_hours": 24,
        "max_uses": 1, "allow_reattach": false});
    for (field, value) in [
        ("expires_in_hours", json!(0)),
        ("expires_in_hours", json!(721)),
        ("max_uses", json!(0)),
        ("max_uses", json!(1001)),
    ] {
        let mut b = base.clone();
        b[field] = value;
        let (s, _) = call(&ctx.app, post(admin(), b)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{field}");
    }
    let mut b = base.clone();
    b["site_id"] = json!(Uuid::new_v4());
    assert_eq!(
        call(&ctx.app, post(admin(), b)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&ctx.app, post(bearer(&["Reader"]), base)).await.0,
        StatusCode::FORBIDDEN
    );
    // the secret is not stored, only its hash
    let stored: i64 = sqlx::query("select count(*) from tenant.enrollment_token")
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, 1);
    assert_eq!(audit_count(&ctx.pool, "enrollment_token.create").await, 1);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn happy_path_enrolls_and_audits(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 1, false).await;
    let r = signed_request(&tok, 1, strong_hw("SN-1"), now());
    let resp = enroll_ok(&ctx, &r).await;
    assert_eq!(resp.client_id, ctx.client);
    assert_eq!(resp.status, "active");
    assert_eq!(resp.nats_url, "wss://nats.test/nats");
    assert!(resp.trust.manifest.is_none());

    let row = sqlx::query("select status, nkey, device_id from tenant.agent where id = $1")
        .bind(resp.agent_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "active");
    assert!(row.get::<String, _>("nkey").starts_with('U'));
    assert_eq!(row.get::<Uuid, _>("device_id"), resp.device_id);
    assert_eq!(token_uses(&ctx.pool, ctx.client).await, 1);
    assert_eq!(audit_count(&ctx.pool, "agent.enroll").await, 1);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn exhausted_token_is_401_and_audited(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 1, false).await;
    enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    let (s, _) = post_enroll(&ctx, &signed_request(&tok, 2, strong_hw("SN-2"), now())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(audit_count(&ctx.pool, "agent.enroll_denied").await, 1);
    assert_eq!(token_uses(&ctx.pool, ctx.client).await, 1);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn expired_and_unknown_tokens_are_401(pool: PgPool) {
    let ctx = setup(pool).await;
    let secret = "rmmenr_EXPIREDEXPIREDEXPIREDEXPIRED22";
    {
        use sha2::{Digest, Sha256};
        let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
            .await
            .unwrap();
        repo::create_enrollment_token(
            &mut tx,
            NewToken {
                client_id: ctx.client,
                site_id: ctx.site,
                token_hash: Sha256::digest(secret.as_bytes()).into(),
                expires_at: DateTime::from_timestamp(Utc::now().timestamp() - 60, 0).unwrap(),
                max_uses: 5,
                allow_reattach: false,
                created_by: "test".into(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let (s, _) = post_enroll(&ctx, &signed_request(secret, 1, strong_hw("SN-1"), now())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = post_enroll(
        &ctx,
        &signed_request("rmmenr_nope", 1, strong_hw("SN-1"), now()),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn proof_from_other_key_is_401_and_keeps_token(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 1, false).await;
    let mut r = signed_request(&tok, 1, strong_hw("SN-1"), now());
    let other = SigningKey::from_bytes(&[99; 32]);
    r.proof = other.sign(&r.signing_bytes()).to_bytes().to_vec();
    let (s, _) = post_enroll(&ctx, &r).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(token_uses(&ctx.pool, ctx.client).await, 0);
    // tampering with a signed field also breaks the proof
    let mut r = signed_request(&tok, 1, strong_hw("SN-1"), now());
    r.hostname = "evil".into();
    assert_eq!(post_enroll(&ctx, &r).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(token_uses(&ctx.pool, ctx.client).await, 0);
    // and the honest request still works afterwards
    enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn timestamp_window_is_enforced(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, false).await;
    for ts in [now() - 301, now() + 400] {
        let (s, _) = post_enroll(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), ts)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "ts {ts}");
    }
    assert_eq!(token_uses(&ctx.pool, ctx.client).await, 0);
    enroll_ok(
        &ctx,
        &signed_request(&tok, 1, strong_hw("SN-1"), now() - 200),
    )
    .await;
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn same_pubkey_twice_is_409(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, false).await;
    enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    let (s, _) = post_enroll(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(token_uses(&ctx.pool, ctx.client).await, 1);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn bad_bodies_are_400(pool: PgPool) {
    let ctx = setup(pool).await;
    let post = |body: Vec<u8>| {
        Request::post("/v1/enroll")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    assert_eq!(
        call(&ctx.app, post(b"not json".to_vec())).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&ctx.app, post(vec![b' '; 16 * 1024 + 1])).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn per_ip_limiter_returns_429(pool: PgPool) {
    let ctx = setup(pool).await;
    let post = || {
        Request::post("/v1/enroll")
            .header("x-real-ip", "203.0.113.9")
            .body(Body::from("{}"))
            .unwrap()
    };
    for _ in 0..10 {
        assert_eq!(call(&ctx.app, post()).await.0, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        call(&ctx.app, post()).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // another address is unaffected
    let other = Request::post("/v1/enroll")
        .header("x-real-ip", "203.0.113.10")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(call(&ctx.app, other).await.0, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn reattach_after_24h_keeps_device_and_supersedes_agent(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, true).await;
    let first = enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    sqlx::query("update tenant.agent set last_seen = now() - interval '25 hours' where id = $1")
        .bind(first.agent_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let second = enroll_ok(&ctx, &signed_request(&tok, 2, strong_hw("SN-1"), now())).await;
    assert_eq!(second.device_id, first.device_id);
    assert_ne!(second.agent_id, first.agent_id);
    assert_eq!(second.status, "active");
    let old: String = sqlx::query("select status from tenant.agent where id = $1")
        .bind(first.agent_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(old, "superseded");
    assert_eq!(
        count(
            &ctx.pool,
            "select count(*) from tenant.device where client_id = $1",
            ctx.client
        )
        .await,
        1
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn flagged_device_is_never_reattached(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, true).await;
    let first = enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    {
        let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
            .await
            .unwrap();
        sqlx::query("update tenant.device set status = 'flagged' where id = $1")
            .bind(first.device_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "update tenant.agent set last_seen = now() - interval '25 hours' where id = $1",
        )
        .bind(first.agent_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let second = enroll_ok(&ctx, &signed_request(&tok, 2, strong_hw("SN-1"), now())).await;
    assert_eq!(second.status, "pending_review");
    assert_ne!(second.device_id, first.device_id);
    let old: String = sqlx::query("select status from tenant.agent where id = $1")
        .bind(first.agent_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(old, "active");
    let row = sqlx::query("select status, possible_clone_of from tenant.device where id = $1")
        .bind(second.device_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "pending_review");
    assert_eq!(
        row.get::<Option<Uuid>, _>("possible_clone_of"),
        Some(first.device_id)
    );
    let flagged: String = sqlx::query("select status from tenant.device where id = $1")
        .bind(first.device_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(flagged, "flagged");
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn recently_seen_agent_makes_pending_review(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, true).await;
    let first = enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    sqlx::query("update tenant.agent set last_seen = now() - interval '1 hour' where id = $1")
        .bind(first.agent_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let second = enroll_ok(&ctx, &signed_request(&tok, 2, strong_hw("SN-1"), now())).await;
    assert_eq!(second.status, "pending_review");
    assert_ne!(second.device_id, first.device_id);
    let row = sqlx::query("select status, possible_clone_of from tenant.device where id = $1")
        .bind(second.device_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "pending_review");
    assert_eq!(
        row.get::<Option<Uuid>, _>("possible_clone_of"),
        Some(first.device_id)
    );
    let old: String = sqlx::query("select status from tenant.agent where id = $1")
        .bind(first.agent_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(old, "active");
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn cross_client_match_is_flagged_never_reattached(pool: PgPool) {
    let ctx = setup(pool).await;
    let (client2, site2) = {
        let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
            .await
            .unwrap();
        let c = repo::create_client(&mut tx, "Globex").await.unwrap();
        let s = repo::create_site(&mut tx, c, "HQ", "UTC").await.unwrap();
        tx.commit().await.unwrap();
        (c, s)
    };
    let t1 = make_token(&ctx, ctx.client, ctx.site, 5, true).await;
    let t2 = make_token(&ctx, client2, site2, 5, true).await;
    let first = enroll_ok(&ctx, &signed_request(&t1, 1, strong_hw("SN-1"), now())).await;
    sqlx::query("update tenant.agent set last_seen = now() - interval '48 hours'")
        .execute(&ctx.pool)
        .await
        .unwrap();
    let second = enroll_ok(&ctx, &signed_request(&t2, 2, strong_hw("SN-1"), now())).await;
    assert_eq!(second.status, "flagged");
    assert_ne!(second.device_id, first.device_id);
    assert_eq!(second.client_id, client2);
    let status: String = sqlx::query("select status from tenant.agent where id = $1")
        .bind(first.agent_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "active");
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn weak_fingerprint_never_reattaches(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, true).await;
    let first = enroll_ok(&ctx, &signed_request(&tok, 1, weak_hw(), now())).await;
    sqlx::query("update tenant.agent set last_seen = now() - interval '48 hours'")
        .execute(&ctx.pool)
        .await
        .unwrap();
    let second = enroll_ok(&ctx, &signed_request(&tok, 2, weak_hw(), now())).await;
    assert_eq!(second.status, "active");
    assert_ne!(second.device_id, first.device_id);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn revoke_sets_status_audits_and_requires_admin(pool: PgPool) {
    let ctx = setup(pool).await;
    let tok = make_token(&ctx, ctx.client, ctx.site, 5, false).await;
    let a = enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    let revoke = |id: Uuid, auth: String| {
        Request::post(format!("/api/v1/agents/{id}/revoke"))
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        call(&ctx.app, revoke(a.agent_id, bearer(&[]))).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&ctx.app, revoke(a.agent_id, "Bearer junk".into()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&ctx.app, revoke(Uuid::new_v4(), admin())).await.0,
        StatusCode::NOT_FOUND
    );
    // The test state has no NATS client, so the kick cannot be published:
    // the revoke is committed but reported as a retryable 503, not a 204.
    assert_eq!(
        call(&ctx.app, revoke(a.agent_id, admin())).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let status: String = sqlx::query("select status from tenant.agent where id = $1")
        .bind(a.agent_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "revoked");
    assert_eq!(audit_count(&ctx.pool, "agent.revoke").await, 1);
    // Repeating is allowed and still reports the unpublished kick.
    assert_eq!(
        call(&ctx.app, revoke(a.agent_id, admin())).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

async fn agent_status(pool: &PgPool, id: Uuid) -> String {
    sqlx::query("select status from tenant.agent where id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        .get(0)
}

async fn device_status(pool: &PgPool, id: Uuid) -> String {
    sqlx::query("select status from tenant.device where id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        .get(0)
}

fn device_action(id: Uuid, action: &str, auth: String) -> Request<Body> {
    Request::post(format!("/api/v1/devices/{id}/{action}"))
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap()
}

/// A clone held for review next to its still-live original.
async fn held_clone(ctx: &Ctx) -> (EnrollResponse, EnrollResponse) {
    let tok = make_token(ctx, ctx.client, ctx.site, 5, true).await;
    let first = enroll_ok(ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    sqlx::query("update tenant.agent set last_seen = now() - interval '1 hour' where id = $1")
        .bind(first.agent_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let second = enroll_ok(ctx, &signed_request(&tok, 2, strong_hw("SN-1"), now())).await;
    assert_eq!(second.status, "pending_review");
    assert_eq!(
        agent_status(&ctx.pool, second.agent_id).await,
        "suspect_clone"
    );
    (first, second)
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn approve_activates_clone_and_supersedes_original(pool: PgPool) {
    let ctx = setup(pool).await;
    let (first, second) = held_clone(&ctx).await;
    assert_eq!(
        call(
            &ctx.app,
            device_action(second.device_id, "approve", bearer(&[]))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // The superseded original needs a kick; without NATS that is a 503, but
    // the transition is committed.
    assert_eq!(
        call(
            &ctx.app,
            device_action(second.device_id, "approve", admin())
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(device_status(&ctx.pool, second.device_id).await, "active");
    assert_eq!(agent_status(&ctx.pool, second.agent_id).await, "active");
    assert_eq!(agent_status(&ctx.pool, first.agent_id).await, "superseded");
    assert_eq!(audit_count(&ctx.pool, "device.approve").await, 1);
    // No longer held: a second approval finds nothing.
    assert_eq!(
        call(
            &ctx.app,
            device_action(second.device_id, "approve", admin())
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // An active device cannot be rejected either.
    assert_eq!(
        call(&ctx.app, device_action(first.device_id, "reject", admin()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn reject_revokes_the_held_agent_and_keeps_the_original(pool: PgPool) {
    let ctx = setup(pool).await;
    let (first, second) = held_clone(&ctx).await;
    assert_eq!(
        call(&ctx.app, device_action(second.device_id, "reject", admin()))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(agent_status(&ctx.pool, second.agent_id).await, "revoked");
    assert_eq!(agent_status(&ctx.pool, first.agent_id).await, "active");
    assert_eq!(audit_count(&ctx.pool, "device.reject").await, 1);
    assert_eq!(
        call(&ctx.app, device_action(Uuid::new_v4(), "reject", admin()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

fn manifest_envelope(seq: u64, signer: &SigningKey) -> Vec<u8> {
    let root = PublicKey::from_bytes(&signer.verifying_key().to_bytes()).unwrap();
    let doc = TrustManifest {
        seq,
        issued_at: now() - 100,
        expires_at: now() + 30 * 86_400,
        root_keys: vec![Bytes(root.to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![],
        thresholds: Default::default(),
        revoked_keys: vec![],
        console_rp_id: "console.test".into(),
        console_origins: vec!["https://console.test".into()],
        capability_ceiling: vec![],
        revocation_mirrors: vec![],
    };
    let payload = to_canonical_vec(&doc).unwrap();
    let msg = rmm_trust::envelope::signing_message(TYPE_MANIFEST, &payload);
    let env = Envelope {
        v: ENVELOPE_VERSION,
        r#type: TYPE_MANIFEST.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: root.key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(signer.sign(&msg).to_bytes()),
        }],
    };
    env.to_bytes().unwrap()
}

fn put_trust(kind: &str, body: Vec<u8>, auth: String) -> Request<Body> {
    Request::put(format!("/api/v1/trust/{kind}"))
        .header("authorization", auth)
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap()
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn trust_upload_accepts_valid_and_rejects_tampered(pool: PgPool) {
    let ctx = setup(pool).await;
    let good = manifest_envelope(1, &root_key());

    // tampered signature
    let env = Envelope::from_bytes(&good).unwrap();
    let mut bad = env.clone();
    bad.sigs[0].sig.0[3] ^= 1;
    let (s, body) = call(
        &ctx.app,
        put_trust("manifest", bad.to_bytes().unwrap(), admin()),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body).contains("error"));
    // signed by a key that is not a configured root
    let stranger = manifest_envelope(1, &SigningKey::from_bytes(&[55; 32]));
    assert_eq!(
        call(&ctx.app, put_trust("manifest", stranger, admin()))
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // garbage, wrong role, unknown kind
    assert_eq!(
        call(&ctx.app, put_trust("manifest", b"junk".to_vec(), admin()))
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(&ctx.app, put_trust("manifest", good.clone(), bearer(&[])))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&ctx.app, put_trust("bogus", good.clone(), admin()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let none: i64 = sqlx::query("select count(*) from msp.trust_artifact")
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(none, 0);

    // valid manifest is stored, and repeating it is harmless
    assert_eq!(
        call(&ctx.app, put_trust("manifest", good.clone(), admin()))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&ctx.app, put_trust("manifest", good.clone(), admin()))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    // a newer manifest replaces it; an older one is a rollback
    let v2 = manifest_envelope(2, &root_key());
    assert_eq!(
        call(&ctx.app, put_trust("manifest", v2.clone(), admin()))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &ctx.app,
            put_trust("manifest", manifest_envelope(1, &root_key()), admin())
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let stored: i64 =
        sqlx::query("select count(*) from msp.trust_artifact where kind = 'manifest'")
            .fetch_one(&ctx.pool)
            .await
            .unwrap()
            .get(0);
    assert_eq!(stored, 2);

    // enrollment now carries the latest manifest
    let tok = make_token(&ctx, ctx.client, ctx.site, 1, false).await;
    let resp = enroll_ok(&ctx, &signed_request(&tok, 1, strong_hw("SN-1"), now())).await;
    assert_eq!(resp.trust.manifest, Some(v2));
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn trust_upload_without_roots_fails_closed(pool: PgPool) {
    let ctx = setup(pool).await;
    let state = AppState::new(
        ctx.pool.clone(),
        dev_auth(),
        None,
        TrustRoots::default(),
        String::new(),
    );
    let app = rmm_api::router(state);
    let (s, _) = call(
        &app,
        put_trust("manifest", manifest_envelope(1, &root_key()), admin()),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // revocations need an installed manifest first
    let (s, _) = call(&ctx.app, put_trust("revocations", b"x".to_vec(), admin())).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

const DEV_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnwjZGao2uARmrdBW/iGXPrOmw0RZoMXO2hiNqo3Moq61Byvo
OuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXNC80T/sH28J4XX2+IRFpF8ohQyBN8
N6zfoU+iUzRi+r0S63Gh81s2ySEJ2foLkLpPeHEgIQoMbDWH88oPIl76kZfW4rl4
KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMmbwAqtn4x3KrazWuBMAM5PUyVpG8A
Se29uGszpsaifMVqICFmc+hjYZ8fQiwCxD1kVXKoEi3x+tP+S06CBQ7ab5OmWJi0
HT0spk0KPoelLvsK0KwCiPHPxS7J/uqU2aJaXwIDAQABAoIBABe5qTGz+//N4EeT
6jZ1amvXP0yoOLrMZ8SPnyrPhrTKXYVZXobSM50h+Y5ALZQz1WuedMr3xB/Fm+Pv
H3IrzVAyYwZBh4Zz/0aki+6ujPrWrT578a8YojAdgjjpes6vQFBRnniAphaxUBft
vqXztYFhVwq2xg2qmsKa5VEaXEU15nqi0EtYe5+VzZbOMI2NRJ2j5lW12S3yUo58
FbsTYbcoP5gXX1UKyq5qxRe8L8tt/OMyLyfujrOzN7UTVor1pNXDprhxPeOziZjP
kyXCYVb67rz+2KZMrYdD5a19j2MoxTzh+9y8X22kYUeOnhvCvjczEfs9jnulO0p/
kF6YCPECgYEA04Y1RV+RZxXDRJV+J6Yb/XpEMULmA9uM86XdsblRj29bk0AAgTNt
3oF7NdweSfJPpfY9RqaSQIFcRLURvb+zkycEfj5ippAeoLjNhMNY+gL4kSIhmQFU
nguv8ugeCP5OowdE0CfFSlXEa5mnKKMDh75WhY3Dw4RNUMhrThCSzscCgYEAwHlC
N39LvthIJr2fy44n5cPQ1TBLMAgdFrtwOF2yPQr0kFT5+VY0sUY3/6Scpz6v8oDk
6yYZ4cEngmd7CX4yfxbYWEzGUxbaFnj/6sM91Kv3Yw5hTCQC+xNOGO9ZKgeqcGH5
kAv69NOCtEYKoArOOHml66BOwkCgWxUQatYkX6kCgYEA0pQdnH7T5mhICZM6EIbR
/rsmAFS1YMnFvRo3ZqMzizQ1Wpaw6e8lRgppeuk0TjGpEXPe9OMHXqhqDwykKN8c
Czcgxf2dgGyh0Sepkq5Xei5S/0mXYRduAhlohM6IeDOUXcDyxLeTNbnE3coOG+qN
rSnUQQktBwxDXFTqXsEpJikCgYBFuuiJcJ3Be1vQZTyCI3NC44lB4ygqM5ZOSQPj
99X+FXz62T5i3Z9jZhwdisaSNLzLr3S/2GLiDfdBYDoL+2NR9bXVb6MeMRY7tASL
ScaZyN9sTKZlTlqiGaFemUAFYReXdXdTf3OgxQwCQanRx3hkr3W0ArTl3UH7HYuA
GSq+WQKBgDkV2DcRKvDK1RIlEPYSyXnP3V0xQ5j3s/xZbfqzqMq2SYYbPA3r23Ty
kj4UNoQqBmzJ5CVUWUx6MLTqX3IFCJErSXbfjiD6CSWl6rObT4VUOoeg9Qho2MBJ
SWf9oefLMwUqfemP0ZQM+bJ2VQMG5rll3zGtfkOS6T0JN70mQNIs
-----END RSA PRIVATE KEY-----
";
const DEV_PUB: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnwjZGao2uARmrdBW/iGX
PrOmw0RZoMXO2hiNqo3Moq61ByvoOuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXN
C80T/sH28J4XX2+IRFpF8ohQyBN8N6zfoU+iUzRi+r0S63Gh81s2ySEJ2foLkLpP
eHEgIQoMbDWH88oPIl76kZfW4rl4KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMm
bwAqtn4x3KrazWuBMAM5PUyVpG8ASe29uGszpsaifMVqICFmc+hjYZ8fQiwCxD1k
VXKoEi3x+tP+S06CBQ7ab5OmWJi0HT0spk0KPoelLvsK0KwCiPHPxS7J/uqU2aJa
XwIDAQAB
-----END PUBLIC KEY-----
";
