//! Artifact upload and download against a database: the server names the
//! file by its own SHA-256, only complete uploads appear under a hash, and
//! only an Admin may upload.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmm_api::auth::{AuthConfig, Authenticator, DEV_ISSUER, rsa_private_der_from_pem};
use rmm_api::{AppState, TrustRoots};
use rmm_trust::keys::PublicKey;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use sqlx::types::chrono::Utc;
use tower::ServiceExt;

const AUD: &str = "api://rmm-test";

fn now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(k: &SigningKey) -> PublicKey {
    PublicKey::from_bytes(&k.verifying_key().to_bytes()).unwrap()
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
    let c = json!({"iss": DEV_ISSUER, "aud": AUD, "exp": now() + 600, "sub": "dev-user",
        "oid": "oid-1", "name": "Dev", "roles": roles});
    let k = EncodingKey::from_rsa_der(&rsa_private_der_from_pem(DEV_KEY.as_bytes()).unwrap());
    format!(
        "Bearer {}",
        encode(&Header::new(Algorithm::RS256), &c, &k).unwrap()
    )
}

fn admin() -> String {
    bearer(&["RMM.Admin"])
}

const ROOT: u8 = 7;

async fn api_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE rmm_api").execute(conn).await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap()
}

fn roots() -> TrustRoots {
    TrustRoots {
        keys: vec![public(&key(ROOT)).to_bytes()],
        threshold: 1,
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rmm-api-{tag}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, headers, body.to_vec())
}

struct Ctx {
    app: Router,
    dir: std::path::PathBuf,
}

async fn setup(pool: PgPool) -> Ctx {
    let dir = temp_dir("artifacts");
    let state = AppState::new(
        api_pool(&pool).await,
        dev_auth(),
        None,
        roots(),
        "wss://nats.test".into(),
    )
    .with_artifact_dir(&dir);
    Ctx {
        app: rmm_api::router(state),
        dir,
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sha_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))
}

fn sample(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap())
        .collect()
}

fn upload_req(auth: Option<String>, body: Body) -> Request<Body> {
    let mut b =
        Request::post("/api/v1/admin/artifacts").header("content-type", "application/octet-stream");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    b.body(body).unwrap()
}

fn files(dir: &std::path::Path) -> Vec<String> {
    match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn upload_then_download_returns_identical_bytes_and_hash(pool: PgPool) {
    let ctx = setup(pool.clone()).await;
    let data = sample(700_000);
    let (status, _, body) = call(
        &ctx.app,
        upload_req(Some(admin()), Body::from(data.clone())),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["sha256_hex"], sha_hex(&data));
    assert_eq!(v["size"], data.len());
    assert_eq!(files(&ctx.dir), vec![sha_hex(&data)], "no temp file left");

    let req = Request::get(format!("/v1/artifacts/{}", sha_hex(&data)))
        .body(Body::empty())
        .unwrap();
    let (status, headers, got) = call(&ctx.app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, data);
    assert_eq!(headers["content-length"], data.len().to_string());
    assert_eq!(headers["content-type"], "application/octet-stream");

    // Same bytes again are the same artifact.
    let (status, _, _) = call(
        &ctx.app,
        upload_req(Some(admin()), Body::from(data.clone())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(files(&ctx.dir).len(), 1);

    let n: i64 =
        sqlx::query_scalar("select count(*) from msp.audit_event where action = 'artifact.upload'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(n, 2);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(&ctx.dir).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(ctx.dir.join(sha_hex(&data)))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn unknown_or_malformed_hash_is_404(pool: PgPool) {
    let ctx = setup(pool).await;
    for h in [
        "0".repeat(64),
        "..".to_owned(),
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_owned(),
        "A".repeat(64),
        "ab".to_owned(),
    ] {
        let req = Request::get(format!("/v1/artifacts/{h}"))
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = call(&ctx.app, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{h}");
    }
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn only_admin_may_upload(pool: PgPool) {
    let ctx = setup(pool).await;
    let (status, _, _) = call(&ctx.app, upload_req(Some(bearer(&[])), Body::from("x"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(&ctx.app, upload_req(None, Body::from("x"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(files(&ctx.dir).is_empty(), "nothing stored");
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn interrupted_upload_leaves_nothing_under_any_name(pool: PgPool) {
    let ctx = setup(pool).await;
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![
        Ok(sample(100_000)),
        Ok(sample(100_000)),
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "client went away",
        )),
    ];
    let body = Body::from_stream(futures_util::stream::iter(chunks));
    let (status, _, _) = call(&ctx.app, upload_req(Some(admin()), body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(files(&ctx.dir).is_empty(), "{:?}", files(&ctx.dir));
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn dropped_upload_future_removes_its_temp_file(pool: PgPool) {
    let ctx = setup(pool).await;
    // A body that never finishes: the request is abandoned like a vanished client.
    let pending = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(sample(50_000))])
        .chain(futures_util::stream::pending());
    let req = upload_req(Some(admin()), Body::from_stream(pending));
    let app = ctx.app.clone();
    let res = tokio::time::timeout(std::time::Duration::from_millis(500), app.oneshot(req)).await;
    assert!(res.is_err(), "the upload is still waiting for data");
    assert!(files(&ctx.dir).is_empty(), "{:?}", files(&ctx.dir));
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn empty_upload_is_refused(pool: PgPool) {
    let ctx = setup(pool).await;
    let (status, _, _) = call(&ctx.app, upload_req(Some(admin()), Body::empty())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(files(&ctx.dir).is_empty());
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
