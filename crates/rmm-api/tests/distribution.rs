//! Release trust uploads (same sequence rules as the other kinds) and the
//! trust/release distribution replies, against a database. The NATS
//! responders themselves are tested when `RMM_TEST_NATS_URL` is set.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmm_api::auth::{AuthConfig, Authenticator, DEV_ISSUER, rsa_private_der_from_pem};
use rmm_api::{AppState, TrustRoots};
use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{
    Cert, ReleaseArtifact, ReleaseLatest, ReleaseManifest, Role, TrustLatest, TrustManifest,
    decode_doc,
};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_MANIFEST, TYPE_RELEASE, signing_message,
};
use rmm_trust::keys::{Bytes, PublicKey, Sig64};
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

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, headers, body.to_vec())
}

const RELEASE: u8 = 8;
const CATALOG: u8 = 9;

fn sign_env(type_: &str, payload: Vec<u8>, signer: u8) -> Vec<u8> {
    let k = key(signer);
    let msg = signing_message(type_, &payload);
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: type_.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: public(&k).key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(k.sign(&msg).to_bytes()),
        }],
    }
    .to_bytes()
    .unwrap()
}

fn manifest() -> Vec<u8> {
    let cert = |seed: u8, roles: Vec<Role>| Cert {
        key_id: public(&key(seed)).key_id(),
        pubkey: Bytes(public(&key(seed)).to_bytes().to_vec()),
        alg: ALG_ED25519.to_owned(),
        roles,
        not_before: now() - 1000,
        not_after: now() + 86_400,
        label: "k".into(),
    };
    let doc = TrustManifest {
        seq: 1,
        issued_at: now() - 100,
        expires_at: now() + 30 * 86_400,
        root_keys: vec![Bytes(public(&key(ROOT)).to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![
            cert(RELEASE, vec![Role::Release]),
            cert(CATALOG, vec![Role::Catalog]),
        ],
        thresholds: BTreeMap::from([(Role::Release, 1), (Role::Catalog, 1)]),
        revoked_keys: vec![],
        console_rp_id: "console.test".into(),
        console_origins: vec!["https://console.test".into()],
        capability_ceiling: vec![],
        revocation_mirrors: vec![],
    };
    sign_env(TYPE_MANIFEST, to_canonical_vec(&doc).unwrap(), ROOT)
}

fn release(seq: u64, version: &str, signer: u8) -> Vec<u8> {
    let doc = ReleaseManifest {
        seq,
        version: version.into(),
        issued_at: now() - 100,
        expires_at: now() + 86_400,
        artifacts: vec![ReleaseArtifact {
            platform: "linux-x86_64".into(),
            sha256: Bytes(vec![7; 32]),
            size: 1000,
            name: "rmm-agent".into(),
        }],
    };
    sign_env(TYPE_RELEASE, to_canonical_vec(&doc).unwrap(), signer)
}

async fn state(pool: &PgPool) -> AppState {
    AppState::new(
        api_pool(pool).await,
        dev_auth(),
        None,
        roots(),
        "wss://nats.test".into(),
    )
}

async fn put(app: &Router, kind: &str, body: Vec<u8>) -> StatusCode {
    let req = Request::put(format!("/api/v1/trust/{kind}"))
        .header("authorization", admin())
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap();
    call(app, req).await.0
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn release_upload_enforces_role_and_sequence(pool: PgPool) {
    let app = rmm_api::router(state(&pool).await);

    // No manifest yet: nothing to verify against.
    assert_eq!(
        put(&app, "release", release(2, "1.0.0", RELEASE)).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        put(&app, "manifest", manifest()).await,
        StatusCode::NO_CONTENT
    );

    // The catalog role may not sign a release.
    assert_eq!(
        put(&app, "release", release(2, "1.0.0", CATALOG)).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let ok = release(2, "1.0.0", RELEASE);
    assert_eq!(
        put(&app, "release", ok.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(&app, "release", ok.clone()).await,
        StatusCode::NO_CONTENT,
        "idempotent"
    );
    // Rollback and equivocation are refused; a higher seq is accepted.
    assert_eq!(
        put(&app, "release", release(1, "0.9.0", RELEASE)).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        put(&app, "release", release(2, "1.0.1", RELEASE)).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        put(&app, "release", release(3, "1.1.0", RELEASE)).await,
        StatusCode::NO_CONTENT
    );
    // A release envelope is not a manifest.
    assert_eq!(
        put(&app, "manifest", release(4, "1.2.0", RELEASE)).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(put(&app, "nonsense", ok).await, StatusCode::NOT_FOUND);

    let stored: Vec<(String, i64)> =
        sqlx::query_as("select kind, seq from msp.trust_artifact order by kind, seq")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        stored,
        vec![
            ("manifest".to_owned(), 1),
            ("release".to_owned(), 2),
            ("release".to_owned(), 3)
        ]
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn replies_carry_the_latest_stored_envelopes(pool: PgPool) {
    let state = state(&pool).await;
    let app = rmm_api::router(state.clone());

    // Nothing stored: both replies are empty maps.
    let t: TrustLatest = decode_doc(
        &rmm_api::distribution::trust_reply(&state.pool)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(t, TrustLatest::default());
    let raw = rmm_api::distribution::release_reply(&state.pool)
        .await
        .unwrap();
    assert_eq!(raw, vec![0xa0], "an empty CBOR map");
    let r: ReleaseLatest = decode_doc(&raw).unwrap();
    assert_eq!(r.release, None);

    let m = manifest();
    assert_eq!(
        put(&app, "manifest", m.clone()).await,
        StatusCode::NO_CONTENT
    );
    let (r2, r3) = (release(2, "1.0.0", RELEASE), release(3, "1.1.0", RELEASE));
    assert_eq!(put(&app, "release", r2).await, StatusCode::NO_CONTENT);
    assert_eq!(
        put(&app, "release", r3.clone()).await,
        StatusCode::NO_CONTENT
    );

    let t: TrustLatest = decode_doc(
        &rmm_api::distribution::trust_reply(&state.pool)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(t.manifest, Some(Bytes(m)));
    assert_eq!(t.revocations, None);
    assert_eq!(t.techlist, None);
    let r: ReleaseLatest = decode_doc(
        &rmm_api::distribution::release_reply(&state.pool)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r.release, Some(Bytes(r3)), "the newest release");
}

/// Needs the dev NATS (`RMM_TEST_NATS_URL`): the api user answers, the
/// ingest user asks (the api user may not publish on `svc.*`).
#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn responders_answer_over_nats(pool: PgPool) {
    let Ok(url) = std::env::var("RMM_TEST_NATS_URL") else {
        println!("skipping responders_answer_over_nats: RMM_TEST_NATS_URL is unset");
        return;
    };
    let password =
        std::env::var("RMM_NATS_API_PASSWORD").unwrap_or_else(|_| "dev-only-nats-api".into());
    let ingest_password =
        std::env::var("RMM_NATS_INGEST_PASSWORD").unwrap_or_else(|_| "dev-only-nats-ingest".into());
    let responder = async_nats::ConnectOptions::with_user_and_password("api".into(), password)
        .connect(url.as_str())
        .await
        .expect("connect api");
    let asker =
        async_nats::ConnectOptions::with_user_and_password("ingest".into(), ingest_password)
            .connect(url.as_str())
            .await
            .expect("connect ingest");

    let mut st = state(&pool).await;
    st.nats = Some(responder.clone());
    let app = rmm_api::router(st.clone());
    let m = manifest();
    let r = release(5, "2.0.0", RELEASE);
    assert_eq!(
        put(&app, "manifest", m.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(&app, "release", r.clone()).await,
        StatusCode::NO_CONTENT
    );

    let handles = rmm_api::distribution::spawn(&st).expect("responders");
    responder.flush().await.unwrap();

    let ask = |subject: &'static str| {
        let asker = asker.clone();
        async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                asker.request(subject, Vec::new().into()),
            )
            .await
            .expect("reply in time")
            .expect("reply")
            .payload
            .to_vec()
        }
    };
    let t: TrustLatest = decode_doc(&ask("svc.trust.latest").await).unwrap();
    assert_eq!(t.manifest, Some(Bytes(m)));
    let rl: ReleaseLatest = decode_doc(&ask("svc.release.latest").await).unwrap();
    assert_eq!(rl.release, Some(Bytes(r)));
    for h in handles {
        h.abort();
    }
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
