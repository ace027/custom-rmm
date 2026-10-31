//! Authentication tests against a local JWKS server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmm_api::auth::{
    AuthConfig, Authenticator, DEV_ISSUER, rsa_private_der_from_pem, rsa_public_der_from_pem,
};
use rmm_api::{AppState, TrustRoots};
use serde_json::{Value, json};
use tower::ServiceExt;

const AUD: &str = "api://rmm-test";
const ISS: &str = "https://login.test/tenant/v2.0";

#[derive(Clone)]
struct Jwks {
    keys: Arc<Mutex<Vec<Value>>>,
    fetches: Arc<AtomicUsize>,
    addr: Arc<Mutex<Option<SocketAddr>>>,
}

fn jwk(kid: &str, n: &str) -> Value {
    json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": "AQAB"})
}

async fn discovery(State(j): State<Jwks>) -> Json<Value> {
    let addr = j.addr.lock().unwrap().unwrap();
    Json(json!({"issuer": ISS, "jwks_uri": format!("http://{addr}/keys")}))
}

async fn keys(State(j): State<Jwks>) -> Json<Value> {
    j.fetches.fetch_add(1, Ordering::SeqCst);
    Json(json!({"keys": j.keys.lock().unwrap().clone()}))
}

async fn jwks_server(initial: Vec<Value>) -> (Jwks, String) {
    let j = Jwks {
        keys: Arc::new(Mutex::new(initial)),
        fetches: Arc::new(AtomicUsize::new(0)),
        addr: Arc::new(Mutex::new(None)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    *j.addr.lock().unwrap() = Some(addr);
    let app = Router::new()
        .route("/disco", get(discovery))
        .route("/keys", get(keys))
        .with_state(j.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    (j, format!("http://{addr}/disco"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(iss: &str, aud: &str, exp: u64, nbf: Option<u64>) -> Value {
    let mut c = json!({
        "iss": iss, "aud": aud, "exp": exp, "sub": "s1", "oid": "o1",
        "name": "Tech One", "roles": ["RMM.Admin"],
    });
    if let Some(n) = nbf {
        c["nbf"] = json!(n);
    }
    c
}

fn sign_rs256(pem: &str, kid: Option<&str>, claims: &Value) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = kid.map(str::to_owned);
    let key = EncodingKey::from_rsa_der(&rsa_private_der_from_pem(pem.as_bytes()).unwrap());
    encode(&h, claims, &key).unwrap()
}

fn good(kid: &str) -> String {
    sign_rs256(KEY_A_PEM, Some(kid), &claims(ISS, AUD, now() + 600, None))
}

fn cfg(allow_dev: bool) -> AuthConfig {
    AuthConfig {
        tenant_id: None,
        audience: AUD.into(),
        allow_dev,
        dev_pubkey_pem: Some(KEY_A_PUB_SPKI.as_bytes().to_vec()),
    }
}

async fn entra(initial: Vec<Value>) -> (Authenticator, Jwks) {
    let (j, url) = jwks_server(initial).await;
    let a = Authenticator::with_discovery_url(cfg(false), &url).unwrap();
    (a, j)
}

#[tokio::test]
async fn valid_entra_token_yields_claims() {
    let (a, _j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    let c = a.verify(&good("k1")).await.unwrap();
    assert_eq!(c.sub, "s1");
    assert_eq!(c.oid, "o1");
    assert_eq!(c.name, "Tech One");
    assert_eq!(c.roles, vec!["RMM.Admin".to_string()]);
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let (a, _j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    let t = sign_rs256(
        KEY_A_PEM,
        Some("k1"),
        &claims(ISS, "api://other", now() + 600, None),
    );
    assert!(a.verify(&t).await.is_err());
}

#[tokio::test]
async fn wrong_issuer_rejected() {
    let (a, _j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    let t = sign_rs256(
        KEY_A_PEM,
        Some("k1"),
        &claims("https://evil/", AUD, now() + 600, None),
    );
    assert!(a.verify(&t).await.is_err());
}

#[tokio::test]
async fn expiry_and_leeway() {
    let (a, _j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    let expired = sign_rs256(KEY_A_PEM, Some("k1"), &claims(ISS, AUD, now() - 3600, None));
    assert!(a.verify(&expired).await.is_err());
    // 30 s past expiry is inside the 60 s leeway
    let slight = sign_rs256(KEY_A_PEM, Some("k1"), &claims(ISS, AUD, now() - 30, None));
    assert!(a.verify(&slight).await.is_ok());
    let early = sign_rs256(
        KEY_A_PEM,
        Some("k1"),
        &claims(ISS, AUD, now() + 7200, Some(now() + 3600)),
    );
    assert!(a.verify(&early).await.is_err());
}

#[tokio::test]
async fn unknown_kid_refetches_once_then_rejects() {
    let (a, j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    assert!(a.verify(&good("k1")).await.is_ok());
    assert_eq!(j.fetches.load(Ordering::SeqCst), 1);
    // inside the 60 s window an unknown kid does not refetch
    assert!(a.verify(&good("nope")).await.is_err());
    assert!(a.verify(&good("nope")).await.is_err());
    assert_eq!(j.fetches.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unknown_kid_after_refetch_is_rejected() {
    let (j, url) = jwks_server(vec![jwk("k1", KEY_A_N)]).await;
    let a = Authenticator::with_discovery_url(cfg(false), &url)
        .unwrap()
        .with_refetch_interval(Duration::ZERO);
    assert!(a.verify(&good("k1")).await.is_ok());
    assert!(a.verify(&good("missing")).await.is_err());
    assert_eq!(j.fetches.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn key_rotation_is_picked_up() {
    let (j, url) = jwks_server(vec![jwk("k1", KEY_A_N)]).await;
    let a = Authenticator::with_discovery_url(cfg(false), &url)
        .unwrap()
        .with_refetch_interval(Duration::ZERO);
    assert!(a.verify(&good("k1")).await.is_ok());
    *j.keys.lock().unwrap() = vec![jwk("k1", KEY_A_N), jwk("k2", KEY_B_N)];
    let t = sign_rs256(KEY_B_PEM, Some("k2"), &claims(ISS, AUD, now() + 600, None));
    assert!(a.verify(&t).await.is_ok());
}

#[tokio::test]
async fn signature_from_other_key_rejected() {
    let (a, _j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    let t = sign_rs256(KEY_B_PEM, Some("k1"), &claims(ISS, AUD, now() + 600, None));
    assert!(a.verify(&t).await.is_err());
}

#[tokio::test]
async fn missing_kid_rejected() {
    let (a, _j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    let t = sign_rs256(KEY_A_PEM, None, &claims(ISS, AUD, now() + 600, None));
    assert!(a.verify(&t).await.is_err());
}

#[tokio::test]
async fn alg_none_and_hs256_rejected() {
    let (a, _j) = entra(vec![jwk("k1", KEY_A_N)]).await;
    let b64 = |v: &Value| data_encoding::BASE64URL_NOPAD.encode(v.to_string().as_bytes());
    let none = format!(
        "{}.{}.",
        b64(&json!({"alg": "none", "typ": "JWT", "kid": "k1"})),
        b64(&claims(ISS, AUD, now() + 600, None))
    );
    assert!(a.verify(&none).await.is_err());

    let mut h = Header::new(Algorithm::HS256);
    h.kid = Some("k1".into());
    let hs = encode(
        &h,
        &claims(ISS, AUD, now() + 600, None),
        &EncodingKey::from_secret(KEY_A_N.as_bytes()),
    )
    .unwrap();
    assert!(a.verify(&hs).await.is_err());
    assert!(a.verify("garbage").await.is_err());
}

fn dev_token(aud: &str, exp: u64) -> String {
    sign_rs256(KEY_A_PEM, None, &claims(DEV_ISSUER, aud, exp, None))
}

#[tokio::test]
async fn dev_token_requires_allow_dev() {
    let off = Authenticator::from_config(cfg(false)).unwrap();
    assert!(off.verify(&dev_token(AUD, now() + 600)).await.is_err());

    let on = Authenticator::from_config(cfg(true)).unwrap();
    let c = on.verify(&dev_token(AUD, now() + 600)).await.unwrap();
    assert_eq!(c.sub, "s1");
    assert!(
        on.verify(&dev_token("api://other", now() + 600))
            .await
            .is_err()
    );
    assert!(on.verify(&dev_token(AUD, now() - 3600)).await.is_err());
}

#[tokio::test]
async fn dev_issuer_cannot_use_entra_keys() {
    // allow_dev with Entra configured: a dev-issuer token signed by another key fails
    let (j, url) = jwks_server(vec![jwk("k1", KEY_B_N)]).await;
    let a = Authenticator::with_discovery_url(cfg(true), &url).unwrap();
    let forged = sign_rs256(
        KEY_B_PEM,
        Some("k1"),
        &claims(DEV_ISSUER, AUD, now() + 600, None),
    );
    assert!(a.verify(&forged).await.is_err());
    assert_eq!(j.fetches.load(Ordering::SeqCst), 0);
}

#[test]
fn pem_helpers_accept_both_encodings() {
    let p1 = rsa_public_der_from_pem(KEY_A_PUB_PKCS1.as_bytes()).unwrap();
    let p2 = rsa_public_der_from_pem(KEY_A_PUB_SPKI.as_bytes()).unwrap();
    assert_eq!(p1, p2);
    let k1 = rsa_private_der_from_pem(KEY_A_PEM.as_bytes()).unwrap();
    let k2 = rsa_private_der_from_pem(KEY_A_PKCS8.as_bytes()).unwrap();
    assert_eq!(k1, k2);
    assert!(rsa_public_der_from_pem(b"nonsense").is_err());
}

fn lazy_state(auth: Authenticator) -> AppState {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://x:x@127.0.0.1:1/x")
        .unwrap();
    AppState::new(pool, auth, None, TrustRoots::default(), "wss://x".into())
}

async fn post_token(app: Router, bearer: Option<&str>) -> StatusCode {
    let mut req =
        Request::post("/api/v1/enrollment-tokens").header("content-type", "application/json");
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let body = json!({"client_id": uuid::Uuid::nil(), "site_id": uuid::Uuid::nil(),
        "expires_in_hours": 1, "max_uses": 1, "allow_reattach": false});
    app.oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn extractor_returns_401_and_403() {
    let auth = Authenticator::from_config(cfg(true)).unwrap();
    let app = rmm_api::router(lazy_state(auth));
    assert_eq!(
        post_token(app.clone(), None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_token(app.clone(), Some("junk")).await,
        StatusCode::UNAUTHORIZED
    );

    let mut c = claims(DEV_ISSUER, AUD, now() + 600, None);
    c["roles"] = json!(["Other.Role"]);
    let t = sign_rs256(KEY_A_PEM, None, &c);
    assert_eq!(post_token(app, Some(&t)).await, StatusCode::FORBIDDEN);
}

const KEY_A_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
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
const KEY_A_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfCNkZqja4BGat
0Fb+IZc+s6bDRFmgxc7aGI2qjcyirrUHK+g64WcEJwgzk0es4H2rG8q6E9LYy7Ow
KmbU9c0LzRP+wfbwnhdfb4hEWkXyiFDIE3w3rN+hT6JTNGL6vRLrcaHzWzbJIQnZ
+guQuk94cSAhCgxsNYfzyg8iXvqRl9biuXgpYJ3hTeDoBOAOlPUY94Ppu0R8Cp60
89jxkyZvACq2fjHcqtrNa4EwAzk9TJWkbwBJ7b24azOmxqJ8xWogIWZz6GNhnx9C
LALEPWRVcqgSLfH60/5LToIFDtpvk6ZYmLQdPSymTQo+h6Uu+wrQrAKI8c/FLsn+
6pTZolpfAgMBAAECggEAF7mpMbP7/83gR5PqNnVqa9c/TKg4usxnxI+fKs+GtMpd
hVlehtIznSH5jkAtlDPVa550yvfEH8Wb4+8fcivNUDJjBkGHhnP/RqSL7q6M+tat
PnvxrxiiMB2COOl6zq9AUFGeeICmFrFQF+2+pfO1gWFXCrbGDaqawprlURpcRTXm
eqLQS1h7n5XNls4wjY1EnaPmVbXZLfJSjnwVuxNhtyg/mBdfVQrKrmrFF7wvy238
4zIvJ+6Os7M3tRNWivWk1cOmuHE947OJmM+TJcJhVvruvP7Ypkyth0PlrX2PYyjF
POH73LxfbaRhR46eG8K+NzMR+z2Oe6U7Sn+QXpgI8QKBgQDThjVFX5FnFcNElX4n
phv9ekQxQuYD24zzpd2xuVGPb1uTQACBM23egXs13B5J8k+l9j1GppJAgVxEtRG9
v7OTJwR+PmKmkB6guM2Ew1j6AviRIiGZAVSeC6/y6B4I/k6jB0TQJ8VKVcRrmaco
owOHvlaFjcPDhE1QyGtOEJLOxwKBgQDAeUI3f0u+2EgmvZ/Ljiflw9DVMEswCB0W
u3A4XbI9CvSQVPn5VjSxRjf/pJynPq/ygOTrJhnhwSeCZ3sJfjJ/FthYTMZTFtoW
eP/qwz3Uq/djDmFMJAL7E04Y71kqB6pwYfmQC/r004K0RgqgCs44eaXroE7CQKBb
FRBq1iRfqQKBgQDSlB2cftPmaEgJkzoQhtH+uyYAVLVgycW9GjdmozOLNDValrDp
7yVGCml66TROMakRc9704wdeqGoPDKQo3xwLNyDF/Z2AbKHRJ6mSrld6LlL/SZdh
F24CGWiEzoh4M5RdwPLEt5M1ucTdyg4b6o2tKdRBCS0HDENcVOpewSkmKQKBgEW6
6IlwncF7W9BlPIIjc0LjiUHjKCozlk5JA+P31f4VfPrZPmLdn2NmHB2KxpI0vMuv
dL/YYuIN90FgOgv7Y1H1tdVvox4xFju0BItJxpnI32xMpmVOWqIZoV6ZQAVhF5d1
d1N/c6DFDAJBqdHHeGSvdbQCtOXdQfsdi4AZKr5ZAoGAORXYNxEq8MrVEiUQ9hLJ
ec/dXTFDmPez/Flt+rOoyrZJhhs8DevbdPKSPhQ2hCoGbMnkJVRZTHowtOpfcgUI
kStJdt+OIPoJJaXqs5tPhVQ6h6D1CGjYwElJZ/2h58szBSp96Y/RlAz5snZVAwbm
uWXfMa1+Q5LpPQk3vSZA0iw=
-----END PRIVATE KEY-----
";
const KEY_A_PUB_PKCS1: &str = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAnwjZGao2uARmrdBW/iGXPrOmw0RZoMXO2hiNqo3Moq61ByvoOuFn
BCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXNC80T/sH28J4XX2+IRFpF8ohQyBN8N6zf
oU+iUzRi+r0S63Gh81s2ySEJ2foLkLpPeHEgIQoMbDWH88oPIl76kZfW4rl4KWCd
4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMmbwAqtn4x3KrazWuBMAM5PUyVpG8ASe29
uGszpsaifMVqICFmc+hjYZ8fQiwCxD1kVXKoEi3x+tP+S06CBQ7ab5OmWJi0HT0s
pk0KPoelLvsK0KwCiPHPxS7J/uqU2aJaXwIDAQAB
-----END RSA PUBLIC KEY-----
";
const KEY_A_PUB_SPKI: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnwjZGao2uARmrdBW/iGX
PrOmw0RZoMXO2hiNqo3Moq61ByvoOuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXN
C80T/sH28J4XX2+IRFpF8ohQyBN8N6zfoU+iUzRi+r0S63Gh81s2ySEJ2foLkLpP
eHEgIQoMbDWH88oPIl76kZfW4rl4KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMm
bwAqtn4x3KrazWuBMAM5PUyVpG8ASe29uGszpsaifMVqICFmc+hjYZ8fQiwCxD1k
VXKoEi3x+tP+S06CBQ7ab5OmWJi0HT0spk0KPoelLvsK0KwCiPHPxS7J/uqU2aJa
XwIDAQAB
-----END PUBLIC KEY-----
";
const KEY_A_N: &str = "nwjZGao2uARmrdBW_iGXPrOmw0RZoMXO2hiNqo3Moq61ByvoOuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXNC80T_sH28J4XX2-IRFpF8ohQyBN8N6zfoU-iUzRi-r0S63Gh81s2ySEJ2foLkLpPeHEgIQoMbDWH88oPIl76kZfW4rl4KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMmbwAqtn4x3KrazWuBMAM5PUyVpG8ASe29uGszpsaifMVqICFmc-hjYZ8fQiwCxD1kVXKoEi3x-tP-S06CBQ7ab5OmWJi0HT0spk0KPoelLvsK0KwCiPHPxS7J_uqU2aJaXw";
const KEY_B_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAja6WXGfmPiVXf7Y9HRCyLQBQzAz/Xo1GHIe2akpvwhXGogEN
ZNmCaSr7AceaiJGqx+zoA5gH6TVpjeX04T3+k2w5alx2xC1WFbDjnl+sYM1hBaTn
WIttZavYe5Hh0abVx5M+2KTOUbT3sn0JkbnkbKrBMBgKIIWtYozyCWYydJ+D5qIT
VdnUnkQ7QQAEjDsDHOocUmOPr+yR337iAjdXnzO+J1ljWK344q4fVuC0Nlkt/r2U
LvGRmrrySXL6tDBOYOIRT9Dv2crjaRLU+LxP7pa8iQJN/+SueMiyCyObg1Rpc/Ou
KmJufKsmPqpNJRMKZuseZFX2bIMU9v1btVY0SQIDAQABAoIBAANWK59EH9hNd8FN
Yf/96MYBUbgVDLT4OkDb0p8daCdw2qESblf/fOlHWPPfGTF1PHcz7opsjgts1bLK
CfvY+U1ea5EENTkbATirDQZgin9QHJs3GaXMf6YUR34wozVVSr7GAUXsWIdibeWf
FLa30NNKvk9R5HgE9eebNX5t9WIEeWwr/T+3VDd9XeaY8ztZghhCjfaTnOCZLHqq
yrslercqeejSqse77Wgx9fIVjhfNHPZj1wvnshikbyGyaMRLFcd7Fmbcc9pSJl5m
QvuOCO3I504/hC/wiaxagmkaDd8dIxYCHSCzJ/K/IiVDAHncGgh1rXZqcMtfdu8X
HmuRdVUCgYEAwoC7yYCKNTYRSvVK4cor/6bPvPH6xSUxoys4ho6glE2P7cfFA6As
ZPZK6yxykyac5j2dimiBrhen4TTOMFootd1ZzbbL1t70xv6T5lxOqGJiHmQ7zL99
7nRiSYSMF+IGBcNvtM5O75OnGoYWSPvPi60/mPzlCxeM7lRo3hS8BqUCgYEAunp5
12jF2Dkq2NfX+QWlTi0UEvLjWhDhLQmwBr0TPY02zWEsGMHfdywb22albb8AGzfd
x0TIWwX4G/Do+u3p/PKvqNPQlSDd/mvTKNBapD4RYSHcW16rqVdDLsFo7WiQ4yKe
GXZg4mHX4KXvXUXwp9gyQS/kKbMes8SgqyCPadUCgYAU1Y1H7EjhokT/7n5y6SEF
ZWzjJFhkPbOvcrW/VA/HUveT1M45sTKQLgGgZ0ZulLhBwV/ar48Ugtwst2dOrpml
wWwZKPd0sLUvi510E3cpekBgWQQ+zlRC8pyEm3oWJNPYUjLo/yBdcUd5A9vnPXHh
2FDzpkMyiPdDoC8LetUZMQKBgQCb+0SddWtAYRlBBtMF3r4WNUi8TOT1encP+DGA
gXltnAiCJM0A7HJiuceXbzXjJcgN/F4Lh7JbyRNvM8V917JIvitG+d5YT4TBgym+
0wFuruhUqkErQHYwkOiGXIvLQhMnmtZKECYcVqF/rO0axRz3GLV4p3mfk8+TqV6H
phWv/QKBgQC7Pkc2rLstbdhCYhV6BYuw0ctlTz2IzU2vlvRwfrz0t20bbsmWUCDn
XIYW5IxLZKpE/xXFOcsyCq1AipI+RSGz95M+KmTQw9RsFdax01aUisF4FKSaWjGe
wtjG+52uCofRJwlXqWwhrc4YDpi9E/DlkzOp9autFtU0mVyY2KMKhw==
-----END RSA PRIVATE KEY-----
";
const KEY_B_N: &str = "ja6WXGfmPiVXf7Y9HRCyLQBQzAz_Xo1GHIe2akpvwhXGogENZNmCaSr7AceaiJGqx-zoA5gH6TVpjeX04T3-k2w5alx2xC1WFbDjnl-sYM1hBaTnWIttZavYe5Hh0abVx5M-2KTOUbT3sn0JkbnkbKrBMBgKIIWtYozyCWYydJ-D5qITVdnUnkQ7QQAEjDsDHOocUmOPr-yR337iAjdXnzO-J1ljWK344q4fVuC0Nlkt_r2ULvGRmrrySXL6tDBOYOIRT9Dv2crjaRLU-LxP7pa8iQJN_-SueMiyCyObg1Rpc_OuKmJufKsmPqpNJRMKZuseZFX2bIMU9v1btVY0SQ";
