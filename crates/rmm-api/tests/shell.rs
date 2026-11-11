//! Shell grant and open endpoints, against a database. The published
//! `ShellOpen` is verified with the same trust code the agent runs. NATS is not
//! needed: without a client the handlers skip the publish step and the tests
//! take the signed command from `open_session`'s return value.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::{DerSignature, SigningKey as P256Key};
use rmm_api::auth::{AuthConfig, Authenticator, Claims, DEV_ISSUER, rsa_private_der_from_pem};
use rmm_api::shell::{OpenRequest, open_session, ticket_hash};
use rmm_api::{ApiError, AppState, TrustRoots};
use rmm_db::repo::{self, NewAgent, NewDevice};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::shell::{self, NewCredential, NewShellSession};
use rmm_proto::canonical::to_canonical_vec;
use rmm_proto::subjects::sid_from_grant_id;
use rmm_trust::docs::{
    ArtifactRevocations, Cert, CommandBody, Role, ShellGrant, TrustManifest, decode_doc,
};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_MANIFEST, TYPE_REVOCATIONS,
    signing_message,
};
use rmm_trust::keys::{Bytes, PublicKey, Sig64};
use rmm_trust::store::{Clock, DocKind, ReplayCache, SeqStore, TrustStore};
use rmm_trust::webauthn::{Assertion, Expected, parse_cose_key, shell_challenge, verify_assertion};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Uuid;
use sqlx::types::chrono::Utc;
use sqlx::{PgPool, Row};
use tower::ServiceExt;

const AUD: &str = "api://rmm-test";
const RP_ID: &str = "console.test";
const ORIGIN: &str = "https://console.test";
const TECH: &str = "tech-1";

fn now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap()
}

fn b64(b: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(b)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(k: &SigningKey) -> PublicKey {
    PublicKey::from_bytes(&k.verifying_key().to_bytes()).unwrap()
}

const ROOT: u8 = 7;
const CATALOG: u8 = 8;
const COMMAND: u8 = 9;

fn manifest() -> Vec<u8> {
    let cert = |k: &SigningKey, roles: Vec<Role>, label: &str| Cert {
        key_id: public(k).key_id(),
        pubkey: Bytes(public(k).to_bytes().to_vec()),
        alg: ALG_ED25519.to_owned(),
        roles,
        not_before: now() - 1000,
        not_after: now() + 86_400,
        label: label.to_owned(),
    };
    let doc = TrustManifest {
        seq: 1,
        issued_at: now() - 100,
        expires_at: now() + 30 * 86_400,
        root_keys: vec![Bytes(public(&key(ROOT)).to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![
            cert(
                &key(CATALOG),
                vec![Role::Catalog, Role::ArtifactRevoke],
                "catalog",
            ),
            cert(&key(COMMAND), vec![Role::Command], "command"),
        ],
        thresholds: BTreeMap::from([
            (Role::Catalog, 1),
            (Role::ArtifactRevoke, 1),
            (Role::Command, 1),
        ]),
        revoked_keys: vec![],
        console_rp_id: RP_ID.into(),
        console_origins: vec![ORIGIN.into()],
        capability_ceiling: vec!["service".into(), "files.write".into()],
        revocation_mirrors: vec![],
    };
    sign_env(TYPE_MANIFEST, to_canonical_vec(&doc).unwrap(), &key(ROOT))
}

fn sign_env(type_: &str, payload: Vec<u8>, signer: &SigningKey) -> Vec<u8> {
    let msg = signing_message(type_, &payload);
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: type_.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: public(signer).key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(signer.sign(&msg).to_bytes()),
        }],
    }
    .to_bytes()
    .unwrap()
}

fn revocations() -> Vec<u8> {
    let doc = ArtifactRevocations {
        seq: 1,
        issued_at: now() - 100,
        expires_at: now() + 86_400,
        revoked_hashes: vec![],
    };
    sign_env(
        TYPE_REVOCATIONS,
        to_canonical_vec(&doc).unwrap(),
        &key(CATALOG),
    )
}

// ------------------------------------------------------- the authenticator

fn cred_key() -> P256Key {
    P256Key::from_slice(&[21; 32]).unwrap()
}

const CRED_ID: [u8; 32] = [0xc1; 32];

fn cose_es256(k: &P256Key) -> Vec<u8> {
    use ciborium::Value as Cbor;
    let point = k.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let map = Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
        (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
        (
            Cbor::Integer((-2).into()),
            Cbor::Bytes(bytes[1..33].to_vec()),
        ),
        (
            Cbor::Integer((-3).into()),
            Cbor::Bytes(bytes[33..65].to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&map, &mut out).unwrap();
    out
}

/// What `navigator.credentials.get` returns for `challenge`, signed by `signer`.
fn assertion_for(signer: &P256Key, challenge: &[u8], flags: u8) -> Assertion {
    let mut ad = Sha256::digest(RP_ID.as_bytes()).to_vec();
    ad.push(flags);
    ad.extend_from_slice(&7u32.to_be_bytes());
    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.get", "challenge": b64(challenge), "origin": ORIGIN, "crossOrigin": false
    }))
    .unwrap();
    let mut msg = ad.clone();
    msg.extend_from_slice(&Sha256::digest(&client_data));
    let sig: DerSignature = signer.sign(&msg);
    Assertion {
        authenticator_data: ad,
        client_data_json: client_data,
        signature: sig.as_bytes().to_vec(),
    }
}

fn open_body(a: &Assertion) -> OpenRequest {
    OpenRequest {
        credential_id_b64url: b64(&CRED_ID),
        authenticator_data_b64url: b64(&a.authenticator_data),
        client_data_json_b64url: b64(&a.client_data_json),
        signature_b64url: b64(&a.signature),
    }
}

fn open_json(a: &Assertion) -> Value {
    json!({
        "credential_id_b64url": b64(&CRED_ID),
        "authenticator_data_b64url": b64(&a.authenticator_data),
        "client_data_json_b64url": b64(&a.client_data_json),
        "signature_b64url": b64(&a.signature),
    })
}

// -------------------------------------------------------------- the harness

struct Ctx {
    pool: PgPool,
    app: Router,
    state: AppState,
    client: Uuid,
    agent: Uuid,
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

fn token(sub: &str, roles: &[&str]) -> String {
    let c = json!({"iss": DEV_ISSUER, "aud": AUD, "exp": now() + 600, "sub": sub,
        "oid": sub, "name": "Tech One", "roles": roles});
    let k = EncodingKey::from_rsa_der(&rsa_private_der_from_pem(DEV_KEY.as_bytes()).unwrap());
    format!(
        "Bearer {}",
        encode(&Header::new(Algorithm::RS256), &c, &k).unwrap()
    )
}

fn claims(sub: &str) -> Claims {
    Claims {
        sub: sub.into(),
        oid: sub.into(),
        name: "Tech One".into(),
        roles: vec![],
    }
}

async fn seed_agent(pool: &PgPool, name: &str, seed: u8) -> (Uuid, Uuid) {
    let mut tx = begin_scoped(pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    let client = repo::create_client(&mut tx, name).await.unwrap();
    let site = repo::create_site(&mut tx, client, "HQ", "UTC")
        .await
        .unwrap();
    let device = repo::insert_device(
        &mut tx,
        NewDevice {
            client_id: client,
            site_id: site,
            hw_fingerprint: vec![seed; 32],
            fp_strength: "strong".into(),
            smbios_uuid: None,
            system_serial: None,
            board_serial: None,
            os_family: "linux".into(),
            hostname: "box".into(),
            status: "active".into(),
            possible_clone_of: None,
        },
    )
    .await
    .unwrap();
    let agent = repo::insert_agent(
        &mut tx,
        NewAgent {
            client_id: client,
            device_id: device,
            credential_pubkey: [seed; 32],
            nkey: format!("nkey-{seed}"),
            version: "0.1.0".into(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (client, agent)
}

/// A database with a trusted manifest, one agent and technician `tech-1` with
/// one credential, not yet assigned to any client.
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
        keys: vec![public(&key(ROOT)).to_bytes()],
        threshold: 1,
    };
    let state = AppState::new(api_pool, dev_auth(), None, roots, "wss://nats.test".into())
        .with_attestation(None)
        .with_command_key(Some(key(COMMAND)));
    let (client, agent) = seed_agent(&pool, "Acme", 1).await;

    let mut tx = begin_scoped(&pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    shell::upsert_technician(&mut tx, TECH, "Tech One")
        .await
        .unwrap();
    assert!(
        shell::insert_credential(
            &mut tx,
            NewCredential {
                cred_id: CRED_ID.to_vec(),
                tech_id: TECH.into(),
                alg: -7,
                cose_pubkey: cose_es256(&cred_key()),
                aaguid: vec![0x42; 16],
                sign_count: 0,
                attestation_fmt: "packed".into(),
            },
        )
        .await
        .unwrap()
    );
    tx.commit().await.unwrap();

    let ctx = Ctx {
        pool,
        app: rmm_api::router(state.clone()),
        state,
        client,
        agent,
    };
    let req = Request::put("/api/v1/trust/manifest")
        .header("authorization", token("admin", &["RMM.Admin"]))
        .header("content-type", "application/octet-stream")
        .body(Body::from(manifest()))
        .unwrap();
    assert_eq!(call(&ctx.app, req).await.0, StatusCode::NO_CONTENT);
    ctx
}

async fn link_technician(ctx: &Ctx) {
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    assert!(
        shell::add_technician_client(&mut tx, TECH, ctx.client)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, body.to_vec())
}

async fn post(ctx: &Ctx, path: &str, auth: String, body: Value) -> (StatusCode, Value) {
    let req = Request::post(path)
        .header("authorization", auth)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (s, b) = call(&ctx.app, req).await;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

async fn grant(ctx: &Ctx, body: Value) -> (StatusCode, Value) {
    post(
        ctx,
        &format!("/api/v1/agents/{}/shell", ctx.agent),
        token(TECH, &[]),
        body,
    )
    .await
}

/// A fresh grant: its id and challenge.
async fn fresh_grant(ctx: &Ctx) -> (Vec<u8>, Vec<u8>, Value) {
    let (s, g) = grant(ctx, json!({"shell": "sh"})).await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    let id = data_encoding::BASE64URL_NOPAD
        .decode(g["grant_id_b64url"].as_str().unwrap().as_bytes())
        .unwrap();
    let challenge = data_encoding::BASE64URL_NOPAD
        .decode(g["challenge_b64url"].as_str().unwrap().as_bytes())
        .unwrap();
    (id, challenge, g)
}

async fn status_of(ctx: &Ctx, grant_id: &[u8]) -> String {
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    shell::shell_session(&mut tx, grant_id)
        .await
        .unwrap()
        .unwrap()
        .status
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query(sql).fetch_one(pool).await.unwrap().get(0)
}

struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> u64 {
        now()
    }
}

#[derive(Default)]
struct Seqs(HashMap<DocKind, (u64, [u8; 32])>);

impl SeqStore for Seqs {
    fn get(&self, kind: DocKind) -> Option<(u64, [u8; 32])> {
        self.0.get(&kind).copied()
    }
    fn put(&mut self, kind: DocKind, seq: u64, id: [u8; 32]) {
        self.0.insert(kind, (seq, id));
    }
}

#[derive(Default)]
struct Replay(HashSet<Vec<u8>>);

impl ReplayCache for Replay {
    fn seen(&mut self, cmd_id: &[u8], _expires_at: u64) -> bool {
        !self.0.insert(cmd_id.to_vec())
    }
}

// ------------------------------------------------------------------- tests

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn out_of_scope_technician_gets_403(pool: PgPool) {
    let ctx = setup(pool).await;
    let (s, _) = grant(&ctx, json!({"shell": "sh"})).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "technician has no client assigned"
    );
    // An unknown agent answers the same: no existence oracle.
    let (s, _) = post(
        &ctx,
        &format!("/api/v1/agents/{}/shell", Uuid::new_v4()),
        token(TECH, &[]),
        json!({"shell": "sh"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A technician with no credential, even in scope, gets nothing.
    link_technician(&ctx).await;
    let (s, _) = post(
        &ctx,
        &format!("/api/v1/agents/{}/shell", ctx.agent),
        token("nobody", &[]),
        json!({"shell": "sh"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        count(&ctx.pool, "select count(*) from tenant.shell_session").await,
        0
    );
    // In scope with a credential: granted.
    let (s, g) = grant(&ctx, json!({"shell": "sh"})).await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    assert_eq!(g["rp_id"], RP_ID);
    assert_eq!(g["allow_credentials"], json!([b64(&CRED_ID)]));
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn grant_limits_and_challenge(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    for body in [
        json!({"shell": "sh", "max_duration_secs": 14_401}),
        json!({"shell": "sh", "max_duration_secs": 0}),
        json!({"shell": "zsh"}),
        json!({"shell": "sh", "credential_id_b64url": b64(&[1, 2, 3])}),
        json!({"shell": "sh", "surprise": true}),
    ] {
        let (s, v) = grant(&ctx, body.clone()).await;
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::UNPROCESSABLE_ENTITY,
            "{body} -> {s} {v}"
        );
    }
    let (s, _) = grant(&ctx, json!({"shell": "sh", "max_duration_secs": 14_400})).await;
    assert_eq!(s, StatusCode::CREATED);
    let (id, challenge, g) = fresh_grant(&ctx).await;

    // The stored grant is the one the challenge commits to.
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    let row = shell::shell_session(&mut tx, &id).await.unwrap().unwrap();
    assert_eq!(row.status, "pending");
    assert_eq!(row.max_duration, 3600);
    assert_eq!(challenge, shell_challenge(&row.grant_cbor));
    assert_eq!(g["grant_cbor_b64url"], b64(&row.grant_cbor));
    let parsed: ShellGrant = decode_doc(&row.grant_cbor).unwrap();
    assert_eq!(parsed.cred_id.0, CRED_ID.to_vec());
    assert_eq!(parsed.tech_id, TECH);
    assert_eq!(parsed.agent_id, ctx.agent.to_string());
    assert_eq!(parsed.client_id, ctx.client.to_string());
    assert_eq!(parsed.open_by - parsed.issued_at, 60);
    assert!(parsed.record);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn several_credentials_need_an_explicit_choice(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    assert!(
        shell::insert_credential(
            &mut tx,
            NewCredential {
                cred_id: vec![0xc2; 32],
                tech_id: TECH.into(),
                alg: -7,
                cose_pubkey: cose_es256(&P256Key::from_slice(&[22; 32]).unwrap()),
                aaguid: vec![0x42; 16],
                sign_count: 0,
                attestation_fmt: "packed".into(),
            },
        )
        .await
        .unwrap()
    );
    tx.commit().await.unwrap();
    let (s, _) = grant(&ctx, json!({"shell": "sh"})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, g) = grant(
        &ctx,
        json!({"shell": "sh", "credential_id_b64url": b64(&CRED_ID)}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    assert_eq!(g["allow_credentials"], json!([b64(&CRED_ID)]));
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn open_twice_is_409(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let (id, challenge, g) = fresh_grant(&ctx).await;
    let a = assertion_for(&cred_key(), &challenge, 0x05);
    let path = format!(
        "/api/v1/shell-sessions/{}/open",
        g["grant_id_b64url"].as_str().unwrap()
    );

    let (s, v) = post(&ctx, &path, token(TECH, &[]), open_json(&a)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["session_id"], sid_from_grant_id(&id));
    let ticket = v["ws_ticket"].as_str().unwrap();
    assert_eq!(
        v["ws_url"],
        format!(
            "/api/v1/shell-sessions/{}/ws?ticket={ticket}",
            sid_from_grant_id(&id)
        )
    );
    assert_eq!(status_of(&ctx, &id).await, "opening");

    let (s, _) = post(&ctx, &path, token(TECH, &[]), open_json(&a)).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        count(&ctx.pool, "select count(*) from tenant.shell_ws_ticket").await,
        1
    );

    // The ticket works exactly once.
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    let hash = ticket_hash(ticket);
    assert!(
        shell::consume_ws_ticket(&mut tx, &hash)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        shell::consume_ws_ticket(&mut tx, &hash)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn someone_elses_grant_is_404(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let (_, challenge, g) = fresh_grant(&ctx).await;
    let a = assertion_for(&cred_key(), &challenge, 0x05);
    let path = format!(
        "/api/v1/shell-sessions/{}/open",
        g["grant_id_b64url"].as_str().unwrap()
    );
    let (s, _) = post(&ctx, &path, token("tech-2", &[]), open_json(&a)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn expired_grant_is_410(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let t = now();
    let grant_id = [0x77u8; 16];
    let grant = ShellGrant {
        grant_id: Bytes(grant_id.to_vec()),
        agent_id: ctx.agent.to_string(),
        client_id: ctx.client.to_string(),
        tech_id: TECH.into(),
        cred_id: Bytes(CRED_ID.to_vec()),
        issued_at: t - 100,
        open_by: t - 40,
        max_duration: 60,
        shell: "sh".into(),
        record: true,
        e2e_pubkey: None,
    };
    let grant_cbor = to_canonical_vec(&grant).unwrap();
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    shell::insert_shell_session(
        &mut tx,
        NewShellSession {
            grant_id: grant_id.to_vec(),
            client_id: ctx.client,
            agent_id: ctx.agent,
            tech_id: TECH.into(),
            cred_id: CRED_ID.to_vec(),
            shell: "sh".into(),
            max_duration: 60,
            grant_cbor: grant_cbor.clone(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let a = assertion_for(&cred_key(), &shell_challenge(&grant_cbor), 0x05);
    let path = format!("/api/v1/shell-sessions/{}/open", b64(&grant_id));
    let (s, _) = post(&ctx, &path, token(TECH, &[]), open_json(&a)).await;
    assert_eq!(s, StatusCode::GONE);
    assert_eq!(status_of(&ctx, &grant_id).await, "expired");
    // Even a perfect assertion cannot revive it.
    let (s, _) = post(&ctx, &path, token(TECH, &[]), open_json(&a)).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn invalid_assertion_is_400_and_publishes_nothing(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let (id, challenge, g) = fresh_grant(&ctx).await;
    let path = format!(
        "/api/v1/shell-sessions/{}/open",
        g["grant_id_b64url"].as_str().unwrap()
    );
    let other = P256Key::from_slice(&[99; 32]).unwrap();
    let bad = [
        // Signed by a key that is not the credential.
        assertion_for(&other, &challenge, 0x05),
        // No user verification.
        assertion_for(&cred_key(), &challenge, 0x01),
        // Signed for another challenge.
        assertion_for(&cred_key(), &[5u8; 32], 0x05),
    ];
    for a in &bad {
        let (s, v) = post(&ctx, &path, token(TECH, &[]), open_json(a)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        // Nothing moved, so nothing was (or could be) published.
        assert_eq!(status_of(&ctx, &id).await, "pending");
        assert_eq!(
            count(&ctx.pool, "select count(*) from tenant.shell_ws_ticket").await,
            0
        );
        let err = open_session(
            &ctx.state,
            &claims(TECH),
            id.as_slice().try_into().unwrap(),
            &open_body(a),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "{err:?}");
    }
    // A wrong credential id is refused before any crypto.
    let a = assertion_for(&cred_key(), &challenge, 0x05);
    let mut body = open_json(&a);
    body["credential_id_b64url"] = json!(b64(&[0xc2; 32]));
    let (s, _) = post(&ctx, &path, token(TECH, &[]), body).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        count(
            &ctx.pool,
            "select count(*) from msp.audit_event where action = 'shell.assertion_rejected'"
        )
        .await,
        6
    );
    // The right assertion still works afterwards.
    let (s, v) = post(&ctx, &path, token(TECH, &[]), open_json(&a)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn valid_open_publishes_one_shell_open_with_the_stored_grant(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let (id, challenge, _) = fresh_grant(&ctx).await;
    let a = assertion_for(&cred_key(), &challenge, 0x05);
    let grant_id: [u8; 16] = id.as_slice().try_into().unwrap();

    let opened = open_session(&ctx.state, &claims(TECH), &grant_id, &open_body(&a))
        .await
        .unwrap();
    assert_eq!(opened.session_id, sid_from_grant_id(&id));

    // The agent's view: a command signed by the command key, bound to it.
    let mut store = TrustStore::new(vec![public(&key(ROOT))], 1);
    let mut seqs = Seqs::default();
    store
        .apply_manifest(&manifest(), &Fixed, &mut seqs)
        .unwrap();
    store
        .apply_revocations(&revocations(), &Fixed, &mut seqs)
        .unwrap();
    let cmd = store
        .verify_command(
            &opened.command,
            &ctx.agent.to_string(),
            &ctx.client.to_string(),
            &Fixed,
            &mut Replay::default(),
        )
        .unwrap();
    assert!(cmd.expires_at > cmd.issued_at);
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    let row = shell::shell_session(&mut tx, &id).await.unwrap().unwrap();
    assert_eq!(row.status, "opening");
    match cmd.body {
        CommandBody::ShellOpen { grant, assertion } => {
            assert_eq!(grant.0, row.grant_cbor, "grant bytes are the stored ones");
            let got: Assertion = decode_doc(&assertion.0).unwrap();
            assert_eq!(got, a);
            // And the agent-side check of that assertion passes.
            let parsed: ShellGrant = decode_doc(&grant.0).unwrap();
            assert_eq!(cmd.expires_at, parsed.open_by);
            let origins = vec![ORIGIN.to_owned()];
            verify_assertion(
                &got,
                &Expected {
                    challenge: shell_challenge(&grant.0),
                    rp_id: RP_ID,
                    origins: &origins,
                    require_uv: true,
                },
                &parse_cose_key(&cose_es256(&cred_key())).unwrap(),
            )
            .unwrap();
        }
        other => panic!("unexpected body {other:?}"),
    }
    // Exactly one open: the grant cannot be used again.
    let err = open_session(&ctx.state, &claims(TECH), &grant_id, &open_body(&a))
        .await
        .unwrap_err();
    assert!(matches!(err, ApiError::Conflict(_)), "{err:?}");
    assert_eq!(
        count(
            &ctx.pool,
            "select count(*) from msp.audit_event where action = 'shell.open'"
        )
        .await,
        1
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn revoked_credential_cannot_open(pool: PgPool) {
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let (id, challenge, g) = fresh_grant(&ctx).await;
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    assert!(shell::revoke_credential(&mut tx, &CRED_ID).await.unwrap());
    tx.commit().await.unwrap();
    let a = assertion_for(&cred_key(), &challenge, 0x05);
    let path = format!(
        "/api/v1/shell-sessions/{}/open",
        g["grant_id_b64url"].as_str().unwrap()
    );
    let (s, _) = post(&ctx, &path, token(TECH, &[]), open_json(&a)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(status_of(&ctx, &id).await, "pending");
    // And no new grant can be requested.
    let (s, _) = grant(&ctx, json!({"shell": "sh"})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn recording_download_is_admin_only_and_hash_checked(pool: PgPool) {
    use rmm_api::recording::Recorder;
    let ctx = setup(pool).await;
    link_technician(&ctx).await;
    let dir = std::env::temp_dir().join(format!("rmm-rec-{}", Uuid::new_v4()));
    let state = ctx.state.clone().with_recording_dir(&dir);
    let app = rmm_api::router(state.clone());
    let (id, _, _) = fresh_grant(&ctx).await;
    let sid = sid_from_grant_id(&id);

    let mut rec = Recorder::create(&dir, ctx.client, &sid, "agent tech", 80, 24).unwrap();
    rec.output(b"hello ").unwrap();
    rec.input(b"ls\n").unwrap();
    rec.resize(100, 30).unwrap();
    rec.output("wor".as_bytes()).unwrap();
    rec.output(b"ld\r\n").unwrap();
    let fin = rec.finish().unwrap();
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    shell::set_recording(
        &mut tx,
        &id,
        &fin.rel_path,
        &fin.sha256,
        i64::try_from(fin.bytes).unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let get = |auth: String| {
        Request::get(format!("/api/v1/shell-sessions/{sid}/recording"))
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap()
    };
    let (s, _) = call(&app, get(token(TECH, &[]))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let res = app
        .clone()
        .oneshot(get(token("admin", &["RMM.Admin"])))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "application/x-asciicast");
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let mut lines = text.lines();
    let head: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(head["version"], 2);
    assert_eq!(head["width"], 80);
    assert_eq!(head["title"], "agent tech");
    let events: Vec<Value> = lines.map(|l| serde_json::from_str(l).unwrap()).collect();
    let kinds: Vec<_> = events.iter().map(|e| e[1].as_str().unwrap()).collect();
    assert_eq!(kinds, ["o", "i", "r", "o", "o"]);
    assert_eq!(events[2][2], "100x30");
    assert_eq!(body.len() as u64, fin.bytes);

    // A file that no longer matches its hash is not served.
    let path = dir.join(&fin.rel_path);
    let mut data = std::fs::read(&path).unwrap();
    data.extend_from_slice(b"[9, \"o\", \"forged\"]\n");
    std::fs::write(&path, data).unwrap();
    let (s, _) = call(&app, get(token("admin", &["RMM.Admin"]))).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);

    // Retention: nothing is old yet; backdate the session and it goes, file and all.
    assert_eq!(
        rmm_api::recording::purge_older_than(&state, 365)
            .await
            .unwrap(),
        0
    );
    sqlx::query("update tenant.shell_session set created_at = now() - interval '400 days'")
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        rmm_api::recording::purge_older_than(&state, 365)
            .await
            .unwrap(),
        1
    );
    assert!(!path.exists());
    assert_eq!(
        count(&ctx.pool, "select count(*) from tenant.shell_session").await,
        0
    );
    let _ = std::fs::remove_dir_all(&dir);
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
