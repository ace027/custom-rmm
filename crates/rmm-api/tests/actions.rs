//! Catalog upload, command issuing and run status, against a database. The
//! issued command is verified with the same trust code the agent runs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmm_api::actions::{IssueRequest, issue_command, read_run};
use rmm_api::auth::{AuthConfig, Authenticator, DEV_ISSUER, rsa_private_der_from_pem};
use rmm_api::{ApiError, AppState, TrustRoots};
use rmm_db::actions as db_actions;
use rmm_db::repo::{self, NewAgent, NewDevice};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_proto::canonical::to_canonical_vec;
use rmm_recipe::definition::{Definition, TYPE_DEFINITION};
use rmm_trust::docs::{ArtifactRevocations, Cert, CommandBody, Role, TrustManifest};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_MANIFEST, TYPE_REVOCATIONS,
    signing_message,
};
use rmm_trust::keys::{Bytes, KeyId, PublicKey, Sig64};
use rmm_trust::store::{Clock, DocKind, ReplayCache, SeqStore, TrustStore};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Uuid;
use sqlx::types::chrono::Utc;
use sqlx::{PgPool, Row};
use tower::ServiceExt;

const AUD: &str = "api://rmm-test";
const SPOOLER: &str = include_str!("../../../catalog/printing.spooler-restart.json");

fn now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(k: &SigningKey) -> PublicKey {
    PublicKey::from_bytes(&k.verifying_key().to_bytes()).unwrap()
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

const ROOT: u8 = 7;
const CATALOG: u8 = 8;
const COMMAND: u8 = 9;
const ROGUE: u8 = 10;

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
        console_rp_id: "console.test".into(),
        console_origins: vec!["https://console.test".into()],
        capability_ceiling: vec!["service".into(), "files.write".into()],
        revocation_mirrors: vec![],
    };
    sign_env(TYPE_MANIFEST, to_canonical_vec(&doc).unwrap(), &key(ROOT))
}

fn revocations(seq: u64, revoked: &[[u8; 32]]) -> Vec<u8> {
    let doc = ArtifactRevocations {
        seq,
        issued_at: now() - 100,
        expires_at: now() + 86_400,
        revoked_hashes: revoked.iter().map(|h| KeyId(*h)).collect(),
    };
    sign_env(
        TYPE_REVOCATIONS,
        to_canonical_vec(&doc).unwrap(),
        &key(CATALOG),
    )
}

/// A definition envelope signed by `signer`; `edit` adjusts the JSON draft.
fn definition(signer: u8, edit: impl FnOnce(&mut Value)) -> (Vec<u8>, [u8; 32]) {
    let mut v: Value = serde_json::from_str(SPOOLER).unwrap();
    edit(&mut v);
    let def: Definition = serde_json::from_value(v).unwrap();
    let payload = def.to_canonical().unwrap();
    let env = sign_env(TYPE_DEFINITION, payload, &key(signer));
    let cid = Envelope::from_bytes(&env).unwrap().content_id();
    (env, cid)
}

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

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

fn admin() -> String {
    let c = json!({"iss": DEV_ISSUER, "aud": AUD, "exp": now() + 600, "sub": "dev-admin",
        "oid": "oid-1", "name": "Dev", "roles": ["RMM.Admin"]});
    let k = EncodingKey::from_rsa_der(&rsa_private_der_from_pem(DEV_KEY.as_bytes()).unwrap());
    format!(
        "Bearer {}",
        encode(&Header::new(Algorithm::RS256), &c, &k).unwrap()
    )
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
            os_family: "windows".into(),
            hostname: "pc".into(),
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

async fn setup(pool: PgPool, with_key: bool) -> Ctx {
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
        .with_command_key(with_key.then(|| key(COMMAND)));
    let (client, agent) = seed_agent(&pool, "Acme", 1).await;
    Ctx {
        pool,
        app: rmm_api::router(state.clone()),
        state,
        client,
        agent,
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

async fn put(ctx: &Ctx, path: &str, body: Vec<u8>) -> StatusCode {
    let req = Request::put(path)
        .header("authorization", admin())
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap();
    call(&ctx.app, req).await.0
}

async fn install_trust(ctx: &Ctx, revoked: &[[u8; 32]]) {
    assert_eq!(
        put(ctx, "/api/v1/trust/manifest", manifest()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(ctx, "/api/v1/trust/revocations", revocations(1, revoked)).await,
        StatusCode::NO_CONTENT
    );
}

async fn upload(ctx: &Ctx, env: Vec<u8>) -> StatusCode {
    put(ctx, "/api/v1/catalog", env).await
}

async fn definitions(pool: &PgPool) -> i64 {
    sqlx::query("select count(*) from msp.action_definition")
        .fetch_one(pool)
        .await
        .unwrap()
        .get(0)
}

async fn post_action(ctx: &Ctx, agent: Uuid, body: Value) -> (StatusCode, Value) {
    let req = Request::post(format!("/api/v1/agents/{agent}/actions"))
        .header("authorization", admin())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (s, b) = call(&ctx.app, req).await;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
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

/// The agent-side view of trust: root key, manifest, revocations.
fn agent_trust(revoked: &[[u8; 32]]) -> TrustStore {
    let mut store = TrustStore::new(vec![public(&key(ROOT))], 1);
    let mut seqs = Seqs::default();
    store
        .apply_manifest(&manifest(), &Fixed, &mut seqs)
        .unwrap();
    store
        .apply_revocations(&revocations(1, revoked), &Fixed, &mut seqs)
        .unwrap();
    store
}

// --- tests -----------------------------------------------------------------

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn upload_accepts_catalog_signed_and_rejects_the_rest(pool: PgPool) {
    let ctx = setup(pool, true).await;
    let (env, cid) = definition(CATALOG, |_| {});

    // No manifest yet: nothing can be verified.
    assert_eq!(
        upload(&ctx, env.clone()).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    install_trust(&ctx, &[]).await;

    assert_eq!(upload(&ctx, env.clone()).await, StatusCode::CREATED);
    assert_eq!(
        upload(&ctx, env.clone()).await,
        StatusCode::OK,
        "idempotent"
    );
    assert_eq!(definitions(&ctx.pool).await, 1);
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("t"), "t")
        .await
        .unwrap();
    let stored = db_actions::definition_by_content_id(&mut tx, &cid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.envelope, env);
    assert_eq!(stored.id, "printing.spooler-restart");
    drop(tx);

    // Signed by a key the manifest does not certify.
    let (rogue, _) = definition(ROGUE, |v| v["id"] = json!("printing.rogue"));
    assert_eq!(upload(&ctx, rogue).await, StatusCode::UNPROCESSABLE_ENTITY);
    // Signed by the command key: certified, but not for the catalog role.
    let (wrong_role, _) = definition(COMMAND, |v| v["id"] = json!("printing.wrongrole"));
    assert_eq!(
        upload(&ctx, wrong_role).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Catalog-signed but fails static validation (unknown block).
    let (bad, _) = definition(CATALOG, |v| {
        v["id"] = json!("printing.badblock");
        v["steps"][0]["block"] = json!("shell.exec");
    });
    assert_eq!(upload(&ctx, bad).await, StatusCode::UNPROCESSABLE_ENTITY);
    // Tampered envelope.
    let mut tampered =
        Envelope::from_bytes(&definition(CATALOG, |v| v["id"] = json!("a.b")).0).unwrap();
    tampered.sigs[0].sig.0[0] ^= 1;
    assert_eq!(
        upload(&ctx, tampered.to_bytes().unwrap()).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Garbage and a wrong envelope type.
    assert_eq!(
        upload(&ctx, b"junk".to_vec()).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        upload(&ctx, manifest()).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(definitions(&ctx.pool).await, 1, "rejects store nothing");

    // Unauthenticated.
    let req = Request::put("/api/v1/catalog")
        .body(Body::from(env))
        .unwrap();
    assert_eq!(call(&ctx.app, req).await.0, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn revoked_content_id_is_rejected_at_upload_and_at_issue(pool: PgPool) {
    let ctx = setup(pool, true).await;
    let (env, cid) = definition(CATALOG, |_| {});
    let (other, other_cid) = definition(CATALOG, |v| v["id"] = json!("printing.other"));
    assert_ne!(cid, other_cid);

    assert_eq!(
        put(&ctx, "/api/v1/trust/manifest", manifest()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(
            &ctx,
            "/api/v1/trust/revocations",
            revocations(1, &[other_cid])
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        upload(&ctx, other).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "revoked at upload"
    );
    assert_eq!(definitions(&ctx.pool).await, 0);

    assert_eq!(upload(&ctx, env).await, StatusCode::CREATED);
    let body = json!({"definition_content_id": hex(&cid), "params": {}});
    assert_eq!(
        post_action(&ctx, ctx.agent, body.clone()).await.0,
        StatusCode::ACCEPTED
    );
    // The definition is revoked after it was stored.
    assert_eq!(
        put(
            &ctx,
            "/api/v1/trust/revocations",
            revocations(2, &[other_cid, cid])
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_action(&ctx, ctx.agent, body).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn issued_command_verifies_like_the_agent_does(pool: PgPool) {
    let ctx = setup(pool, true).await;
    install_trust(&ctx, &[]).await;
    let (env, cid) = definition(CATALOG, |_| {});
    assert_eq!(upload(&ctx, env.clone()).await, StatusCode::CREATED);

    let req = IssueRequest {
        definition_content_id: hex(&cid),
        params: json!({}),
    };
    let issued = issue_command(
        &ctx.state,
        &Scope::Service("test"),
        "tester",
        ctx.agent,
        &req,
    )
    .await
    .unwrap();

    let store = agent_trust(&[]);
    let mut replay = Replay::default();
    let cmd = store
        .verify_command(
            &issued.command,
            &ctx.agent.to_string(),
            &ctx.client.to_string(),
            &Fixed,
            &mut replay,
        )
        .unwrap();
    assert_eq!(cmd.cmd_id.0, issued.cmd_id.as_bytes().to_vec());
    assert_eq!(cmd.expires_at - cmd.issued_at, 600);
    assert_eq!(cmd.policy_hash.0.len(), 32);
    match cmd.body {
        CommandBody::Invoke { definition, .. } => assert_eq!(definition.0, env),
        other => panic!("unexpected body {other:?}"),
    }
    // A second verification is a replay.
    assert!(
        store
            .verify_command(
                &issued.command,
                &ctx.agent.to_string(),
                &ctx.client.to_string(),
                &Fixed,
                &mut replay,
            )
            .is_err()
    );
    // Addressed to this agent only.
    assert!(
        store
            .verify_command(
                &issued.command,
                &Uuid::from_u128(5).to_string(),
                &ctx.client.to_string(),
                &Fixed,
                &mut Replay::default(),
            )
            .is_err()
    );

    // The run is recorded as queued and an audit row exists.
    let run = read_run(&ctx.state, &Scope::Service("t"), "t", issued.cmd_id)
        .await
        .unwrap();
    assert_eq!(run.status, "queued");
    assert!(run.finished_at.is_none());
    let audits: i64 =
        sqlx::query("select count(*) from msp.audit_event where action = 'action.issue'")
            .fetch_one(&ctx.pool)
            .await
            .unwrap()
            .get(0);
    assert_eq!(audits, 1);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn issue_validates_params_and_definition(pool: PgPool) {
    let ctx = setup(pool, true).await;
    install_trust(&ctx, &[]).await;
    let (env, cid) = definition(CATALOG, |v| {
        v["id"] = json!("test.waiter");
        v["params"] =
            json!([{"name": "wait_s", "kind": "int", "required": true, "min": 1, "max": 120}]);
    });
    assert_eq!(upload(&ctx, env).await, StatusCode::CREATED);
    let hexid = hex(&cid);

    let (s, body) = post_action(
        &ctx,
        ctx.agent,
        json!({"definition_content_id": hexid, "params": {"wait_s": 30}}),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let cmd_id: Uuid = body["cmd_id"].as_str().unwrap().parse().unwrap();

    for params in [
        json!({"wait_s": 9999}),
        json!({}),
        json!({"wait_s": "x"}),
        json!({"wait_s": 5, "extra": 1}),
        json!([1]),
    ] {
        let (s, _) = post_action(
            &ctx,
            ctx.agent,
            json!({"definition_content_id": hexid, "params": params}),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "params {params}");
    }
    let unknown = hex(&[9u8; 32]);
    for id in [unknown.as_str(), "zz", "abcd"] {
        let (s, _) = post_action(
            &ctx,
            ctx.agent,
            json!({"definition_content_id": id, "params": {}}),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "id {id}");
    }
    let (s, _) = post_action(
        &ctx,
        Uuid::from_u128(77),
        json!({"definition_content_id": hexid, "params": {"wait_s": 30}}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Poll the accepted run over HTTP.
    let req = Request::get(format!("/api/v1/action-runs/{cmd_id}"))
        .header("authorization", admin())
        .body(Body::empty())
        .unwrap();
    let (s, b) = call(&ctx.app, req).await;
    assert_eq!(s, StatusCode::OK);
    let run: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(run["status"], "queued");
    assert!(run["finished_at"].is_null());
    assert_eq!(run["stages"], json!([]));
    let req = Request::get(format!("/api/v1/action-runs/{}", Uuid::from_u128(1)))
        .header("authorization", admin())
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&ctx.app, req).await.0, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn inactive_agent_conflicts_and_missing_key_is_503(pool: PgPool) {
    let ctx = setup(pool, true).await;
    install_trust(&ctx, &[]).await;
    let (env, cid) = definition(CATALOG, |_| {});
    assert_eq!(upload(&ctx, env).await, StatusCode::CREATED);
    let body = json!({"definition_content_id": hex(&cid), "params": {}});

    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("t"), "t")
        .await
        .unwrap();
    repo::set_agent_status(&mut tx, ctx.agent, "revoked")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        post_action(&ctx, ctx.agent, body.clone()).await.0,
        StatusCode::CONFLICT
    );

    // Same state without a command key.
    let state = ctx.state.clone().with_command_key(None);
    let app = rmm_api::router(state);
    let nokey = Ctx { app, ..ctx };
    assert_eq!(
        post_action(&nokey, nokey.agent, body.clone()).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        post_action(&nokey, nokey.agent, body).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn other_client_scope_sees_nothing(pool: PgPool) {
    let ctx = setup(pool, true).await;
    install_trust(&ctx, &[]).await;
    let (env, cid) = definition(CATALOG, |_| {});
    assert_eq!(upload(&ctx, env).await, StatusCode::CREATED);
    let (other_client, _other_agent) = seed_agent(&ctx.pool, "Other", 2).await;
    let req = IssueRequest {
        definition_content_id: hex(&cid),
        params: json!({}),
    };

    // An agent outside the caller's client scope is unknown.
    let err = issue_command(
        &ctx.state,
        &Scope::Clients(vec![other_client]),
        "tester",
        ctx.agent,
        &req,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ApiError::NotFound(_)), "{err:?}");
    let err = issue_command(&ctx.state, &Scope::Clients(vec![]), "t", ctx.agent, &req)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiError::NotFound(_)), "{err:?}");

    // A run of one client is unknown to another.
    let issued = issue_command(
        &ctx.state,
        &Scope::Clients(vec![ctx.client]),
        "tester",
        ctx.agent,
        &req,
    )
    .await
    .unwrap();
    assert!(
        read_run(
            &ctx.state,
            &Scope::Clients(vec![ctx.client]),
            "t",
            issued.cmd_id
        )
        .await
        .is_ok()
    );
    let err = read_run(
        &ctx.state,
        &Scope::Clients(vec![other_client]),
        "t",
        issued.cmd_id,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ApiError::NotFound(_)), "{err:?}");
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
