//! Result consumer: subject and envelope checks without a database, and the
//! verified recording of agent-signed results against the database named by
//! `DATABASE_URL` (a unique client per test; skipped when it is unset).
//!
//! The results module is a child of `ingest`, compiled in directly (the
//! package has no library target and no direct sqlx dependency).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "../src/ingest.rs"]
mod ingest;

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rmm_db::DbError;
use rmm_db::actions::{self, NewActionRun};
use rmm_db::repo::{self, NewAgent, NewDevice, Tx};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_recipe::definition::Stage;
use rmm_recipe::result::{ActionResult, Outcome, RejectReason, StageOutcome, TYPE_RESULT};
use rmm_trust::envelope::{ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, signing_message};
use rmm_trust::keys::{Bytes, KeyId, PublicKey, Sig64};
use uuid::Uuid;

use ingest::results::{ResultProcessor, ResultStats, parse_subject};
use ingest::{BatchOutcome, Db, Incoming};

fn block<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn subject(client: Uuid, agent: Uuid) -> String {
    format!("result.{client}.{agent}")
}

fn sign_result(result: &ActionResult, signer: &SigningKey) -> Vec<u8> {
    let payload = result.to_canonical().unwrap();
    let msg = signing_message(TYPE_RESULT, &payload);
    let pk = PublicKey::from_bytes(&signer.verifying_key().to_bytes()).unwrap();
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: TYPE_RESULT.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: pk.key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(signer.sign(&msg).to_bytes()),
        }],
    }
    .to_bytes()
    .unwrap()
}

fn result_for(
    cmd: Uuid,
    agent: Uuid,
    cid: [u8; 32],
    outcome: Outcome,
    reason: Option<RejectReason>,
) -> ActionResult {
    ActionResult {
        cmd_id: Bytes(cmd.as_bytes().to_vec()),
        agent_id: agent.to_string(),
        definition_content_id: KeyId(cid),
        outcome,
        reason,
        stages: vec![StageOutcome {
            stage: Stage::Steps,
            ok: outcome == Outcome::Succeeded,
            started_at: now() - 5,
            finished_at: now() - 1,
            detail: "stopped, quarantined, started".into(),
        }],
        finished_at: now(),
    }
}

fn broken_processor() -> ResultProcessor {
    ResultProcessor::new(Db::new(
        Box::new(|| Box::pin(async { Err(DbError::InvalidRole("down".into())) })),
        Box::new(|| Box::pin(async { Err(DbError::InvalidRole("down".into())) })),
    ))
}

fn termed() -> BatchOutcome {
    BatchOutcome {
        acked: vec![],
        termed: vec![0],
        naked: vec![],
    }
}

fn acked() -> BatchOutcome {
    BatchOutcome {
        acked: vec![0],
        termed: vec![],
        naked: vec![],
    }
}

// --- without a database ----------------------------------------------------

#[test]
fn parses_a_valid_subject() {
    let (c, a) = (Uuid::from_u128(1), Uuid::from_u128(2));
    assert_eq!(parse_subject(&subject(c, a)), Some((c, a)));
    assert_eq!(parse_subject(&format!("{}.x", subject(c, a))), None);
    assert_eq!(parse_subject(&format!("telemetry.{c}.{a}")), None);
    assert_eq!(parse_subject(&format!("result.{c}")), None);
    assert_eq!(parse_subject("result.x.y"), None);
}

#[test]
fn bad_subjects_and_payloads_are_termed_without_the_database() {
    let p = broken_processor();
    let (c, a) = (Uuid::from_u128(1), Uuid::from_u128(2));
    let key = SigningKey::from_bytes(&[1; 32]);
    let good = sign_result(
        &result_for(Uuid::from_u128(3), a, [1; 32], Outcome::Succeeded, None),
        &key,
    );
    let good_subject = subject(c, a);
    // A payload that is not the canonical encoding fails to decode.
    let mut tampered = good.clone();
    tampered.push(0);
    // rejected without a reason
    let bad_doc = sign_result(
        &result_for(Uuid::from_u128(3), a, [1; 32], Outcome::Rejected, None),
        &key,
    );
    let msgs = [
        Incoming {
            subject: "result.x.y",
            payload: &good,
        },
        Incoming {
            subject: &good_subject,
            payload: b"not cbor",
        },
        Incoming {
            subject: &good_subject,
            payload: &bad_doc,
        },
        Incoming {
            subject: &good_subject,
            payload: &tampered,
        },
    ];
    let out = block(p.process_batch(&msgs));
    assert_eq!(out.termed, vec![0, 1, 2, 3]);
    assert!(out.acked.is_empty() && out.naked.is_empty());
    assert_eq!(ResultStats::get(&p.stats.bad_subject), 1);
    assert_eq!(ResultStats::get(&p.stats.malformed), 3);
}

#[test]
fn database_down_naks() {
    let p = broken_processor();
    let (c, a) = (Uuid::from_u128(1), Uuid::from_u128(2));
    let payload = sign_result(
        &result_for(Uuid::from_u128(3), a, [1; 32], Outcome::Succeeded, None),
        &SigningKey::from_bytes(&[1; 32]),
    );
    let s = subject(c, a);
    let out = block(p.process_batch(&[Incoming {
        subject: &s,
        payload: &payload,
    }]));
    assert_eq!(out.naked, vec![0]);
    assert_eq!(ResultStats::get(&p.stats.db_errors), 1);
}

// --- database-backed -------------------------------------------------------

fn database_url() -> Option<String> {
    let url = std::env::var("DATABASE_URL").ok();
    if url.is_none() {
        eprintln!("DATABASE_URL not set; skipping database test");
    }
    url
}

async fn admin_tx(url: &str) -> Tx<'static> {
    let pool = rmm_db::connect(url).await.unwrap();
    rmm_db::migrate(&pool).await.unwrap();
    begin_scoped(&pool, &Scope::Service("results-test"), "test")
        .await
        .unwrap()
}

fn random32() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    k[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    k
}

struct World {
    url: String,
    client: Uuid,
    /// Agent A, with its signing key, a definition and a queued run.
    agent: Uuid,
    key: SigningKey,
    cid: [u8; 32],
    cmd: Uuid,
    /// Agent B in the same client.
    other: Uuid,
    other_key: SigningKey,
    proc: ResultProcessor,
}

async fn seed_agent(tx: &mut Tx<'static>, client: Uuid, site: Uuid, key: &SigningKey) -> Uuid {
    let device = repo::insert_device(
        tx,
        NewDevice {
            client_id: client,
            site_id: site,
            hw_fingerprint: Uuid::new_v4().as_bytes().to_vec(),
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
    repo::insert_agent(
        tx,
        NewAgent {
            client_id: client,
            device_id: device,
            credential_pubkey: key.verifying_key().to_bytes(),
            nkey: format!("U{}", Uuid::new_v4().simple()),
            version: "0.1.0".into(),
        },
    )
    .await
    .unwrap()
}

async fn world(url: &str) -> World {
    let key = SigningKey::from_bytes(&random32());
    let other_key = SigningKey::from_bytes(&random32());
    let cid = random32();
    let cmd = Uuid::new_v4();
    let mut tx = admin_tx(url).await;
    let client = repo::create_client(&mut tx, &format!("results-{}", Uuid::new_v4()))
        .await
        .unwrap();
    let site = repo::create_site(&mut tx, client, "main", "UTC")
        .await
        .unwrap();
    let agent = seed_agent(&mut tx, client, site, &key).await;
    let other = seed_agent(&mut tx, client, site, &other_key).await;
    actions::put_definition(&mut tx, &cid, "test.action", 1, "service", b"env", "test")
        .await
        .unwrap();
    queue(&mut tx, client, agent, cid, cmd).await;
    tx.commit().await.unwrap();
    World {
        url: url.to_owned(),
        client,
        agent,
        key,
        cid,
        cmd,
        other,
        other_key,
        proc: ResultProcessor::new(Db::connect(url).await.unwrap()),
    }
}

async fn queue(tx: &mut Tx<'static>, client: Uuid, agent: Uuid, cid: [u8; 32], cmd: Uuid) {
    let dev = device_of(tx, agent).await;
    actions::insert_action_run(
        tx,
        NewActionRun {
            cmd_id: cmd,
            client_id: client,
            agent_id: agent,
            device_id: dev,
            definition_content_id: cid.to_vec(),
            params: Default::default(),
            requested_by: "test".into(),
        },
    )
    .await
    .unwrap();
}

async fn device_of(tx: &mut Tx<'static>, agent: Uuid) -> Uuid {
    rmm_db::telemetry::agent_for_telemetry(tx, agent)
        .await
        .unwrap()
        .unwrap()
        .device_id
}

async fn send(w: &World, subject: &str, payload: &[u8]) -> BatchOutcome {
    w.proc.process_batch(&[Incoming { subject, payload }]).await
}

async fn run_row(w: &World, cmd: Uuid) -> actions::ActionRunRow {
    let mut tx = admin_tx(&w.url).await;
    actions::action_run(&mut tx, cmd).await.unwrap().unwrap()
}

async fn audits(w: &World, cmd: Uuid) -> i64 {
    let mut tx = admin_tx(&w.url).await;
    repo::count_audit(&mut tx, "action.result", &format!("action_run:{cmd}"))
        .await
        .unwrap()
}

#[test]
fn valid_result_updates_the_run_and_writes_audit() {
    let Some(url) = database_url() else { return };
    block(async {
        let w = world(&url).await;
        let r = result_for(w.cmd, w.agent, w.cid, Outcome::Succeeded, None);
        let env = sign_result(&r, &w.key);
        let out = send(&w, &subject(w.client, w.agent), &env).await;
        assert_eq!(out, acked());
        let run = run_row(&w, w.cmd).await;
        assert_eq!(run.status, "succeeded");
        assert!(run.reason.is_none());
        assert!(run.finished_at.is_some());
        let stages = run.stages.as_array().unwrap();
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0]["stage"], "steps");
        assert_eq!(stages[0]["ok"], true);
        assert_eq!(audits(&w, w.cmd).await, 1);
        assert_eq!(ResultStats::get(&w.proc.stats.applied), 1);
    });
}

#[test]
fn duplicate_result_is_acked_without_a_second_update() {
    let Some(url) = database_url() else { return };
    block(async {
        let w = world(&url).await;
        let s = subject(w.client, w.agent);
        let first = sign_result(
            &result_for(w.cmd, w.agent, w.cid, Outcome::Succeeded, None),
            &w.key,
        );
        assert_eq!(send(&w, &s, &first).await, acked());
        assert_eq!(send(&w, &s, &first).await, acked());
        // A later, different (but validly signed) result for the same run.
        let second = sign_result(
            &result_for(w.cmd, w.agent, w.cid, Outcome::Failed, None),
            &w.key,
        );
        assert_eq!(send(&w, &s, &second).await, acked());
        assert_eq!(run_row(&w, w.cmd).await.status, "succeeded");
        assert_eq!(audits(&w, w.cmd).await, 1);
        assert_eq!(ResultStats::get(&w.proc.stats.duplicates), 2);
    });
}

#[test]
fn result_signed_by_another_agents_key_is_termed() {
    let Some(url) = database_url() else { return };
    block(async {
        let w = world(&url).await;
        let r = result_for(w.cmd, w.agent, w.cid, Outcome::Succeeded, None);
        let env = sign_result(&r, &w.other_key);
        let out = send(&w, &subject(w.client, w.agent), &env).await;
        assert_eq!(out, termed());
        assert_eq!(run_row(&w, w.cmd).await.status, "queued");
        assert_eq!(audits(&w, w.cmd).await, 0);
        assert_eq!(ResultStats::get(&w.proc.stats.bad_signature), 1);
    });
}

#[test]
fn result_with_a_mismatched_agent_is_termed() {
    let Some(url) = database_url() else { return };
    block(async {
        let w = world(&url).await;
        // Agent B publishes on its own subject but names agent A.
        let names_a = sign_result(
            &result_for(w.cmd, w.agent, w.cid, Outcome::Succeeded, None),
            &w.other_key,
        );
        assert_eq!(
            send(&w, &subject(w.client, w.other), &names_a).await,
            termed()
        );
        // Agent B names itself but answers agent A's command.
        let steals = sign_result(
            &result_for(w.cmd, w.other, w.cid, Outcome::Succeeded, None),
            &w.other_key,
        );
        assert_eq!(
            send(&w, &subject(w.client, w.other), &steals).await,
            termed()
        );
        // Agent A on its own subject but naming agent B.
        let names_b = sign_result(
            &result_for(w.cmd, w.other, w.cid, Outcome::Succeeded, None),
            &w.key,
        );
        assert_eq!(
            send(&w, &subject(w.client, w.agent), &names_b).await,
            termed()
        );
        // Right agent, wrong definition.
        let wrong_def = sign_result(
            &result_for(w.cmd, w.agent, [0xee; 32], Outcome::Succeeded, None),
            &w.key,
        );
        assert_eq!(
            send(&w, &subject(w.client, w.agent), &wrong_def).await,
            termed()
        );
        // Right agent, subject client of another tenant.
        let ok = sign_result(
            &result_for(w.cmd, w.agent, w.cid, Outcome::Succeeded, None),
            &w.key,
        );
        assert_eq!(
            send(&w, &subject(Uuid::new_v4(), w.agent), &ok).await,
            termed()
        );
        assert_eq!(run_row(&w, w.cmd).await.status, "queued");
        assert_eq!(audits(&w, w.cmd).await, 0);
    });
}

#[test]
fn unknown_command_and_unknown_agent_are_termed() {
    let Some(url) = database_url() else { return };
    block(async {
        let w = world(&url).await;
        let ghost = sign_result(
            &result_for(Uuid::new_v4(), w.agent, w.cid, Outcome::Succeeded, None),
            &w.key,
        );
        assert_eq!(
            send(&w, &subject(w.client, w.agent), &ghost).await,
            termed()
        );
        assert_eq!(ResultStats::get(&w.proc.stats.unknown_cmd), 1);

        let nobody = Uuid::new_v4();
        let env = sign_result(
            &result_for(w.cmd, nobody, w.cid, Outcome::Succeeded, None),
            &w.key,
        );
        assert_eq!(send(&w, &subject(w.client, nobody), &env).await, termed());
        assert_eq!(ResultStats::get(&w.proc.stats.unknown_agent), 1);
        assert_eq!(run_row(&w, w.cmd).await.status, "queued");
    });
}

#[test]
fn revoked_agents_last_result_counts_but_superseded_does_not() {
    let Some(url) = database_url() else { return };
    block(async {
        let w = world(&url).await;
        let mut tx = admin_tx(&url).await;
        repo::set_agent_status(&mut tx, w.agent, "revoked")
            .await
            .unwrap();
        repo::set_agent_status(&mut tx, w.other, "superseded")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let stolen = sign_result(
            &result_for(w.cmd, w.other, w.cid, Outcome::Succeeded, None),
            &w.other_key,
        );
        assert_eq!(
            send(&w, &subject(w.client, w.other), &stolen).await,
            termed()
        );
        assert_eq!(ResultStats::get(&w.proc.stats.inactive_agent), 1);

        let env = sign_result(
            &result_for(
                w.cmd,
                w.agent,
                w.cid,
                Outcome::Rejected,
                Some(RejectReason::Expired),
            ),
            &w.key,
        );
        assert_eq!(send(&w, &subject(w.client, w.agent), &env).await, acked());
        let run = run_row(&w, w.cmd).await;
        assert_eq!(run.status, "rejected");
        assert_eq!(run.reason.as_deref(), Some("expired"));
    });
}
