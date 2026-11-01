//! Action schema tests: definitions keyed by content id, two-client RLS on
//! action_run, ingest grants and idempotent finishing.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rmm_db::actions::{self, NewActionRun};
use rmm_db::repo::{self, NewAgent, NewDevice};
use rmm_db::scope::{Scope, begin_scoped};
use sqlx::PgPool;
use sqlx::types::chrono::Utc;
use sqlx::types::{JsonValue, Uuid};

type Tx = sqlx::Transaction<'static, sqlx::Postgres>;

async fn tx_as(pool: &PgPool, role: &str, scope: Scope) -> Tx {
    let mut tx = begin_scoped(pool, &scope, "test").await.unwrap();
    sqlx::query(&format!("SET LOCAL ROLE {role}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

struct Seed {
    client: Uuid,
    device: Uuid,
    agent: Uuid,
}

async fn seed(pool: &PgPool, name: &str, key: u8) -> Seed {
    let mut tx = tx_as(pool, "rmm_api", Scope::Service("test-seed")).await;
    let client = repo::create_client(&mut tx, name).await.unwrap();
    let site = repo::create_site(&mut tx, client, "main", "UTC")
        .await
        .unwrap();
    let device = repo::insert_device(
        &mut tx,
        NewDevice {
            client_id: client,
            site_id: site,
            hw_fingerprint: vec![key; 32],
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
    let agent = repo::insert_agent(
        &mut tx,
        NewAgent {
            client_id: client,
            device_id: device,
            credential_pubkey: [key; 32],
            nkey: format!("nkey-{key}"),
            version: "0.1.0".into(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Seed {
        client,
        device,
        agent,
    }
}

async fn define(pool: &PgPool, cid: &[u8; 32]) {
    let mut tx = tx_as(pool, "rmm_api", Scope::Service("test")).await;
    actions::put_definition(&mut tx, cid, "a.b", 1, "service", b"env", "tester")
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn new_run(s: &Seed, cid: &[u8; 32], n: u128) -> NewActionRun {
    NewActionRun {
        cmd_id: Uuid::from_u128(n),
        client_id: s.client,
        agent_id: s.agent,
        device_id: s.device,
        definition_content_id: cid.to_vec(),
        params: JsonValue::Object(Default::default()),
        requested_by: "tester".into(),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn definitions_are_keyed_by_content_id(pool: PgPool) {
    let cid = [3u8; 32];
    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![])).await;
    assert!(
        actions::put_definition(&mut tx, &cid, "a.b", 1, "service", b"env", "t")
            .await
            .unwrap()
    );
    assert!(
        !actions::put_definition(&mut tx, &cid, "a.b", 1, "service", b"env", "t")
            .await
            .unwrap(),
        "second insert of the same content id is a no-op"
    );
    let got = actions::definition_by_content_id(&mut tx, &cid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.id, "a.b");
    assert_eq!(got.envelope, b"env");
    assert!(
        actions::definition_by_content_id(&mut tx, &[4u8; 32])
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn action_run_is_scoped_per_client(pool: PgPool) {
    let (a, b) = (seed(&pool, "A", 1).await, seed(&pool, "B", 2).await);
    let cid = [5u8; 32];
    define(&pool, &cid).await;

    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    actions::insert_action_run(&mut tx, new_run(&a, &cid, 1))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // A client-scoped transaction cannot create a run for another client.
    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    let denied = actions::insert_action_run(&mut tx, new_run(&b, &cid, 2)).await;
    assert!(denied.is_err(), "cross-client insert must violate RLS");
    drop(tx);

    let mut tx = tx_as(&pool, "rmm_api", Scope::Service("test")).await;
    actions::insert_action_run(&mut tx, new_run(&b, &cid, 2))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    assert!(
        actions::action_run(&mut tx, Uuid::from_u128(1))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        actions::action_run(&mut tx, Uuid::from_u128(2))
            .await
            .unwrap()
            .is_none(),
        "other client's run is invisible"
    );
    drop(tx);
    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![])).await;
    assert!(
        actions::action_run(&mut tx, Uuid::from_u128(1))
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn ingest_can_finish_but_not_insert(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let cid = [6u8; 32];
    define(&pool, &cid).await;
    let mut tx = tx_as(&pool, "rmm_api", Scope::Service("test")).await;
    actions::insert_action_run(&mut tx, new_run(&a, &cid, 1))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("ingest")).await;
    let denied = actions::insert_action_run(&mut tx, new_run(&a, &cid, 9)).await;
    assert!(denied.is_err(), "rmm_ingest has no INSERT on action_run");
    drop(tx);

    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("ingest")).await;
    let stages: JsonValue = JsonValue::Array(vec![JsonValue::String("steps".into())]);
    let first = actions::finish_action_run(
        &mut tx,
        Uuid::from_u128(1),
        "succeeded",
        None,
        &stages,
        b"result",
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(first);
    let second = actions::finish_action_run(
        &mut tx,
        Uuid::from_u128(1),
        "failed",
        Some("x"),
        &JsonValue::Array(vec![]),
        b"other",
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(!second, "a finished run is not updated again");
    let row = actions::action_run(&mut tx, Uuid::from_u128(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "succeeded");
    assert_eq!(row.stages, stages);
    assert!(row.finished_at.is_some());
    // Columns outside the grant stay protected.
    let bad = sqlx::query("update tenant.action_run set requested_by = 'x'")
        .execute(&mut *tx)
        .await;
    assert!(bad.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn ingest_scope_without_service_sees_nothing(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let cid = [7u8; 32];
    define(&pool, &cid).await;
    let mut tx = tx_as(&pool, "rmm_api", Scope::Service("test")).await;
    actions::insert_action_run(&mut tx, new_run(&a, &cid, 1))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Clients(vec![])).await;
    assert!(
        actions::action_run(&mut tx, Uuid::from_u128(1))
            .await
            .unwrap()
            .is_none()
    );
}
