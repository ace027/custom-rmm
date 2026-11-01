//! Integration tests for the identity schema, RLS and repositories.
//! Each `sqlx::test` gets a fresh database with migrations applied.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rmm_db::repo::{self, NewAgent, NewDevice, NewToken};
use rmm_db::scope::{Scope, begin_scoped};
use sqlx::PgPool;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::{JsonValue, Uuid};

type Tx = sqlx::Transaction<'static, sqlx::Postgres>;

/// Scoped transaction running as the given restricted role.
async fn tx_as(pool: &PgPool, role: &str, scope: Scope) -> Tx {
    let mut tx = begin_scoped(pool, &scope, "test").await.unwrap();
    sqlx::query(&format!("SET LOCAL ROLE {role}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

async fn api_tx(pool: &PgPool, scope: Scope) -> Tx {
    tx_as(pool, "rmm_api", scope).await
}

struct Seed {
    client: Uuid,
    site: Uuid,
    device: Uuid,
    agent: Uuid,
}

fn new_device(client: Uuid, site: Uuid, fp: &[u8]) -> NewDevice {
    NewDevice {
        client_id: client,
        site_id: site,
        hw_fingerprint: fp.to_vec(),
        fp_strength: "strong".into(),
        smbios_uuid: Some("00000000-1111-2222-3333-444444444444".into()),
        system_serial: Some("SER".into()),
        board_serial: Some("BRD".into()),
        os_family: "linux".into(),
        hostname: "host".into(),
        status: "active".into(),
        possible_clone_of: None,
    }
}

fn new_agent(client: Uuid, device: Uuid, key: u8) -> NewAgent {
    NewAgent {
        client_id: client,
        device_id: device,
        credential_pubkey: [key; 32],
        nkey: format!("U{key:02}"),
        version: "0.1.0".into(),
    }
}

fn new_token(client: Uuid, site: Uuid, hash: u8, ttl_secs: i64, max_uses: i32) -> NewToken {
    NewToken {
        client_id: client,
        site_id: site,
        token_hash: [hash; 32],
        expires_at: DateTime::from_timestamp(Utc::now().timestamp() + ttl_secs, 0).unwrap(),
        max_uses,
        allow_reattach: true,
        created_by: "tech".into(),
    }
}

/// Create a client with a site, device, agent and token, under service scope.
async fn seed(pool: &PgPool, name: &str, key: u8) -> Seed {
    let mut tx = api_tx(pool, Scope::Service("test-seed")).await;
    let client = repo::create_client(&mut tx, name).await.unwrap();
    let site = repo::create_site(&mut tx, client, "main", "UTC")
        .await
        .unwrap();
    let device = repo::insert_device(&mut tx, new_device(client, site, &[key; 32]))
        .await
        .unwrap();
    let agent = repo::insert_agent(&mut tx, new_agent(client, device, key))
        .await
        .unwrap();
    repo::create_enrollment_token(&mut tx, new_token(client, site, key, 3600, 1))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    Seed {
        client,
        site,
        device,
        agent,
    }
}

async fn count(tx: &mut Tx, table: &str) -> i64 {
    sqlx::query_scalar(&format!("select count(*) from {table}"))
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

const TENANT_TABLES: [&str; 5] = [
    "tenant.client",
    "tenant.site",
    "tenant.device",
    "tenant.agent",
    "tenant.enrollment_token",
];

#[sqlx::test(migrations = "./migrations")]
async fn client_scope_sees_only_own_rows(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let _b = seed(&pool, "B", 2).await;
    let mut tx = api_tx(&pool, Scope::Clients(vec![a.client])).await;
    for table in TENANT_TABLES {
        assert_eq!(count(&mut tx, table).await, 1, "{table}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn client_scope_cannot_insert_other_client_rows(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let b = seed(&pool, "B", 2).await;
    let scope = || Scope::Clients(vec![a.client]);

    let mut tx = api_tx(&pool, scope()).await;
    assert!(
        repo::create_site(&mut tx, b.client, "evil", "UTC")
            .await
            .is_err()
    );
    drop(tx);

    let mut tx = api_tx(&pool, scope()).await;
    let dev = repo::insert_device(&mut tx, new_device(b.client, b.site, &[9; 32])).await;
    assert!(dev.is_err());
    drop(tx);

    let mut tx = api_tx(&pool, scope()).await;
    let tok = repo::create_enrollment_token(&mut tx, new_token(b.client, b.site, 9, 3600, 1)).await;
    assert!(tok.is_err());
    drop(tx);

    let mut tx = api_tx(&pool, scope()).await;
    assert!(
        repo::insert_agent(&mut tx, new_agent(b.client, b.device, 9))
            .await
            .is_err()
    );
    drop(tx);

    let mut tx = api_tx(&pool, scope()).await;
    assert!(
        sqlx::query("insert into tenant.client (name) values ('x')")
            .execute(&mut *tx)
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn client_scope_cannot_update_other_client_rows(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let b = seed(&pool, "B", 2).await;
    let mut tx = api_tx(&pool, Scope::Clients(vec![a.client])).await;
    let row = repo::set_agent_status(&mut tx, b.agent, "revoked")
        .await
        .unwrap();
    assert!(row.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn empty_scope_sees_nothing(pool: PgPool) {
    seed(&pool, "A", 1).await;
    let mut tx = api_tx(&pool, Scope::Clients(vec![])).await;
    for table in TENANT_TABLES {
        assert_eq!(count(&mut tx, table).await, 0, "{table}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn service_scope_sees_all(pool: PgPool) {
    seed(&pool, "A", 1).await;
    seed(&pool, "B", 2).await;
    let mut tx = api_tx(&pool, Scope::Service("test")).await;
    for table in TENANT_TABLES {
        assert_eq!(count(&mut tx, table).await, 2, "{table}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn token_is_single_use_under_concurrency(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let consume = |pool: PgPool| async move {
        let mut tx = api_tx(&pool, Scope::Service("enroll")).await;
        let row = repo::consume_enrollment_token(&mut tx, &[1; 32])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        row
    };
    let (r1, r2) = tokio::join!(consume(pool.clone()), consume(pool.clone()));
    let wins = [r1, r2].into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(wins.len(), 1);
    assert_eq!(wins[0].client_id, a.client);
    assert_eq!(wins[0].site_id, a.site);
    assert_eq!(wins[0].uses, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_token_is_not_consumable(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = api_tx(&pool, Scope::Service("t")).await;
    repo::create_enrollment_token(&mut tx, new_token(a.client, a.site, 7, -5, 5))
        .await
        .unwrap();
    assert!(
        repo::consume_enrollment_token(&mut tx, &[7; 32])
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn revoked_token_is_not_consumable(pool: PgPool) {
    seed(&pool, "A", 1).await;
    sqlx::query("update tenant.enrollment_token set revoked = true")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = api_tx(&pool, Scope::Service("t")).await;
    assert!(
        repo::consume_enrollment_token(&mut tx, &[1; 32])
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn max_uses_is_enforced(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = api_tx(&pool, Scope::Service("t")).await;
    repo::create_enrollment_token(&mut tx, new_token(a.client, a.site, 5, 3600, 2))
        .await
        .unwrap();
    for expect_some in [true, true, false] {
        let got = repo::consume_enrollment_token(&mut tx, &[5; 32])
            .await
            .unwrap();
        assert_eq!(got.is_some(), expect_some);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn agent_by_pubkey_reports_agent_and_client_status(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = tx_as(&pool, "rmm_authd", Scope::Service("authd")).await;
    let row = repo::agent_by_pubkey(&mut tx, &[1; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.agent_id, a.agent);
    assert_eq!(row.device_id, a.device);
    assert_eq!(row.client_id, a.client);
    assert_eq!(row.status, "active");
    assert_eq!(row.client_status, "active");
    assert_eq!(row.nkey, "U01");
    assert!(
        repo::agent_by_pubkey(&mut tx, &[99; 32])
            .await
            .unwrap()
            .is_none()
    );
    drop(tx);

    sqlx::query("update tenant.client set status = 'disabled'")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = tx_as(&pool, "rmm_authd", Scope::Service("authd")).await;
    let row = repo::agent_by_pubkey(&mut tx, &[1; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.client_status, "disabled");
}

#[sqlx::test(migrations = "./migrations")]
async fn supersede_and_set_status(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = api_tx(&pool, Scope::Clients(vec![a.client])).await;
    let row = repo::supersede_agent(&mut tx, a.agent)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "superseded");
    let row = repo::set_agent_status(&mut tx, a.agent, "revoked")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "revoked");
    assert_eq!(row.nkey, "U01");
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_agent_status_is_rejected(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = api_tx(&pool, Scope::Clients(vec![a.client])).await;
    assert!(
        repo::set_agent_status(&mut tx, a.agent, "bogus")
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn fingerprint_lookup_uses_newest_non_superseded_agent(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = api_tx(&pool, Scope::Service("t")).await;
    let found = repo::find_devices_by_fingerprint(&mut tx, &[1; 32])
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].device_id, a.device);
    assert_eq!(found[0].client_id, a.client);
    assert_eq!(found[0].agent_id, Some(a.agent));
    assert_eq!(found[0].agent_status.as_deref(), Some("active"));
    assert!(found[0].last_seen.is_none());

    repo::touch_last_seen(&mut tx, a.agent).await.unwrap();
    repo::supersede_agent(&mut tx, a.agent).await.unwrap();
    let newer = repo::insert_agent(&mut tx, new_agent(a.client, a.device, 3))
        .await
        .unwrap();
    let found = repo::find_devices_by_fingerprint(&mut tx, &[1; 32])
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].agent_id, Some(newer));
    assert!(
        repo::find_devices_by_fingerprint(&mut tx, &[42; 32])
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_events_are_append_only(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = api_tx(&pool, Scope::Service("t")).await;
    repo::insert_audit(
        &mut tx,
        "tech",
        "enroll",
        Some(a.client),
        "agent",
        &JsonValue::Null,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    for stmt in [
        "update msp.audit_event set actor = 'x'",
        "delete from msp.audit_event",
        "truncate msp.audit_event",
    ] {
        assert!(sqlx::query(stmt).execute(&pool).await.is_err(), "{stmt}");
    }
    let n: i64 = sqlx::query_scalar("select count(*) from msp.audit_event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn authd_role_cannot_insert_device(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = tx_as(&pool, "rmm_authd", Scope::Service("authd")).await;
    let res = repo::insert_device(&mut tx, new_device(a.client, a.site, &[8; 32])).await;
    assert!(res.is_err());
    drop(tx);

    let mut tx = tx_as(&pool, "rmm_authd", Scope::Service("authd")).await;
    repo::touch_last_seen(&mut tx, a.agent).await.unwrap();
    assert!(
        repo::set_agent_status(&mut tx, a.agent, "revoked")
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn latest_trust_artifacts_returns_highest_seq_per_kind(pool: PgPool) {
    let mut tx = api_tx(&pool, Scope::Service("t")).await;
    for (kind, seq, body) in [
        ("manifest", 1, b"m1"),
        ("manifest", 2, b"m2"),
        ("techlist", 5, b"t5"),
    ] {
        let stored = repo::put_trust_artifact(&mut tx, kind, seq, b"cid", body, "tech")
            .await
            .unwrap();
        assert!(stored);
    }
    let dup = repo::put_trust_artifact(&mut tx, "manifest", 2, b"cid", b"dup", "tech")
        .await
        .unwrap();
    assert!(!dup);
    let latest = repo::latest_trust_artifacts(&mut tx).await.unwrap();
    assert_eq!(
        latest,
        vec![
            ("manifest".to_string(), 2, b"m2".to_vec()),
            ("techlist".to_string(), 5, b"t5".to_vec()),
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_trust_artifact_kind_is_rejected(pool: PgPool) {
    let mut tx = api_tx(&pool, Scope::Service("t")).await;
    assert!(
        repo::put_trust_artifact(&mut tx, "bogus", 1, b"cid", b"x", "tech")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn connect_as_rejects_bad_role_names() {
    for bad in ["", "rmm-api", "rmm_api; drop table x", "Rmm", "rmm1"] {
        let res = rmm_db::scope::connect_as("postgres://invalid/none", bad).await;
        assert!(matches!(res, Err(rmm_db::DbError::InvalidRole(_))), "{bad}");
    }
}
