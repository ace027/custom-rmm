//! Telemetry schema tests: two-client scoping (including compressed chunks),
//! ts_private denial, role-gated service bypass, inventory events.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rmm_db::repo::{self, NewAgent, NewDevice};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::telemetry::{self, InventoryUpdate, MetricRow};
use sqlx::PgPool;
use sqlx::types::chrono::{DateTime, Utc};
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
    repo::insert_agent(
        &mut tx,
        NewAgent {
            client_id: client,
            device_id: device,
            credential_pubkey: [key; 32],
            nkey: format!("U{key:02}"),
            version: "0.1.0".into(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Seed { client, device }
}

fn metric(s: &Seed, age_days: i64, name: &str) -> MetricRow {
    MetricRow {
        time: DateTime::from_timestamp(Utc::now().timestamp() - age_days * 86_400, 0).unwrap(),
        client_id: s.client,
        device_id: s.device,
        metric: name.into(),
        value: 1.5,
    }
}

async fn insert_metrics(pool: &PgPool, rows: &[MetricRow]) {
    let mut tx = tx_as(pool, "rmm_ingest", Scope::Service("test-ingest")).await;
    let n = telemetry::insert_metrics(&mut tx, rows).await.unwrap();
    assert_eq!(n, rows.len() as u64);
    tx.commit().await.unwrap();
}

fn inv(ram: i64, hash: u8) -> InventoryUpdate {
    InventoryUpdate {
        os_version: Some("Linux 6".into()),
        cpu_model: Some("cpu".into()),
        cpu_cores: Some(4),
        ram_bytes: Some(ram),
        disk_total_bytes: None,
        disk_free_bytes: None,
        last_boot: None,
        inventory: JsonValue::Null,
        inventory_hash: [hash; 32],
    }
}

async fn view_rows(pool: &PgPool, scope: Scope) -> Vec<Uuid> {
    let mut tx = tx_as(pool, "rmm_api", scope).await;
    sqlx::query_scalar("select client_id from tenant.metrics_v")
        .fetch_all(&mut *tx)
        .await
        .unwrap()
}

async fn two_clients_with_compressed_metrics(pool: &PgPool) -> (Seed, Seed) {
    let a = seed(pool, "A", 1).await;
    let b = seed(pool, "B", 2).await;
    let mut rows = Vec::new();
    for _ in 0..3 {
        rows.push(metric(&a, 10, "cpu"));
    }
    for _ in 0..2 {
        rows.push(metric(&b, 10, "cpu"));
    }
    rows.push(metric(&a, 0, "cpu"));
    rows.push(metric(&b, 0, "cpu"));
    insert_metrics(pool, &rows).await;
    let compressed: i64 = sqlx::query_scalar(
        "select count(compress_chunk(c, if_not_compressed => true)) from show_chunks('ts_private.metrics', older_than => interval '7 days') c",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(compressed >= 1);
    (a, b)
}

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.to_string())
}

#[sqlx::test(migrations = "./migrations")]
async fn view_filters_by_client_on_compressed_chunks(pool: PgPool) {
    let (a, b) = two_clients_with_compressed_metrics(&pool).await;
    let ra = view_rows(&pool, Scope::Clients(vec![a.client])).await;
    assert_eq!(ra.len(), 4);
    assert!(ra.iter().all(|c| *c == a.client));
    let rb = view_rows(&pool, Scope::Clients(vec![b.client])).await;
    assert_eq!(rb.len(), 3);
    assert!(rb.iter().all(|c| *c == b.client));
    assert!(view_rows(&pool, Scope::Clients(vec![])).await.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn api_cannot_read_ts_private(pool: PgPool) {
    let (a, _b) = two_clients_with_compressed_metrics(&pool).await;
    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    let err = sqlx::query("select * from ts_private.metrics")
        .fetch_all(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"));
}

#[sqlx::test(migrations = "./migrations")]
async fn service_flag_does_not_widen_view_or_open_ts_private(pool: PgPool) {
    let (a, _b) = two_clients_with_compressed_metrics(&pool).await;
    let mut tx = tx_as(&pool, "rmm_api", Scope::Service("test")).await;
    let err = sqlx::query("select * from ts_private.metrics")
        .fetch_all(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"));
    drop(tx);
    // Service scope sets no client ids: the view yields nothing.
    assert!(view_rows(&pool, Scope::Service("test")).await.is_empty());

    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    sqlx::query("select set_config('rmm.service', 'on', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let rows: Vec<Uuid> = sqlx::query_scalar("select client_id from tenant.metrics_v")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|c| *c == a.client));
}

#[sqlx::test(migrations = "./migrations")]
async fn service_bypass_requires_rmm_service_membership(pool: PgPool) {
    seed(&pool, "A", 1).await;
    seed(&pool, "B", 2).await;
    sqlx::query("create role rmm_test_reader nologin")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("grant usage on schema tenant, rmm to rmm_test_reader")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("grant select on tenant.device to rmm_test_reader")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = tx_as(&pool, "rmm_test_reader", Scope::Service("test")).await;
    let n: i64 = sqlx::query_scalar("select count(*) from tenant.device")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 0);
    drop(tx);
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test")).await;
    let n: i64 = sqlx::query_scalar("select count(*) from tenant.device")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 2);
    drop(tx);
    sqlx::query("drop owned by rmm_test_reader")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("drop role rmm_test_reader")
        .execute(&pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn identical_inventory_hash_is_a_noop(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let now = Utc::now();
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test")).await;
    let first = telemetry::apply_inventory(&mut tx, a.client, a.device, &inv(8, 7), now)
        .await
        .unwrap();
    let fields = first.unwrap();
    assert_eq!(
        fields,
        vec!["os_version", "cpu_model", "cpu_cores", "ram_bytes"]
    );
    let second = telemetry::apply_inventory(&mut tx, a.client, a.device, &inv(8, 7), now)
        .await
        .unwrap();
    assert!(second.is_none());
    tx.commit().await.unwrap();
    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    let events = telemetry::device_events(&mut tx, a.device, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].r#type, "inventory.changed");
}

#[sqlx::test(migrations = "./migrations")]
async fn ram_change_writes_event_with_only_ram(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test")).await;
    telemetry::apply_inventory(&mut tx, a.client, a.device, &inv(8, 1), Utc::now())
        .await
        .unwrap();
    let changed = telemetry::apply_inventory(&mut tx, a.client, a.device, &inv(16, 2), Utc::now())
        .await
        .unwrap();
    assert_eq!(changed, Some(vec!["ram_bytes".to_owned()]));
    tx.commit().await.unwrap();
    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    let events = telemetry::device_events(&mut tx, a.device, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    let newest = &events[0];
    assert_eq!(
        newest.before.as_ref().unwrap(),
        &serde_like(&[("ram_bytes", 8)])
    );
    assert_eq!(
        newest.after.as_ref().unwrap(),
        &serde_like(&[("ram_bytes", 16)])
    );
}

fn serde_like(pairs: &[(&str, i64)]) -> JsonValue {
    JsonValue::Object(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), JsonValue::from(*v)))
            .collect(),
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn device_event_is_append_only(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test")).await;
    telemetry::apply_inventory(&mut tx, a.client, a.device, &inv(8, 1), Utc::now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Owner connection without RLS passing still hits the trigger first for
    // statements it may run; use a service-scoped owner-equivalent role.
    for stmt in [
        "update tenant.device_event set type = 'x'",
        "delete from tenant.device_event",
        "truncate tenant.device_event",
    ] {
        let mut conn = pool.acquire().await.unwrap();
        let err = sqlx::query(stmt).execute(&mut *conn).await.unwrap_err();
        assert!(err.to_string().contains("append-only"), "{stmt}: {err}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn ingest_privileges(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test")).await;
    telemetry::insert_metrics(&mut tx, &[metric(&a, 0, "cpu")])
        .await
        .unwrap();
    assert_eq!(telemetry::insert_metrics(&mut tx, &[]).await.unwrap(), 0);
    telemetry::apply_inventory(&mut tx, a.client, a.device, &inv(8, 1), Utc::now())
        .await
        .unwrap();
    let ag = telemetry::agent_for_telemetry(&mut tx, Uuid::nil())
        .await
        .unwrap();
    assert!(ag.is_none());
    telemetry::touch_heartbeat(&mut tx, Uuid::nil(), Utc::now())
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test")).await;
    let err = sqlx::query("select * from tenant.enrollment_token")
        .fetch_all(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"));
}

#[sqlx::test(migrations = "./migrations")]
async fn device_event_rls_isolates_clients(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    let b = seed(&pool, "B", 2).await;
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test")).await;
    for s in [&a, &b] {
        telemetry::apply_inventory(&mut tx, s.client, s.device, &inv(8, 1), Utc::now())
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let mut tx = tx_as(&pool, "rmm_api", Scope::Clients(vec![a.client])).await;
    assert_eq!(
        telemetry::device_events(&mut tx, a.device, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        telemetry::device_events(&mut tx, b.device, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn claim_msg_ids_returns_only_new_ids(pool: PgPool) {
    let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test-ingest")).await;
    let first = telemetry::claim_msg_ids(&mut tx, &[a, b, b]).await.unwrap();
    assert_eq!(first, [a, b].into_iter().collect());
    tx.commit().await.unwrap();

    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test-ingest")).await;
    let second = telemetry::claim_msg_ids(&mut tx, &[b, c]).await.unwrap();
    assert_eq!(second, [c].into_iter().collect());
    assert!(
        telemetry::claim_msg_ids(&mut tx, &[])
            .await
            .unwrap()
            .is_empty()
    );
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn prune_ingested_deletes_only_old_records(pool: PgPool) {
    let (old, fresh) = (Uuid::from_u128(10), Uuid::from_u128(11));
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test-ingest")).await;
    telemetry::claim_msg_ids(&mut tx, &[old, fresh])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("update ts_private.ingested_msg set received_at = now() - interval '8 days' where msg_id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .unwrap();

    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("test-ingest")).await;
    let cutoff = DateTime::from_timestamp(Utc::now().timestamp() - 7 * 86_400, 0).unwrap();
    assert_eq!(telemetry::prune_ingested(&mut tx, cutoff).await.unwrap(), 1);
    let again = telemetry::claim_msg_ids(&mut tx, &[old, fresh])
        .await
        .unwrap();
    assert_eq!(again, [old].into_iter().collect());
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn rmm_api_cannot_read_the_dedupe_table(pool: PgPool) {
    let mut tx = tx_as(&pool, "rmm_api", Scope::Service("test-api")).await;
    let err = sqlx::query("select count(*) from ts_private.ingested_msg")
        .fetch_one(&mut *tx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}
