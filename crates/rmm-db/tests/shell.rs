//! Shell schema tests: two-client RLS on shell_session and shell_ws_ticket,
//! single-use tickets and challenges, expiry, unique credential ids and
//! the retention query.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rmm_db::repo::{self, NewAgent, NewDevice};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::shell::{self, NewCredential, NewShellSession};
use sqlx::PgPool;
use sqlx::types::Uuid;
use sqlx::types::chrono::Utc;

type Tx = sqlx::Transaction<'static, sqlx::Postgres>;

async fn tx_as(pool: &PgPool, role: &str, scope: Scope) -> Tx {
    let mut tx = begin_scoped(pool, &scope, "test").await.unwrap();
    sqlx::query(&format!("SET LOCAL ROLE {role}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

async fn api(pool: &PgPool, scope: Scope) -> Tx {
    tx_as(pool, "rmm_api", scope).await
}

struct Seed {
    client: Uuid,
    agent: Uuid,
}

async fn seed(pool: &PgPool, name: &str, key: u8) -> Seed {
    let mut tx = api(pool, Scope::Service("test-seed")).await;
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
    Seed { client, agent }
}

fn cred(tech: &str, id: u8) -> NewCredential {
    NewCredential {
        cred_id: vec![id; 16],
        tech_id: tech.into(),
        alg: -7,
        cose_pubkey: vec![0xa5],
        aaguid: vec![0xee; 16],
        sign_count: 0,
        attestation_fmt: "packed".into(),
    }
}

async fn tech_with_cred(pool: &PgPool, tech: &str, id: u8) {
    let mut tx = api(pool, Scope::Clients(vec![])).await;
    shell::upsert_technician(&mut tx, tech, "Tech")
        .await
        .unwrap();
    assert!(
        shell::insert_credential(&mut tx, cred(tech, id))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
}

fn session(s: &Seed, tech: &str, cred_id: u8, gid: u8) -> NewShellSession {
    NewShellSession {
        grant_id: vec![gid; 16],
        client_id: s.client,
        agent_id: s.agent,
        tech_id: tech.into(),
        cred_id: vec![cred_id; 16],
        shell: "sh".into(),
        max_duration: 600,
        grant_cbor: vec![0xa0],
    }
}

async fn insert_session(pool: &PgPool, s: NewShellSession) {
    let mut tx = api(pool, Scope::Clients(vec![s.client_id])).await;
    shell::insert_shell_session(&mut tx, s).await.unwrap();
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn shell_session_and_ticket_are_scoped_per_client(pool: PgPool) {
    let (a, b) = (seed(&pool, "A", 1).await, seed(&pool, "B", 2).await);
    tech_with_cred(&pool, "alice", 1).await;
    insert_session(&pool, session(&a, "alice", 1, 0xa1)).await;
    insert_session(&pool, session(&b, "alice", 1, 0xb1)).await;

    // A client-scoped transaction cannot create a session for another client.
    let mut tx = api(&pool, Scope::Clients(vec![a.client])).await;
    let denied = shell::insert_shell_session(&mut tx, session(&b, "alice", 1, 0xb2)).await;
    assert!(denied.is_err(), "cross-client insert must violate RLS");
    drop(tx);

    let mut tx = api(&pool, Scope::Clients(vec![a.client])).await;
    assert!(
        shell::shell_session(&mut tx, &[0xa1; 16])
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        shell::shell_session(&mut tx, &[0xb1; 16])
            .await
            .unwrap()
            .is_none(),
        "other client's session is invisible"
    );
    assert!(
        !shell::update_shell_status(&mut tx, &[0xb1; 16], &["pending"], "open", None)
            .await
            .unwrap(),
        "other client's session cannot be updated"
    );
    drop(tx);

    // Tickets: B's ticket is invisible and unconsumable from A's scope.
    let mut tx = api(&pool, Scope::Clients(vec![b.client])).await;
    shell::insert_ws_ticket(&mut tx, &[0x11; 32], b.client, &[0xb1; 16], 60)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = api(&pool, Scope::Clients(vec![a.client])).await;
    assert!(
        shell::consume_ws_ticket(&mut tx, &[0x11; 32])
            .await
            .unwrap()
            .is_none()
    );
    // Nor can A mint a ticket for B's session, or one pointing at B's
    // session under A's client id.
    let denied = shell::insert_ws_ticket(&mut tx, &[0x12; 32], b.client, &[0xb1; 16], 60).await;
    assert!(denied.is_err());
    drop(tx);
    let mut tx = api(&pool, Scope::Clients(vec![a.client])).await;
    let mismatched = shell::insert_ws_ticket(&mut tx, &[0x13; 32], a.client, &[0xb1; 16], 60).await;
    assert!(mismatched.is_err(), "ticket client must match the session");
    drop(tx);

    // An empty scope sees nothing.
    let mut tx = api(&pool, Scope::Clients(vec![])).await;
    assert!(
        shell::shell_session(&mut tx, &[0xa1; 16])
            .await
            .unwrap()
            .is_none()
    );
    drop(tx);

    // The ingest role has no access at all.
    let mut tx = tx_as(&pool, "rmm_ingest", Scope::Service("ingest")).await;
    assert!(shell::shell_session(&mut tx, &[0xa1; 16]).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn ws_ticket_consumes_once_and_never_after_expiry(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    tech_with_cred(&pool, "alice", 1).await;
    insert_session(&pool, session(&a, "alice", 1, 0xa1)).await;
    let scope = Scope::Clients(vec![a.client]);

    let mut tx = api(&pool, scope.clone()).await;
    shell::insert_ws_ticket(&mut tx, &[1; 32], a.client, &[0xa1; 16], 60)
        .await
        .unwrap();
    shell::insert_ws_ticket(&mut tx, &[2; 32], a.client, &[0xa1; 16], 60)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = api(&pool, scope.clone()).await;
    let first = shell::consume_ws_ticket(&mut tx, &[1; 32]).await.unwrap();
    assert_eq!(first, Some((vec![0xa1; 16], a.client)));
    assert!(
        shell::consume_ws_ticket(&mut tx, &[1; 32])
            .await
            .unwrap()
            .is_none(),
        "second use fails"
    );
    assert!(
        shell::consume_ws_ticket(&mut tx, &[9; 32])
            .await
            .unwrap()
            .is_none(),
        "unknown ticket"
    );
    tx.commit().await.unwrap();

    // Expire ticket 2 (as the owner) before its first use.
    sqlx::query("update tenant.shell_ws_ticket set expires_at = now() - interval '1 second' where ticket_hash = $1")
        .bind(&[2u8; 32][..])
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = api(&pool, scope).await;
    assert!(
        shell::consume_ws_ticket(&mut tx, &[2; 32])
            .await
            .unwrap()
            .is_none(),
        "expired ticket never consumes"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn challenge_consumes_once_for_its_owner_only(pool: PgPool) {
    let mut tx = api(&pool, Scope::Clients(vec![])).await;
    shell::upsert_technician(&mut tx, "alice", "Alice")
        .await
        .unwrap();
    shell::upsert_technician(&mut tx, "bob", "Bob")
        .await
        .unwrap();
    let id = shell::insert_challenge(&mut tx, "alice", &[7; 32], "register", 300)
        .await
        .unwrap();
    let old = shell::insert_challenge(&mut tx, "alice", &[8; 32], "register", 300)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = api(&pool, Scope::Clients(vec![])).await;
    assert!(
        shell::consume_challenge(&mut tx, id, "bob", "register")
            .await
            .unwrap()
            .is_none(),
        "another technician cannot use it"
    );
    assert_eq!(
        shell::consume_challenge(&mut tx, id, "alice", "register")
            .await
            .unwrap(),
        Some(vec![7; 32])
    );
    assert!(
        shell::consume_challenge(&mut tx, id, "alice", "register")
            .await
            .unwrap()
            .is_none(),
        "second use fails"
    );
    tx.commit().await.unwrap();

    // Six minutes later the 5-minute challenge is dead.
    sqlx::query("update msp.webauthn_challenge set created_at = created_at - interval '6 minutes', expires_at = expires_at - interval '6 minutes' where id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = api(&pool, Scope::Clients(vec![])).await;
    assert!(
        shell::consume_challenge(&mut tx, old, "alice", "register")
            .await
            .unwrap()
            .is_none(),
        "expired challenge never consumes"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn credential_ids_are_unique_across_technicians(pool: PgPool) {
    tech_with_cred(&pool, "alice", 1).await;
    let mut tx = api(&pool, Scope::Clients(vec![])).await;
    shell::upsert_technician(&mut tx, "bob", "Bob")
        .await
        .unwrap();
    assert!(
        !shell::insert_credential(&mut tx, cred("bob", 1))
            .await
            .unwrap(),
        "bob cannot take alice's credential id"
    );
    assert!(
        shell::insert_credential(&mut tx, cred("bob", 2))
            .await
            .unwrap()
    );
    let alice = shell::list_credentials(&mut tx, "alice").await.unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].tech_id, "alice");
    assert!(shell::revoke_credential(&mut tx, &[2; 16]).await.unwrap());
    assert!(
        shell::list_credentials(&mut tx, "bob")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        shell::credential(&mut tx, &[2; 16])
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    // Only technicians with live credentials appear in the techlist.
    let entries = shell::techlist_entries(&mut tx).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tech_id, "alice");
}

#[sqlx::test(migrations = "./migrations")]
async fn status_transitions_and_retention(pool: PgPool) {
    let a = seed(&pool, "A", 1).await;
    tech_with_cred(&pool, "alice", 1).await;
    insert_session(&pool, session(&a, "alice", 1, 0x01)).await;
    insert_session(&pool, session(&a, "alice", 1, 0x02)).await;
    let mut tx = api(&pool, Scope::Clients(vec![])).await;
    assert!(
        shell::add_technician_client(&mut tx, "alice", a.client)
            .await
            .unwrap()
    );
    let entries = shell::techlist_entries(&mut tx).await.unwrap();
    assert_eq!(entries[0].client_ids, vec![a.client]);
    tx.commit().await.unwrap();

    let scope = Scope::Clients(vec![a.client]);
    let mut tx = api(&pool, scope.clone()).await;
    assert!(
        shell::update_shell_status(&mut tx, &[1; 16], &["pending"], "open", None)
            .await
            .unwrap()
    );
    assert!(
        !shell::update_shell_status(&mut tx, &[1; 16], &["pending"], "open", None)
            .await
            .unwrap(),
        "transition only from the listed states"
    );
    assert!(
        shell::update_shell_status(&mut tx, &[1; 16], &["open"], "closed", Some("exit"))
            .await
            .unwrap()
    );
    assert!(
        shell::set_recording(&mut tx, &[1; 16], "/rec/a/01.cast", &[3; 32], 42)
            .await
            .unwrap()
    );
    shell::insert_ws_ticket(&mut tx, &[5; 32], a.client, &[1; 16], 60)
        .await
        .unwrap();
    let row = shell::shell_session(&mut tx, &[1; 16])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "closed");
    assert!(row.opened_at.is_some() && row.closed_at.is_some());
    assert_eq!(row.close_reason.as_deref(), Some("exit"));
    assert_eq!(row.recording_bytes, Some(42));
    tx.commit().await.unwrap();

    // Age session 1 past retention.
    sqlx::query("update tenant.shell_session set created_at = now() - interval '400 days' where grant_id = $1")
        .bind(&[1u8; 16][..])
        .execute(&pool)
        .await
        .unwrap();

    let cutoff = Utc::now() - std::time::Duration::from_secs(365 * 86_400);
    let mut tx = api(&pool, scope.clone()).await;
    let old = shell::recordings_older_than(&mut tx, cutoff, 100)
        .await
        .unwrap();
    assert_eq!(old.len(), 1, "only the old session");
    assert_eq!(old[0].grant_id, vec![1; 16]);
    assert_eq!(old[0].recording_path.as_deref(), Some("/rec/a/01.cast"));
    assert!(
        shell::delete_shell_session(&mut tx, &[1; 16])
            .await
            .unwrap()
    );
    assert!(
        shell::recordings_older_than(&mut tx, cutoff, 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        shell::consume_ws_ticket(&mut tx, &[5; 32])
            .await
            .unwrap()
            .is_none(),
        "tickets go with their session"
    );
    assert!(
        shell::shell_session(&mut tx, &[2; 16])
            .await
            .unwrap()
            .is_some()
    );
}
