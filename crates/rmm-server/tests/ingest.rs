//! Ingest: subject parsing, payload handling, identity enforcement and the
//! database writes of each telemetry kind.
//!
//! The package has no library target and no direct sqlx dependency, so the
//! module is compiled in directly and the database tests run against the
//! database named by `DATABASE_URL` (unique client per test; skipped when it
//! is unset), like the authd decision tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "../src/ingest.rs"]
mod ingest;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use rmm_db::DbError;
use rmm_db::repo::{self, NewAgent, NewDevice, Tx};
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::telemetry::{self, AgentTelemetryRow};
use rmm_proto::telemetry::{
    Heartbeat, Inventory, MetricBatch, SCHEMA_VERSION, Sample, Volume, encode,
};
use uuid::Uuid;

use ingest::{BatchOutcome, Db, Health, Incoming, Kind, Processor, Stats, parse_subject};

fn block<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn subject(client: Uuid, agent: Uuid, kind: &str) -> String {
    format!("telemetry.{client}.{agent}.{kind}")
}

// --- subject parsing ------------------------------------------------------

#[test]
fn parses_a_valid_subject() {
    let (c, a) = (Uuid::from_u128(1), Uuid::from_u128(2));
    assert_eq!(parse_subject(&subject(c, a, "hb")), Some((c, a, Kind::Hb)));
    assert_eq!(
        parse_subject(&subject(c, a, "inv")),
        Some((c, a, Kind::Inv))
    );
    assert_eq!(
        parse_subject(&subject(c, a, "metric")),
        Some((c, a, Kind::Metric))
    );
}

#[test]
fn rejects_a_wrong_prefix() {
    let (c, a) = (Uuid::from_u128(1), Uuid::from_u128(2));
    assert_eq!(parse_subject(&format!("telemetrics.{c}.{a}.hb")), None);
    assert_eq!(parse_subject(&format!("shell.{c}.{a}.hb")), None);
    assert_eq!(parse_subject(&format!("{c}.{a}.hb.x")), None);
}

#[test]
fn rejects_three_or_five_tokens() {
    let (c, a) = (Uuid::from_u128(1), Uuid::from_u128(2));
    assert_eq!(parse_subject(&format!("telemetry.{c}.{a}")), None);
    assert_eq!(parse_subject(&format!("telemetry.{c}.hb")), None);
    assert_eq!(parse_subject(&format!("telemetry.{c}.{a}.hb.extra")), None);
    assert_eq!(parse_subject("telemetry"), None);
    assert_eq!(parse_subject(""), None);
}

#[test]
fn rejects_bad_uuids() {
    let ok = Uuid::from_u128(1);
    assert_eq!(parse_subject(&format!("telemetry.nope.{ok}.hb")), None);
    assert_eq!(parse_subject(&format!("telemetry.{ok}.nope.hb")), None);
    assert_eq!(parse_subject(&format!("telemetry.{ok}.*.hb")), None);
    assert_eq!(parse_subject(&format!("telemetry.{ok}.>.hb")), None);
    let simple = ok.simple();
    assert_eq!(parse_subject(&format!("telemetry.{simple}.{ok}.hb")), None);
}

#[test]
fn rejects_unknown_kinds() {
    let (c, a) = (Uuid::from_u128(1), Uuid::from_u128(2));
    for kind in ["cpu", "HB", "heartbeat", "", "metrics"] {
        assert_eq!(parse_subject(&subject(c, a, kind)), None, "{kind:?}");
    }
}

// --- pure processing ------------------------------------------------------

fn inventory(ram: u64) -> Inventory {
    Inventory {
        v: SCHEMA_VERSION,
        msg_id: Uuid::now_v7(),
        sent_at: now_ms(),
        os_family: "linux".into(),
        os_version: "Debian 13".into(),
        hostname: "host-1".into(),
        cpu_model: Some("Test CPU".into()),
        cpu_cores: Some(4),
        ram_bytes: Some(ram),
        volumes: vec![
            Volume {
                mount: "/".into(),
                total_bytes: 100,
                free_bytes: 40,
            },
            Volume {
                mount: "/data".into(),
                total_bytes: 200,
                free_bytes: 50,
            },
        ],
        last_boot: Some(1_700_000_000),
    }
}

fn heartbeat() -> Heartbeat {
    Heartbeat {
        v: SCHEMA_VERSION,
        msg_id: Uuid::now_v7(),
        sent_at: now_ms(),
        agent_version: "0.1.0".into(),
        uptime_s: 12,
    }
}

fn metric_batch(samples: Vec<Sample>) -> MetricBatch {
    MetricBatch {
        v: SCHEMA_VERSION,
        msg_id: Uuid::now_v7(),
        sent_at: now_ms(),
        samples,
    }
}

fn sample(t: i64, metric: &str, value: f64) -> Sample {
    Sample {
        t,
        metric: metric.into(),
        value,
    }
}

/// A database that fails every transaction.
fn broken_db() -> Db {
    Db::new(
        Box::new(|| Box::pin(async { Err(DbError::InvalidRole("down".into())) })),
        Box::new(|| Box::pin(async { Err(DbError::InvalidRole("down".into())) })),
    )
}

fn broken_processor() -> Processor {
    Processor::new(broken_db(), Arc::new(Health::default()))
}

#[test]
fn bad_subjects_are_termed_without_the_database() {
    let p = broken_processor();
    let payload = encode(&heartbeat()).unwrap();
    let c = Uuid::from_u128(1);
    let a = Uuid::from_u128(2);
    let long = format!("telemetry.{c}.{a}.hb.extra");
    let msgs = [
        Incoming {
            subject: "telemetry.x.y.hb",
            payload: &payload,
        },
        Incoming {
            subject: &long,
            payload: &payload,
        },
    ];
    let out = block(p.process_batch(&msgs));
    assert_eq!(
        out,
        BatchOutcome {
            acked: vec![],
            termed: vec![0, 1],
            naked: vec![]
        }
    );
    assert_eq!(Stats::get(&p.stats.bad_subject), 2);
}

#[test]
fn payload_with_an_extra_client_id_is_termed() {
    // A valid heartbeat (a 5-entry CBOR map) with a sixth entry appended:
    // "client_id": "c". The package has no serde dependency to derive one.
    let mut forged = encode(&heartbeat()).unwrap();
    assert_eq!(forged[0], 0xA5, "heartbeat is a definite 5-entry map");
    forged[0] = 0xA6;
    forged.push(0x69);
    forged.extend_from_slice(b"client_id");
    forged.extend_from_slice(&[0x61, b'c']);
    let p = broken_processor();
    let s = subject(Uuid::from_u128(1), Uuid::from_u128(2), "hb");
    let msgs = [
        Incoming {
            subject: &s,
            payload: &forged,
        },
        Incoming {
            subject: &s,
            payload: b"not cbor at all",
        },
    ];
    let out = block(p.process_batch(&msgs));
    assert_eq!(out.termed, vec![0, 1]);
    assert!(out.acked.is_empty() && out.naked.is_empty());
    assert_eq!(Stats::get(&p.stats.malformed), 2);
}

#[test]
fn database_down_naks_and_turns_health_unhealthy() {
    let p = broken_processor();
    let payload = encode(&heartbeat()).unwrap();
    let s = subject(Uuid::from_u128(1), Uuid::from_u128(2), "hb");
    let msgs = [Incoming {
        subject: &s,
        payload: &payload,
    }];
    let out = block(p.process_batch(&msgs));
    assert_eq!(out.naked, vec![0]);
    assert!(out.acked.is_empty() && out.termed.is_empty());
    assert_eq!(Stats::get(&p.stats.db_errors), 1);
    assert!(!p.health.healthy(u64::MAX / 2));
}

#[test]
fn health_needs_nats_consumer_and_a_recent_database() {
    let h = Health::default();
    assert!(!h.healthy(1000));
    let set = |nats: bool, consumer: bool, db: u64| {
        h.nats_up.store(nats, Ordering::Relaxed);
        h.consumer_ok.store(consumer, Ordering::Relaxed);
        h.db_ok_at.store(db, Ordering::Relaxed);
    };
    set(true, true, 1000);
    assert!(h.healthy(1010));
    assert!(!h.healthy(1031), "database contact too old");
    set(false, true, 1000);
    assert!(!h.healthy(1010), "nats down");
    set(true, false, 1000);
    assert!(!h.healthy(1010), "no consumer");
    set(true, true, 0);
    assert!(!h.healthy(1010), "database never reached");
}

#[test]
fn metric_rows_take_ids_from_the_agent_and_drop_bad_samples() {
    let agent = AgentTelemetryRow {
        agent_id: Uuid::from_u128(10),
        client_id: Uuid::from_u128(20),
        device_id: Uuid::from_u128(30),
        status: "active".into(),
    };
    let now = now_ms();
    let day = 24 * 3600 * 1000;
    let batch = metric_batch(vec![
        sample(now - 1000, "cpu.usage_pct", 12.5),
        sample(now - 8 * day, "cpu.usage_pct", 1.0),
        sample(now + 10 * 60 * 1000, "cpu.usage_pct", 2.0),
        sample(now, "cpu.usage_pct", f64::NAN),
        sample(now, "", 3.0),
        sample(now + 60 * 1000, "uptime_s", 99.0),
    ]);
    let (rows, dropped) = ingest::metric_rows(&agent, &batch, now);
    assert_eq!(dropped, 4);
    assert_eq!(rows.len(), 2);
    for r in &rows {
        assert_eq!(r.client_id, agent.client_id);
        assert_eq!(r.device_id, agent.device_id);
    }
    assert_eq!(rows[0].metric, "cpu.usage_pct");
    assert!((rows[0].value - 12.5).abs() < f64::EPSILON);
    assert_eq!(rows[1].metric, "uptime_s");
}

#[test]
fn inventory_update_sums_volumes_and_keeps_the_document() {
    let inv = inventory(8 << 30);
    let u = ingest::inventory_update(&inv, now_ms());
    assert_eq!(u.disk_total_bytes, Some(300));
    assert_eq!(u.disk_free_bytes, Some(90));
    assert_eq!(u.ram_bytes, Some(8 << 30));
    assert_eq!(u.cpu_cores, Some(4));
    assert_eq!(u.os_version.as_deref(), Some("Debian 13"));
    assert_eq!(u.inventory_hash, inv.hash());
    assert!(u.last_boot.is_some());
    let doc = u.inventory.as_object().unwrap();
    assert!(!doc.contains_key("msg_id") && !doc.contains_key("sent_at"));
    assert_eq!(doc["hostname"], "host-1");
    assert_eq!(doc["volumes"].as_array().unwrap().len(), 2);
}

// --- database-backed ------------------------------------------------------

fn database_url() -> Option<String> {
    let url = std::env::var("DATABASE_URL").ok();
    if url.is_none() {
        eprintln!("DATABASE_URL not set; skipping database test");
    }
    url
}

/// A service-scoped transaction as the owner (seeding and read-back).
async fn admin_tx(url: &str) -> Tx<'static> {
    let pool = rmm_db::connect(url).await.unwrap();
    rmm_db::migrate(&pool).await.unwrap();
    begin_scoped(&pool, &Scope::Service("ingest-test"), "test")
        .await
        .unwrap()
}

struct Seeded {
    client: Uuid,
    device: Uuid,
    agent: Uuid,
}

fn pubkey() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    k[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    k
}

async fn seed(url: &str) -> Seeded {
    let mut tx = admin_tx(url).await;
    let client = repo::create_client(&mut tx, &format!("ingest-{}", Uuid::new_v4()))
        .await
        .unwrap();
    let site = repo::create_site(&mut tx, client, "main", "UTC")
        .await
        .unwrap();
    let device = repo::insert_device(
        &mut tx,
        NewDevice {
            client_id: client,
            site_id: site,
            hw_fingerprint: Uuid::new_v4().as_bytes().to_vec(),
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
            credential_pubkey: pubkey(),
            nkey: format!("U{}", Uuid::new_v4().simple()),
            version: "0.1.0".into(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Seeded {
        client,
        device,
        agent,
    }
}

async fn processor(url: &str) -> Processor {
    let db = Db::connect(url).await.unwrap();
    Processor::new(db, Arc::new(Health::default()))
}

async fn events(url: &str, device: Uuid) -> Vec<telemetry::DeviceEventRow> {
    let mut tx = admin_tx(url).await;
    let ev = telemetry::device_events(&mut tx, device, 50).await.unwrap();
    tx.commit().await.unwrap();
    ev
}

async fn send(p: &Processor, subject: &str, payload: &[u8]) -> BatchOutcome {
    p.process_batch(&[Incoming { subject, payload }]).await
}

fn acked() -> BatchOutcome {
    BatchOutcome {
        acked: vec![0],
        termed: vec![],
        naked: vec![],
    }
}

fn termed() -> BatchOutcome {
    BatchOutcome {
        acked: vec![],
        termed: vec![0],
        naked: vec![],
    }
}

#[test]
fn heartbeat_from_an_active_agent_is_acked() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let out = send(
            &p,
            &subject(s.client, s.agent, "hb"),
            &encode(&heartbeat()).unwrap(),
        )
        .await;
        assert_eq!(out, acked());
        assert_eq!(Stats::get(&p.stats.heartbeats), 1);
        assert_ne!(p.health.db_ok_at.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn first_inventory_writes_the_columns_and_one_event() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let out = send(
            &p,
            &subject(s.client, s.agent, "inv"),
            &encode(&inventory(8 << 30)).unwrap(),
        )
        .await;
        assert_eq!(out, acked());
        assert_eq!(Stats::get(&p.stats.inventory_changed), 1);
        let ev = events(&url, s.device).await;
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].r#type, "inventory.changed");
        assert_eq!(ev[0].client_id, s.client);
        let after = ev[0].after.as_ref().unwrap().as_object().unwrap();
        for k in [
            "os_version",
            "cpu_model",
            "cpu_cores",
            "ram_bytes",
            "disk_total_bytes",
            "last_boot",
        ] {
            assert!(after.contains_key(k), "after lacks {k}");
        }
        // Free space is volatile: stored on the device, never diffed into an event.
        assert!(!after.contains_key("disk_free_bytes"));
        assert_eq!(after["ram_bytes"], 8i64 << 30);
        assert_eq!(after["disk_total_bytes"], 300);
    });
}

#[test]
fn the_same_inventory_twice_writes_one_event() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let subj = subject(s.client, s.agent, "inv");
        // Same facts, new message ids and send times.
        assert_eq!(
            send(&p, &subj, &encode(&inventory(8 << 30)).unwrap()).await,
            acked()
        );
        assert_eq!(
            send(&p, &subj, &encode(&inventory(8 << 30)).unwrap()).await,
            acked()
        );
        assert_eq!(Stats::get(&p.stats.inventory_changed), 1);
        assert_eq!(Stats::get(&p.stats.inventory_unchanged), 1);
        assert_eq!(events(&url, s.device).await.len(), 1);
    });
}

#[test]
fn a_ram_change_writes_an_event_with_exactly_ram_bytes() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let subj = subject(s.client, s.agent, "inv");
        send(&p, &subj, &encode(&inventory(8 << 30)).unwrap()).await;
        let out = send(&p, &subj, &encode(&inventory(16 << 30)).unwrap()).await;
        assert_eq!(out, acked());
        let ev = events(&url, s.device).await;
        assert_eq!(ev.len(), 2);
        let (before, after) = (
            ev[0].before.as_ref().unwrap().as_object().unwrap(),
            ev[0].after.as_ref().unwrap().as_object().unwrap(),
        );
        assert_eq!(before.keys().collect::<Vec<_>>(), ["ram_bytes"]);
        assert_eq!(after.keys().collect::<Vec<_>>(), ["ram_bytes"]);
        assert_eq!(before["ram_bytes"], 8i64 << 30);
        assert_eq!(after["ram_bytes"], 16i64 << 30);
    });
}

#[test]
fn metrics_land_under_the_agents_client_and_device() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let now = now_ms();
        let batch = metric_batch(vec![
            sample(now - 2000, "cpu.usage_pct", 10.0),
            sample(now - 1000, "cpu.usage_pct", 20.0),
            sample(now, "mem.used_bytes", 1.0e9),
            sample(now - 9 * 24 * 3600 * 1000, "cpu.usage_pct", 5.0),
            sample(now + 3_600_000, "cpu.usage_pct", 5.0),
        ]);
        let out = send(
            &p,
            &subject(s.client, s.agent, "metric"),
            &encode(&batch).unwrap(),
        )
        .await;
        assert_eq!(out, acked());
        assert_eq!(Stats::get(&p.stats.metric_rows), 3);
        assert_eq!(Stats::get(&p.stats.samples_dropped), 2);
    });
}

#[test]
fn the_same_metric_batch_twice_writes_its_rows_once() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let now = now_ms();
        let batch = metric_batch(vec![
            sample(now - 2000, "cpu.usage_pct", 10.0),
            sample(now - 1000, "cpu.usage_pct", 20.0),
        ]);
        let payload = encode(&batch).unwrap();
        let subj = subject(s.client, s.agent, "metric");
        assert_eq!(send(&p, &subj, &payload).await, acked());
        assert_eq!(send(&p, &subj, &payload).await, acked());
        assert_eq!(Stats::get(&p.stats.metric_rows), 2);
        assert_eq!(Stats::get(&p.stats.duplicates), 1);

        // The same id twice inside one batch is also written once.
        let batch2 = metric_batch(vec![sample(now, "cpu.usage_pct", 30.0)]);
        let payload2 = encode(&batch2).unwrap();
        let out = p
            .process_batch(&[
                Incoming {
                    subject: &subj,
                    payload: &payload2,
                },
                Incoming {
                    subject: &subj,
                    payload: &payload2,
                },
            ])
            .await;
        assert_eq!(out.acked, vec![0, 1]);
        assert_eq!(Stats::get(&p.stats.metric_rows), 3);
        assert_eq!(Stats::get(&p.stats.duplicates), 2);
    });
}

#[test]
fn a_rejected_message_does_not_claim_its_id() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let batch = metric_batch(vec![sample(now_ms(), "cpu.usage_pct", 1.0)]);
        let payload = encode(&batch).unwrap();
        // Wrong subject client: termed, and the id stays free for the real agent.
        let wrong = subject(Uuid::new_v4(), s.agent, "metric");
        assert_eq!(send(&p, &wrong, &payload).await, termed());
        let right = subject(s.client, s.agent, "metric");
        assert_eq!(send(&p, &right, &payload).await, acked());
        assert_eq!(Stats::get(&p.stats.metric_rows), 1);
        assert_eq!(Stats::get(&p.stats.duplicates), 0);
    });
}

#[test]
fn a_subject_client_that_is_not_the_agents_client_is_rejected() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let other = seed(&url).await;
        let p = processor(&url).await;
        // The agent of `s` published under another client's id.
        let subj = subject(other.client, s.agent, "inv");
        assert_eq!(
            send(&p, &subj, &encode(&inventory(8 << 30)).unwrap()).await,
            termed()
        );
        let subj = subject(other.client, s.agent, "metric");
        let batch = metric_batch(vec![sample(now_ms(), "cpu.usage_pct", 1.0)]);
        assert_eq!(send(&p, &subj, &encode(&batch).unwrap()).await, termed());
        assert_eq!(Stats::get(&p.stats.identity_mismatch), 2);
        assert_eq!(Stats::get(&p.stats.metric_rows), 0);
        assert!(events(&url, s.device).await.is_empty());
        assert!(events(&url, other.device).await.is_empty());
    });
}

#[test]
fn a_revoked_agent_is_rejected() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let mut tx = admin_tx(&url).await;
        repo::set_agent_status(&mut tx, s.agent, "revoked")
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        let p = processor(&url).await;
        let out = send(
            &p,
            &subject(s.client, s.agent, "inv"),
            &encode(&inventory(8 << 30)).unwrap(),
        )
        .await;
        assert_eq!(out, termed());
        assert_eq!(Stats::get(&p.stats.inactive_agent), 1);
        assert!(events(&url, s.device).await.is_empty());
    });
}

#[test]
fn an_unknown_agent_is_termed_and_counted() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let stranger = Uuid::new_v4();
        let out = send(
            &p,
            &subject(s.client, stranger, "hb"),
            &encode(&heartbeat()).unwrap(),
        )
        .await;
        assert_eq!(out, termed());
        assert_eq!(Stats::get(&p.stats.unknown_agent), 1);
    });
}

#[test]
fn a_mixed_batch_gets_one_verdict_per_message() {
    let Some(url) = database_url() else { return };
    block(async {
        let s = seed(&url).await;
        let p = processor(&url).await;
        let hb = encode(&heartbeat()).unwrap();
        let inv = encode(&inventory(4 << 30)).unwrap();
        let metric = encode(&metric_batch(vec![sample(now_ms(), "cpu.usage_pct", 3.0)])).unwrap();
        let (hs, is, ms) = (
            subject(s.client, s.agent, "hb"),
            subject(s.client, s.agent, "inv"),
            subject(s.client, s.agent, "metric"),
        );
        let bad = subject(s.client, Uuid::new_v4(), "hb");
        let msgs = [
            Incoming {
                subject: &hs,
                payload: &hb,
            },
            Incoming {
                subject: &is,
                payload: &inv,
            },
            Incoming {
                subject: &bad,
                payload: &hb,
            },
            Incoming {
                subject: &ms,
                payload: &metric,
            },
            Incoming {
                subject: "telemetry.bogus",
                payload: &hb,
            },
        ];
        let out = p.process_batch(&msgs).await;
        assert_eq!(
            out,
            BatchOutcome {
                acked: vec![0, 1, 3],
                termed: vec![2, 4],
                naked: vec![]
            }
        );
        assert_eq!(Stats::get(&p.stats.metric_rows), 1);
        assert_eq!(events(&url, s.device).await.len(), 1);
    });
}
