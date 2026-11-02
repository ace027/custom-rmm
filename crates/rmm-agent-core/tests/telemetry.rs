use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciborium::Value;
use rmm_agent_core::identity::Identity;
use rmm_agent_core::store::{OutboxItem, STORE_KEY_FILE, Store};
use rmm_agent_core::telemetry::{
    CancellationToken, DrainOutcome, Intervals, Sink, build_batch, build_heartbeat,
    build_inventory, drain_loop, drain_once, jitter, jitter_with, subject,
};
use rmm_proto::telemetry::{self, KIND_HEARTBEAT, KIND_INVENTORY, KIND_METRIC};
use tokio::sync::Notify;
use uuid::Uuid;

fn ident() -> Identity {
    Identity {
        agent_id: Uuid::from_u128(1),
        device_id: Uuid::from_u128(2),
        client_id: Uuid::from_u128(3),
        nats_url: "wss://x".into(),
        server_url: "https://x".into(),
    }
}

#[test]
fn subjects_per_kind() {
    let i = ident();
    let base = format!("telemetry.{}.{}", i.client_id, i.agent_id);
    assert_eq!(subject(&i, KIND_HEARTBEAT), format!("{base}.hb"));
    assert_eq!(subject(&i, KIND_INVENTORY), format!("{base}.inv"));
    assert_eq!(subject(&i, KIND_METRIC), format!("{base}.metric"));
}

#[test]
fn jitter_within_ten_percent() {
    let base = Duration::from_secs(100);
    for u in [0.0, 0.25, 0.5, 1.0, f64::NAN] {
        let d = jitter_with(base, u);
        assert!(
            d >= Duration::from_secs(90) && d <= Duration::from_secs(110),
            "{u}: {d:?}"
        );
    }
    for _ in 0..1000 {
        let d = jitter(base);
        assert!(
            d >= Duration::from_secs(90) && d <= Duration::from_secs(110),
            "{d:?}"
        );
    }
}

#[test]
fn interval_parsing() {
    let d = Intervals::default();
    assert_eq!(d.hb, Duration::from_secs(30));
    assert_eq!(d.metric, Duration::from_secs(60));
    assert_eq!(d.inv, Duration::from_secs(6 * 3600));
    assert_eq!(d.inv_check(), Duration::from_secs(300));

    let p = Intervals::parse("hb=2,metric=0.05,inv=5");
    assert_eq!(p.hb, Duration::from_secs(2));
    assert_eq!(p.metric, Duration::from_millis(50));
    assert_eq!(p.inv, Duration::from_secs(5));
    assert_eq!(p.inv_check(), Duration::from_secs(5));

    // clamped to at least 10 ms
    assert_eq!(Intervals::parse("hb=0").hb, Duration::from_millis(10));
    assert_eq!(Intervals::parse("hb=-3").hb, Duration::from_millis(10));
}

#[test]
fn malformed_intervals_fall_back() {
    for s in [
        "",
        "garbage",
        "hb=abc",
        "hb=nan,metric=inf",
        "hb=,metric",
        "x=1",
    ] {
        assert_eq!(Intervals::parse(s), Intervals::default(), "{s}");
    }
    let p = Intervals::parse("hb=abc,metric=3");
    assert_eq!(p.hb, Duration::from_secs(30));
    assert_eq!(p.metric, Duration::from_secs(3));
}

#[test]
fn non_finite_samples_dropped() {
    let b = build_batch(vec![
        ("a".into(), 1.0),
        ("b".into(), f64::NAN),
        ("c".into(), f64::INFINITY),
        ("d".into(), f64::NEG_INFINITY),
    ])
    .expect("batch");
    assert_eq!(b.samples.len(), 1);
    assert_eq!(b.samples[0].metric, "a");
    assert!(build_batch(vec![("x".into(), f64::NAN)]).is_none());
    assert!(build_batch(vec![]).is_none());
}

fn keys(bytes: &[u8]) -> Vec<String> {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor");
    match v {
        Value::Map(m) => m
            .into_iter()
            .map(|(k, _)| k.into_text().expect("text key"))
            .collect(),
        _ => panic!("not a map"),
    }
}

#[test]
fn payloads_carry_no_identity() {
    let hb = telemetry::encode(&build_heartbeat(5)).expect("hb");
    let inv = telemetry::encode(&build_inventory(rmm_platform::collect::inventory())).expect("inv");
    let m = telemetry::encode(&build_batch(vec![("a".into(), 1.0)]).expect("batch")).expect("m");
    for bytes in [hb, inv, m] {
        for k in keys(&bytes) {
            assert!(
                !k.contains("client") && !k.contains("agent_id") && k != "device_id",
                "{k}"
            );
        }
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmm-telemetry-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open_store(dir: &Path) -> Arc<Store> {
    let key = rmm_platform::keystore_named(dir, STORE_KEY_FILE);
    Arc::new(Store::open(dir, key.as_ref()).expect("open store"))
}

fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

/// A sink whose first `fail_first` publish attempts (counted per item) fail.
/// `ack_but_fail` makes the first attempt of every item reach the server
/// (recorded in `delivered`) while reporting failure, like a lost ack.
#[derive(Default)]
struct FakeSink {
    attempts: Mutex<Vec<[u8; 16]>>,
    delivered: Mutex<Vec<[u8; 16]>>,
    fail_batches: Mutex<u32>,
    ack_but_fail: bool,
}

struct Handle(Arc<FakeSink>);

impl Sink for Handle {
    async fn publish_batch(&self, items: &[OutboxItem]) -> Vec<bool> {
        {
            let mut left = self.0.fail_batches.lock().expect("lock");
            if *left > 0 {
                *left -= 1;
                return vec![false; items.len()];
            }
        }
        let mut attempts = self.0.attempts.lock().expect("lock");
        let mut delivered = self.0.delivered.lock().expect("lock");
        items
            .iter()
            .map(|it| {
                let first = !attempts.contains(&it.msg_id);
                attempts.push(it.msg_id);
                delivered.push(it.msg_id);
                !(self.0.ack_but_fail && first)
            })
            .collect()
    }
}

fn queue(store: &Store) {
    // pushed out of priority order on purpose
    store
        .outbox_push(id(1), "s.metric", 2, b"m1")
        .expect("push");
    store.outbox_push(id(2), "s.inv", 1, b"i1").expect("push");
    store
        .outbox_push(id(3), "s.metric", 2, b"m2")
        .expect("push");
    store.outbox_push(id(4), "s.inv", 1, b"i2").expect("push");
}

#[tokio::test]
async fn a_sink_that_fails_then_acks_sends_every_row_once_in_order() {
    let dir = TempDir::new();
    let store = open_store(dir.path());
    queue(&store);
    let sink = Arc::new(FakeSink {
        fail_batches: Mutex::new(2),
        ..FakeSink::default()
    });

    let wake = Arc::new(Notify::new());
    let reconnect = Arc::new(Notify::new());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(drain_loop(
        Arc::clone(&store),
        Handle(Arc::clone(&sink)),
        wake,
        reconnect,
        shutdown.clone(),
        (Duration::from_millis(5), Duration::from_millis(20)),
    ));
    for _ in 0..200 {
        if store.outbox_len().expect("len") == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    shutdown.cancel();
    task.await.expect("drain task");

    assert_eq!(store.outbox_len().expect("len"), 0);
    // inventory first (seq order within a priority), then metrics
    assert_eq!(
        *sink.delivered.lock().expect("lock"),
        vec![id(2), id(4), id(1), id(3)]
    );
}

#[tokio::test]
async fn a_failed_step_keeps_all_rows_queued() {
    let dir = TempDir::new();
    let store = open_store(dir.path());
    queue(&store);
    let sink = Arc::new(FakeSink {
        fail_batches: Mutex::new(1),
        ..FakeSink::default()
    });
    let out = drain_once(&store, &Handle(Arc::clone(&sink)))
        .await
        .expect("drain");
    assert_eq!(
        out,
        DrainOutcome {
            sent: 0,
            failed: 4,
            empty: false
        }
    );
    assert_eq!(store.outbox_len().expect("len"), 4);
    let out = drain_once(&store, &Handle(Arc::clone(&sink)))
        .await
        .expect("drain");
    assert_eq!((out.sent, out.failed), (4, 0));
    assert!(
        drain_once(&store, &Handle(Arc::clone(&sink)))
            .await
            .expect("drain")
            .empty
    );
}

#[tokio::test]
async fn an_ack_reported_as_failed_is_resent_with_the_same_msg_id() {
    let dir = TempDir::new();
    let store = open_store(dir.path());
    store.outbox_push(id(7), "s.metric", 2, b"m").expect("push");
    let sink = Arc::new(FakeSink {
        ack_but_fail: true,
        ..FakeSink::default()
    });

    let first = drain_once(&store, &Handle(Arc::clone(&sink)))
        .await
        .expect("drain");
    assert_eq!((first.sent, first.failed), (0, 1));
    assert_eq!(store.outbox_len().expect("len"), 1);
    let second = drain_once(&store, &Handle(Arc::clone(&sink)))
        .await
        .expect("drain");
    assert_eq!((second.sent, second.failed), (1, 0));
    assert_eq!(store.outbox_len().expect("len"), 0);
    // the server saw the same id twice: it dedupes on msg_id
    assert_eq!(*sink.delivered.lock().expect("lock"), vec![id(7), id(7)]);
}

#[tokio::test]
async fn queued_rows_survive_a_restart_and_drain_afterwards() {
    let dir = TempDir::new();
    {
        let store = open_store(dir.path());
        queue(&store);
    }
    let store = open_store(dir.path());
    assert_eq!(store.outbox_len().expect("len"), 4);
    let sink = Arc::new(FakeSink::default());
    let out = drain_once(&store, &Handle(Arc::clone(&sink)))
        .await
        .expect("drain");
    assert_eq!((out.sent, out.failed), (4, 0));
    assert_eq!(store.outbox_len().expect("len"), 0);
}

#[tokio::test]
async fn reconnect_cuts_the_backoff_short() {
    let dir = TempDir::new();
    let store = open_store(dir.path());
    queue(&store);
    let sink = Arc::new(FakeSink {
        fail_batches: Mutex::new(1),
        ..FakeSink::default()
    });
    let reconnect = Arc::new(Notify::new());
    let shutdown = CancellationToken::new();
    // A 1 hour backoff: only the reconnect signal can make the retry happen.
    let task = tokio::spawn(drain_loop(
        Arc::clone(&store),
        Handle(Arc::clone(&sink)),
        Arc::new(Notify::new()),
        Arc::clone(&reconnect),
        shutdown.clone(),
        (Duration::from_secs(3600), Duration::from_secs(3600)),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(store.outbox_len().expect("len"), 4);
    reconnect.notify_one();
    for _ in 0..200 {
        if store.outbox_len().expect("len") == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    shutdown.cancel();
    task.await.expect("drain task");
    assert_eq!(store.outbox_len().expect("len"), 0);
}
