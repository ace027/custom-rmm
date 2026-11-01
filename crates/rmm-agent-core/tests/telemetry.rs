use std::time::Duration;

use ciborium::Value;
use rmm_agent_core::identity::Identity;
use rmm_agent_core::telemetry::{
    Intervals, build_batch, build_heartbeat, build_inventory, jitter, jitter_with, subject,
};
use rmm_proto::telemetry::{self, KIND_HEARTBEAT, KIND_INVENTORY, KIND_METRIC};
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
