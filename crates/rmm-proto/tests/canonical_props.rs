//! Property tests for the canonical CBOR codec.
#![allow(clippy::unwrap_used)]

use ciborium::Value;
use proptest::prelude::*;
use rmm_proto::canonical::{CanonicalError, check_canonical, encode_value, from_canonical_slice};

fn config() -> ProptestConfig {
    ProptestConfig::with_cases(512)
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(|n| Value::Integer(n.into())),
        any::<u64>().prop_map(|n| Value::Integer(n.into())),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        ".{0,20}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::vec((inner.clone(), inner), 0..6).prop_map(Value::Map),
        ]
    })
}

proptest! {
    #![proptest_config(config())]

    // (a) random bytes never panic.
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = check_canonical(&bytes);
        let _ = from_canonical_slice::<Value>(&bytes);
        let _ = from_canonical_slice::<Vec<u8>>(&bytes);
    }

    // (b) any accepted input re-encodes byte-identically. Biased towards
    // inputs that start like real structures so acceptance actually happens.
    #[test]
    fn accepted_inputs_reencode_identically(
        head in prop_oneof![Just(0x80u8), Just(0xa0), Just(0x40), Just(0x60), Just(0x81), Just(0xa1), Just(0x82), Just(0x00)],
        tail in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let mut bytes = vec![head];
        bytes.extend(tail);
        if let Ok(v) = check_canonical(&bytes) {
            prop_assert_eq!(encode_value(&v).unwrap(), bytes);
        }
    }

    // (c) generated trees round-trip.
    #[test]
    fn value_trees_round_trip(v in arb_value()) {
        match encode_value(&v) {
            Ok(bytes) => {
                let parsed = check_canonical(&bytes).unwrap();
                prop_assert_eq!(encode_value(&parsed).unwrap(), bytes);
            }
            Err(e) => prop_assert_eq!(e, CanonicalError::DuplicateKey),
        }
    }

    // (d1) a non-shortest top-level head is rejected.
    #[test]
    fn non_shortest_head_rejected(v in arb_value()) {
        if let Ok(bytes) = encode_value(&v) {
            let b0 = bytes[0];
            prop_assume!(b0 >> 5 != 7 && (b0 & 0x1f) < 24);
            let mut bad = vec![(b0 & 0xe0) | 24, b0 & 0x1f];
            bad.extend_from_slice(&bytes[1..]);
            prop_assert_eq!(check_canonical(&bad), Err(CanonicalError::NonCanonical));
        }
    }

    // (d2) swapping two map entries of a valid encoding is rejected.
    #[test]
    fn swapped_map_keys_rejected(keys in proptest::collection::btree_set(0u16..1000, 2..8)) {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = keys
            .iter()
            .map(|k| {
                (
                    encode_value(&Value::Integer((*k).into())).unwrap(),
                    encode_value(&Value::Null).unwrap(),
                )
            })
            .collect();
        let build = |order: &[usize]| {
            let mut out = vec![0xa0 | entries.len() as u8];
            for i in order {
                out.extend_from_slice(&entries[*i].0);
                out.extend_from_slice(&entries[*i].1);
            }
            out
        };
        let mut order: Vec<usize> = (0..entries.len()).collect();
        prop_assert!(check_canonical(&build(&order)).is_ok());
        order.swap(0, 1);
        prop_assert_eq!(check_canonical(&build(&order)), Err(CanonicalError::NonCanonical));
    }
}
