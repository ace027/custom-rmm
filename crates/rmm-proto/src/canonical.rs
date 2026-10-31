//! Deterministic CBOR (RFC 8949 section 4.2.1) with strict decoding.
//!
//! Rules: shortest-form heads, definite lengths only, map keys sorted bytewise
//! by their encoded form, no duplicate keys, no floats, no tags, no simple
//! values other than booleans and null, nesting depth at most
//! [`MAX_DEPTH`], and no trailing bytes. Decoding parses, re-encodes
//! canonically and rejects unless the result is byte-identical.

use ciborium::Value;
use serde::{Serialize, de::DeserializeOwned};

/// Maximum container nesting depth accepted by the codec.
pub const MAX_DEPTH: usize = 32;

/// Reasons a value cannot be encoded or an input is not canonical CBOR.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CanonicalError {
    /// The input is not well-formed CBOR (or uses unsupported simple values).
    #[error("malformed CBOR")]
    Malformed,
    /// The input is valid CBOR but not in canonical form.
    #[error("CBOR is not canonically encoded")]
    NonCanonical,
    /// A floating point number was present.
    #[error("floating point numbers are not allowed")]
    Float,
    /// A CBOR tag was present.
    #[error("CBOR tags are not allowed")]
    Tag,
    /// Nesting exceeds [`MAX_DEPTH`].
    #[error("nesting depth exceeded")]
    DepthExceeded,
    /// Bytes remain after the first data item.
    #[error("trailing bytes after CBOR item")]
    TrailingBytes,
    /// A map contains the same key twice.
    #[error("duplicate map key")]
    DuplicateKey,
    /// Serde (de)serialization failed.
    #[error("serde: {0}")]
    Serde(String),
}

fn put_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if let Ok(v) = u8::try_from(n) {
        out.extend_from_slice(&[m | 24, v]);
    } else if let Ok(v) = u16::try_from(n) {
        out.push(m | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(n) {
        out.push(m | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn len_u64(n: usize) -> u64 {
    // usize is at most 64 bits on every supported target.
    n as u64
}

fn encode_into(v: &Value, depth: usize, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match v {
        Value::Integer(i) => {
            let n = i128::from(*i);
            if n >= 0 {
                put_head(
                    out,
                    0,
                    u64::try_from(n).map_err(|_| CanonicalError::Malformed)?,
                );
            } else {
                put_head(
                    out,
                    1,
                    u64::try_from(-1 - n).map_err(|_| CanonicalError::Malformed)?,
                );
            }
        }
        Value::Bytes(b) => {
            put_head(out, 2, len_u64(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            put_head(out, 3, len_u64(t.len()));
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(CanonicalError::DepthExceeded);
            }
            put_head(out, 4, len_u64(items.len()));
            for item in items {
                encode_into(item, depth + 1, out)?;
            }
        }
        Value::Map(entries) => {
            if depth >= MAX_DEPTH {
                return Err(CanonicalError::DepthExceeded);
            }
            let mut encoded = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let mut kb = Vec::new();
                encode_into(k, depth + 1, &mut kb)?;
                let mut vb = Vec::new();
                encode_into(val, depth + 1, &mut vb)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(CanonicalError::DuplicateKey);
            }
            put_head(out, 5, len_u64(encoded.len()));
            for (kb, vb) in encoded {
                out.extend_from_slice(&kb);
                out.extend_from_slice(&vb);
            }
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Float(_) => return Err(CanonicalError::Float),
        Value::Tag(..) => return Err(CanonicalError::Tag),
        _ => return Err(CanonicalError::Malformed),
    }
    Ok(())
}

/// Encode a CBOR value in canonical form, sorting map entries.
pub fn encode_value(v: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    encode_into(v, 0, &mut out)?;
    Ok(out)
}

/// Serialize `v` to canonical CBOR bytes.
pub fn to_canonical_vec<T: Serialize>(v: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = Value::serialized(v).map_err(|e| CanonicalError::Serde(e.to_string()))?;
    encode_value(&value)
}

/// Strictly parse `bytes`: it must be exactly one canonical CBOR item.
pub fn check_canonical(bytes: &[u8]) -> Result<Value, CanonicalError> {
    let mut rest = bytes;
    let value: Value = ciborium::de::from_reader(&mut rest).map_err(|e| match e {
        ciborium::de::Error::RecursionLimitExceeded => CanonicalError::DepthExceeded,
        _ => CanonicalError::Malformed,
    })?;
    if !rest.is_empty() {
        return Err(CanonicalError::TrailingBytes);
    }
    let reencoded = encode_value(&value)?;
    if reencoded != bytes {
        return Err(CanonicalError::NonCanonical);
    }
    Ok(value)
}

/// Strictly decode canonical CBOR bytes into `T`.
pub fn from_canonical_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CanonicalError> {
    let value = check_canonical(bytes)?;
    value
        .deserialized()
        .map_err(|e| CanonicalError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn err(hex: &str) -> CanonicalError {
        check_canonical(&unhex(hex)).expect_err("must be rejected")
    }

    #[test]
    fn shortest_integer_heads() {
        let cases: &[(i64, &str)] = &[
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65536, "1a00010000"),
            (-1, "20"),
            (-24, "37"),
            (-25, "3818"),
            (-257, "390100"),
        ];
        for (n, hex) in cases {
            let bytes = to_canonical_vec(n).expect("encode");
            assert_eq!(bytes, unhex(hex), "{n}");
            assert_eq!(from_canonical_slice::<i64>(&bytes).expect("decode"), *n);
        }
        assert_eq!(
            to_canonical_vec(&u64::MAX).expect("encode"),
            unhex("1bffffffffffffffff")
        );
    }

    #[test]
    fn mixed_map_keys_sort_by_encoded_bytes() {
        // keys: "b" (61 62), 10 (0a), "aa" (62 61 61), 1 (01)
        let v = Value::Map(vec![
            (Value::Text("b".into()), Value::Null),
            (Value::Integer(10.into()), Value::Null),
            (Value::Text("aa".into()), Value::Null),
            (Value::Integer(1.into()), Value::Null),
        ]);
        let bytes = encode_value(&v).expect("encode");
        assert_eq!(bytes, unhex("a4 01 f6 0a f6 6162 f6 626161 f6"));
        assert!(check_canonical(&bytes).is_ok());
    }

    #[test]
    fn empty_containers_and_payloads() {
        assert_eq!(
            to_canonical_vec(&Vec::<u8>::new()).expect("enc"),
            unhex("80")
        );
        let empty_bytes = Value::Bytes(vec![]);
        assert_eq!(encode_value(&empty_bytes).expect("enc"), unhex("40"));
        assert_eq!(encode_value(&Value::Map(vec![])).expect("enc"), unhex("a0"));
        assert!(check_canonical(&unhex("a0")).is_ok());
        assert!(check_canonical(&unhex("40")).is_ok());
    }

    #[test]
    fn rejects_non_shortest_integer() {
        assert_eq!(err("1800"), CanonicalError::NonCanonical);
        assert_eq!(err("190001"), CanonicalError::NonCanonical);
        assert_eq!(err("1b0000000000000001"), CanonicalError::NonCanonical);
        assert_eq!(err("3800"), CanonicalError::NonCanonical);
        // non-shortest length
        assert_eq!(err("780161"), CanonicalError::NonCanonical);
    }

    #[test]
    fn rejects_indefinite_lengths() {
        assert_eq!(err("5f4101ff"), CanonicalError::NonCanonical);
        assert_eq!(err("7f6161ff"), CanonicalError::NonCanonical);
        assert_eq!(err("9f01ff"), CanonicalError::NonCanonical);
        assert_eq!(err("bf6161 01ff"), CanonicalError::NonCanonical);
    }

    #[test]
    fn rejects_unsorted_keys() {
        assert_eq!(err("a2 6162 01 6161 02"), CanonicalError::NonCanonical);
        assert_eq!(err("a2 0a 01 01 02"), CanonicalError::NonCanonical);
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert_eq!(err("a2 6161 01 6161 02"), CanonicalError::DuplicateKey);
    }

    #[test]
    fn rejects_floats() {
        assert_eq!(err("f93c00"), CanonicalError::Float);
        assert_eq!(err("fb3ff0000000000000"), CanonicalError::Float);
        assert!(matches!(
            to_canonical_vec(&1.0f64),
            Err(CanonicalError::Float)
        ));
    }

    #[test]
    fn rejects_tags() {
        assert_eq!(
            err("c074323031332d30332d32315432303a30343a30305a"),
            CanonicalError::Tag
        );
        assert_eq!(err("c101"), CanonicalError::Tag);
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert_eq!(err("0000"), CanonicalError::TrailingBytes);
        assert_eq!(err("80ff"), CanonicalError::TrailingBytes);
    }

    #[test]
    fn rejects_undefined() {
        // ciborium decodes undefined as null; the re-encode comparison rejects it.
        assert_eq!(err("f7"), CanonicalError::NonCanonical);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(err(""), CanonicalError::Malformed);
        assert_eq!(err("18"), CanonicalError::Malformed);
        assert_eq!(err("a1 01"), CanonicalError::Malformed);
        assert_eq!(err("f0"), CanonicalError::Malformed); // simple(16)
        assert_eq!(err("62c328"), CanonicalError::Malformed); // invalid utf-8
    }

    #[test]
    fn depth_limit() {
        let nest = |n: usize| {
            let mut b = vec![0x81; n];
            b.push(0x00);
            b
        };
        assert!(check_canonical(&nest(32)).is_ok());
        assert_eq!(
            check_canonical(&nest(33)),
            Err(CanonicalError::DepthExceeded)
        );
        assert_eq!(
            check_canonical(&nest(5000)),
            Err(CanonicalError::DepthExceeded)
        );
    }

    #[test]
    fn serde_round_trip() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct S {
            b: Vec<u8>,
            a: Option<u32>,
            name: String,
        }
        let s = S {
            b: vec![1, 2],
            a: None,
            name: "x".into(),
        };
        let bytes = to_canonical_vec(&s).expect("encode");
        // keys sorted: "a" < "b" < "name"
        assert_eq!(&bytes[..4], &unhex("a3 6161 f6")[..]);
        assert_eq!(from_canonical_slice::<S>(&bytes).expect("decode"), s);
        assert!(matches!(
            from_canonical_slice::<S>(&unhex("01")),
            Err(CanonicalError::Serde(_))
        ));
    }
}
