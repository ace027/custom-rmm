//! Key identifiers, signature and byte newtypes, and the verifying key wrapper.
//!
//! All newtypes serialize as lowercase hex strings for human-readable formats
//! (JSON) and as CBOR byte strings otherwise.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::TrustError;

fn ser_bytes<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        s.serialize_str(&hex::encode(b))
    } else {
        s.serialize_bytes(b)
    }
}

struct BytesVisitor;

impl Visitor<'_> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte string or lowercase hex string")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(v)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(E::custom("hex must be lowercase"));
        }
        hex::decode(v).map_err(E::custom)
    }
}

fn de_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    if d.is_human_readable() {
        d.deserialize_str(BytesVisitor)
    } else {
        d.deserialize_bytes(BytesVisitor)
    }
}

fn de_array<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
    let v = de_bytes(d)?;
    <[u8; N]>::try_from(v.as_slice())
        .map_err(|_| de::Error::invalid_length(v.len(), &"a fixed-length byte string"))
}

macro_rules! fixed_newtype {
    ($(#[$m:meta])* $name:ident, $n:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $n]);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                ser_bytes(&self.0, s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                de_array::<D, $n>(d).map(Self)
            }
        }
    };
}

fixed_newtype!(
    /// SHA-256 of a raw Ed25519 public key.
    KeyId,
    32
);
fixed_newtype!(
    /// A 64-byte Ed25519 signature.
    Sig64,
    64
);

/// Arbitrary bytes (envelope payloads).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Bytes(pub Vec<u8>);

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({} bytes)", self.0.len())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_bytes(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        de_bytes(d).map(Self)
    }
}

/// An Ed25519 verifying key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0.as_bytes()))
    }
}

impl PublicKey {
    /// Parse a raw 32-byte Ed25519 public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, TrustError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| TrustError::InvalidKey)
    }

    /// The raw 32-byte public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `SHA-256(raw public key)`.
    pub fn key_id(&self) -> KeyId {
        KeyId(Sha256::digest(self.0.as_bytes()).into())
    }

    /// Strict Ed25519 verification of `sig` over `msg`.
    pub(crate) fn verify(&self, msg: &[u8], sig: &Sig64) -> Result<(), TrustError> {
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| TrustError::BadSignature)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_bytes(self.0.as_bytes(), s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = de_array::<D, 32>(d)?;
        Self::from_bytes(&raw).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_proto::canonical::{from_canonical_slice, to_canonical_vec};

    #[test]
    fn key_id_hex_in_json_bytes_in_cbor() {
        let id = KeyId([0xab; 32]);
        let json = serde_json::to_string(&id).expect("json");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<KeyId>(&json).expect("de"), id);
        assert!(serde_json::from_str::<KeyId>(&format!("\"{}\"", "AB".repeat(32))).is_err());
        assert!(serde_json::from_str::<KeyId>("\"abab\"").is_err());

        let cbor = to_canonical_vec(&id).expect("cbor");
        assert_eq!(&cbor[..3], &[0x58, 0x20, 0xab]);
        assert_eq!(cbor.len(), 34);
        assert_eq!(from_canonical_slice::<KeyId>(&cbor).expect("de"), id);
    }

    #[test]
    fn sig_and_bytes_round_trip() {
        let s = Sig64([7; 64]);
        let cbor = to_canonical_vec(&s).expect("cbor");
        assert_eq!(cbor.len(), 66);
        assert_eq!(from_canonical_slice::<Sig64>(&cbor).expect("de"), s);
        let b = Bytes(vec![0, 255]);
        assert_eq!(serde_json::to_string(&b).expect("json"), "\"00ff\"");
        let cbor = to_canonical_vec(&b).expect("cbor");
        assert_eq!(cbor, vec![0x42, 0, 255]);
        assert_eq!(from_canonical_slice::<Bytes>(&cbor).expect("de"), b);
    }

    #[test]
    fn wrong_length_rejected() {
        let cbor = to_canonical_vec(&Bytes(vec![1; 31])).expect("cbor");
        assert!(from_canonical_slice::<KeyId>(&cbor).is_err());
    }

    #[test]
    fn public_key_rejects_invalid_point() {
        // y = 2 is not on the curve for ed25519.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert_eq!(PublicKey::from_bytes(&bad), Err(TrustError::InvalidKey));
    }
}
