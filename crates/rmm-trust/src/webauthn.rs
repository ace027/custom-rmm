//! Agent-side verification of a WebAuthn assertion over a ShellGrant challenge.
//!
//! The agent verifies the technician's hardware-key assertion independently
//! of the server. ES256 (COSE alg -7) and EdDSA (COSE alg -8) are supported.

use std::io::Cursor;

use ciborium::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::keys::{Bytes, PublicKey, Sig64};

/// Domain-separation prefix for shell challenges.
pub const SHELL_CHALLENGE_PREFIX: &[u8] = b"RMMSHELL1";

/// `SHA-256(SHELL_CHALLENGE_PREFIX || grant_bytes)`.
pub fn shell_challenge(grant_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SHELL_CHALLENGE_PREFIX);
    h.update(grant_bytes);
    h.finalize().into()
}

fn ser_vec<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    Bytes(v.to_vec()).serialize(s)
}

fn de_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    Bytes::deserialize(d).map(|b| b.0)
}

/// The authenticator's response to `navigator.credentials.get`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    #[serde(serialize_with = "ser_vec", deserialize_with = "de_vec")]
    pub authenticator_data: Vec<u8>,
    #[serde(serialize_with = "ser_vec", deserialize_with = "de_vec")]
    pub client_data_json: Vec<u8>,
    #[serde(serialize_with = "ser_vec", deserialize_with = "de_vec")]
    pub signature: Vec<u8>,
}

/// What the verifier requires of the assertion.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    pub challenge: [u8; 32],
    pub rp_id: &'a str,
    pub origins: &'a [String],
    pub require_uv: bool,
}

/// A parsed credential public key.
#[derive(Clone, Debug)]
pub enum CoseKey {
    Es256(P256VerifyingKey),
    Ed25519(PublicKey),
}

/// Authenticator flags and counter from a verified assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthFlags {
    pub up: bool,
    pub uv: bool,
    pub sign_count: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("clientDataJSON type is not webauthn.get")]
    ClientDataType,
    #[error("challenge mismatch")]
    Challenge,
    #[error("origin not allowed")]
    Origin,
    #[error("rpIdHash mismatch")]
    RpIdHash,
    #[error("user presence flag not set")]
    UserPresence,
    #[error("user verification flag not set")]
    UserVerification,
    #[error("bad signature")]
    Signature,
    #[error("bad COSE key: {0}")]
    CoseKey(String),
    #[error("malformed assertion: {0}")]
    Malformed(String),
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

fn cose_err(m: &str) -> WebAuthnError {
    WebAuthnError::CoseKey(m.to_string())
}

fn int_of(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

/// Parse a COSE_Key leniently (authenticators do not emit canonical CBOR).
pub fn parse_cose_key(bytes: &[u8]) -> Result<CoseKey, WebAuthnError> {
    let mut cur = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cur)
        .map_err(|e| WebAuthnError::CoseKey(format!("cbor: {e}")))?;
    if cur.position() != bytes.len() as u64 {
        return Err(cose_err("trailing data"));
    }
    let Value::Map(entries) = value else {
        return Err(cose_err("not a map"));
    };

    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    let mut seen: Vec<i128> = Vec::new();
    for (k, v) in &entries {
        let Some(label) = int_of(k) else { continue };
        if seen.contains(&label) {
            return Err(cose_err("duplicate label"));
        }
        seen.push(label);
        match label {
            1 => kty = int_of(v),
            3 => alg = int_of(v),
            -1 => crv = int_of(v),
            -2 => {
                x = if let Value::Bytes(b) = v {
                    Some(b.clone())
                } else {
                    None
                }
            }
            -3 => {
                y = if let Value::Bytes(b) = v {
                    Some(b.clone())
                } else {
                    None
                }
            }
            _ => {}
        }
    }

    match (kty, alg, crv) {
        (Some(2), Some(-7), Some(1)) => {
            let x = x.ok_or_else(|| cose_err("missing x"))?;
            let y = y.ok_or_else(|| cose_err("missing y"))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(cose_err("x/y must be 32 bytes"));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            P256VerifyingKey::from_sec1_bytes(&point)
                .map(CoseKey::Es256)
                .map_err(|_| cose_err("point not on P-256"))
        }
        (Some(1), Some(-8), Some(6)) => {
            if y.is_some() {
                return Err(cose_err("OKP key must not have y"));
            }
            let x = x.ok_or_else(|| cose_err("missing x"))?;
            let raw =
                <[u8; 32]>::try_from(x.as_slice()).map_err(|_| cose_err("x must be 32 bytes"))?;
            PublicKey::from_bytes(&raw)
                .map(CoseKey::Ed25519)
                .map_err(|_| cose_err("invalid Ed25519 point"))
        }
        _ => Err(cose_err("unsupported kty/alg/crv combination")),
    }
}

/// Strict base64url decode: no padding, no whitespace, canonical trailing bits.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in bytes {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return None;
    }
    Some(out)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// Verify an assertion against the expected challenge, relying party and key.
pub fn verify_assertion(
    a: &Assertion,
    exp: &Expected<'_>,
    key: &CoseKey,
) -> Result<AuthFlags, WebAuthnError> {
    let ad = &a.authenticator_data;
    if ad.len() < 37 {
        return Err(WebAuthnError::Malformed(
            "authenticator data shorter than 37 bytes".into(),
        ));
    }
    let cd: ClientData = serde_json::from_slice(&a.client_data_json)
        .map_err(|e| WebAuthnError::Malformed(format!("clientDataJSON: {e}")))?;

    if cd.ty != "webauthn.get" {
        return Err(WebAuthnError::ClientDataType);
    }
    let got = b64url_decode(&cd.challenge).ok_or(WebAuthnError::Challenge)?;
    if !ct_eq(&got, &exp.challenge) {
        return Err(WebAuthnError::Challenge);
    }
    if cd.cross_origin == Some(true) || !exp.origins.contains(&cd.origin) {
        return Err(WebAuthnError::Origin);
    }

    let rp_hash = Sha256::digest(exp.rp_id.as_bytes());
    if !ct_eq(&ad[..32], &rp_hash) {
        return Err(WebAuthnError::RpIdHash);
    }
    let flags = ad[32];
    let up = flags & FLAG_UP != 0;
    let uv = flags & FLAG_UV != 0;
    if !up {
        return Err(WebAuthnError::UserPresence);
    }
    if exp.require_uv && !uv {
        return Err(WebAuthnError::UserVerification);
    }

    let mut msg = Vec::with_capacity(ad.len() + 32);
    msg.extend_from_slice(ad);
    msg.extend_from_slice(&Sha256::digest(&a.client_data_json));

    match key {
        CoseKey::Es256(vk) => {
            let sig =
                P256Signature::from_der(&a.signature).map_err(|_| WebAuthnError::Signature)?;
            vk.verify(&msg, &sig)
                .map_err(|_| WebAuthnError::Signature)?;
        }
        CoseKey::Ed25519(pk) => {
            let raw = <[u8; 64]>::try_from(a.signature.as_slice())
                .map_err(|_| WebAuthnError::Signature)?;
            pk.verify(&msg, &Sig64(raw))
                .map_err(|_| WebAuthnError::Signature)?;
        }
    }

    Ok(AuthFlags {
        up,
        uv,
        sign_count: u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_strict() {
        assert_eq!(b64url_decode("aGk"), Some(b"hi".to_vec()));
        assert_eq!(b64url_decode("_-8"), Some(vec![0xff, 0xef]));
        assert_eq!(b64url_decode(""), Some(vec![]));
        assert_eq!(b64url_decode("aGk="), None);
        assert_eq!(b64url_decode("aGl"), None); // non-zero trailing bits
        assert_eq!(b64url_decode("a"), None);
        assert_eq!(b64url_decode("a+/="), None);
        assert_eq!(b64url_decode("aG k"), None);
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"ab", b"ab"));
        assert!(!ct_eq(b"ab", b"ac"));
        assert!(!ct_eq(b"ab", b"abc"));
    }
}
