//! WebAuthn assertion verification tests (ES256 and EdDSA).
#![allow(clippy::unwrap_used)]

use ciborium::Value;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use p256::ecdsa::{Signature as P256Sig, SigningKey as P256SigningKey};
use rmm_proto::canonical::{from_canonical_slice, to_canonical_vec};
use rmm_trust::webauthn::{
    Assertion, CoseKey, Expected, SHELL_CHALLENGE_PREFIX, WebAuthnError, parse_cose_key,
    shell_challenge, verify_assertion,
};
use sha2::{Digest, Sha256};

const RP_ID: &str = "rmm.example.com";
const ORIGIN: &str = "https://rmm.example.com";

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for ch in data.chunks(3) {
        let n = ch
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, b)| a | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=ch.len() {
            s.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    s
}

fn auth_data(flags: u8, count: u32) -> Vec<u8> {
    let mut v = Sha256::digest(RP_ID.as_bytes()).to_vec();
    v.push(flags);
    v.extend_from_slice(&count.to_be_bytes());
    v
}

fn client_data(ty: &str, challenge: &[u8; 32], origin: &str, extra: &str) -> Vec<u8> {
    format!(
        "{{\"type\":\"{ty}\",\"challenge\":\"{}\",\"origin\":\"{origin}\"{extra}}}",
        b64url(challenge)
    )
    .into_bytes()
}

fn signing_msg(ad: &[u8], cdj: &[u8]) -> Vec<u8> {
    let mut m = ad.to_vec();
    m.extend_from_slice(&Sha256::digest(cdj));
    m
}

struct Fixture {
    es_sk: P256SigningKey,
    ed_sk: EdSigningKey,
    es_key: CoseKey,
    ed_key: CoseKey,
    origins: Vec<String>,
    challenge: [u8; 32],
}

fn es_cose(sk: &P256SigningKey) -> Vec<u8> {
    let pt = sk.verifying_key().to_sec1_point(false);
    cose_map(2, -7, 1, pt.x().unwrap(), Some(pt.y().unwrap()))
}

fn cose_map(kty: i64, alg: i64, crv: i64, x: &[u8], y: Option<&[u8]>) -> Vec<u8> {
    let mut m = vec![
        (Value::from(1), Value::from(kty)),
        (Value::from(3), Value::from(alg)),
        (Value::from(-1), Value::from(crv)),
        (Value::from(-2), Value::Bytes(x.to_vec())),
    ];
    if let Some(y) = y {
        m.push((Value::from(-3), Value::Bytes(y.to_vec())));
    }
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(m), &mut out).unwrap();
    out
}

fn fixture() -> Fixture {
    let es_sk = P256SigningKey::from_slice(&[7u8; 32]).unwrap();
    let ed_sk = EdSigningKey::from_bytes(&[9u8; 32]);
    let es_key = parse_cose_key(&es_cose(&es_sk)).unwrap();
    let ed_key =
        parse_cose_key(&cose_map(1, -8, 6, ed_sk.verifying_key().as_bytes(), None)).unwrap();
    Fixture {
        es_sk,
        ed_sk,
        es_key,
        ed_key,
        origins: vec![ORIGIN.to_string()],
        challenge: shell_challenge(b"grant-bytes"),
    }
}

impl Fixture {
    fn exp(&self, require_uv: bool) -> Expected<'_> {
        Expected {
            challenge: self.challenge,
            rp_id: RP_ID,
            origins: &self.origins,
            require_uv,
        }
    }
    fn es(&self, ad: Vec<u8>, cdj: Vec<u8>) -> Assertion {
        let sig: P256Sig = self.es_sk.sign(&signing_msg(&ad, &cdj));
        Assertion {
            authenticator_data: ad,
            client_data_json: cdj,
            signature: sig.to_der().as_bytes().to_vec(),
        }
    }
    fn ed(&self, ad: Vec<u8>, cdj: Vec<u8>) -> Assertion {
        let sig = self.ed_sk.sign(&signing_msg(&ad, &cdj));
        Assertion {
            authenticator_data: ad,
            client_data_json: cdj,
            signature: sig.to_bytes().to_vec(),
        }
    }
    fn good_cdj(&self) -> Vec<u8> {
        client_data("webauthn.get", &self.challenge, ORIGIN, "")
    }
}

#[test]
fn challenge_is_prefixed_sha256() {
    let mut h = Sha256::new();
    h.update(SHELL_CHALLENGE_PREFIX);
    h.update(b"abc");
    let want: [u8; 32] = h.finalize().into();
    assert_eq!(shell_challenge(b"abc"), want);
    assert_ne!(shell_challenge(b"abc"), shell_challenge(b"abd"));
}

#[test]
fn valid_es256_passes() {
    let f = fixture();
    let a = f.es(auth_data(0x05, 1), f.good_cdj());
    let flags = verify_assertion(&a, &f.exp(true), &f.es_key).unwrap();
    assert!(flags.up && flags.uv);
}

#[test]
fn valid_eddsa_passes() {
    let f = fixture();
    let a = f.ed(auth_data(0x05, 1), f.good_cdj());
    assert!(verify_assertion(&a, &f.exp(true), &f.ed_key).is_ok());
}

#[test]
fn sign_count_is_big_endian() {
    let f = fixture();
    let a = f.ed(auth_data(0x05, 0x0102_0304), f.good_cdj());
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key)
            .unwrap()
            .sign_count,
        0x0102_0304
    );
}

#[test]
fn uv_not_required_allows_clear_uv() {
    let f = fixture();
    let a = f.ed(auth_data(0x01, 0), f.good_cdj());
    let flags = verify_assertion(&a, &f.exp(false), &f.ed_key).unwrap();
    assert!(flags.up && !flags.uv);
}

#[test]
fn short_authenticator_data_is_malformed() {
    let f = fixture();
    let a = f.ed(vec![0; 36], f.good_cdj());
    assert!(matches!(
        verify_assertion(&a, &f.exp(false), &f.ed_key),
        Err(WebAuthnError::Malformed(_))
    ));
}

#[test]
fn bad_client_data_json_is_malformed() {
    let f = fixture();
    let a = f.ed(auth_data(0x05, 1), b"not json".to_vec());
    assert!(matches!(
        verify_assertion(&a, &f.exp(false), &f.ed_key),
        Err(WebAuthnError::Malformed(_))
    ));
}

#[test]
fn wrong_type_rejected() {
    let f = fixture();
    let cdj = client_data("webauthn.create", &f.challenge, ORIGIN, "");
    let a = f.ed(auth_data(0x05, 1), cdj);
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key),
        Err(WebAuthnError::ClientDataType)
    );
}

#[test]
fn unknown_client_data_fields_accepted() {
    let f = fixture();
    let cdj = client_data(
        "webauthn.get",
        &f.challenge,
        ORIGIN,
        ",\"foo\":{\"a\":1},\"crossOrigin\":false",
    );
    let a = f.ed(auth_data(0x05, 1), cdj);
    assert!(verify_assertion(&a, &f.exp(true), &f.ed_key).is_ok());
}

#[test]
fn challenge_from_different_grant_rejected() {
    let f = fixture();
    let cdj = client_data("webauthn.get", &shell_challenge(b"other-grant"), ORIGIN, "");
    let a = f.ed(auth_data(0x05, 1), cdj);
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key),
        Err(WebAuthnError::Challenge)
    );
}

#[test]
fn padded_challenge_rejected() {
    let f = fixture();
    let cdj = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}=\",\"origin\":\"{ORIGIN}\"}}",
        b64url(&f.challenge)
    )
    .into_bytes();
    let a = f.ed(auth_data(0x05, 1), cdj);
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key),
        Err(WebAuthnError::Challenge)
    );
}

#[test]
fn origin_variants_rejected() {
    let f = fixture();
    for o in [
        "https://rmm.example.com/",
        "http://rmm.example.com",
        "https://rmm.example.com:8443",
        "https://evil.example.com",
    ] {
        let cdj = client_data("webauthn.get", &f.challenge, o, "");
        let a = f.ed(auth_data(0x05, 1), cdj);
        assert_eq!(
            verify_assertion(&a, &f.exp(true), &f.ed_key),
            Err(WebAuthnError::Origin),
            "{o}"
        );
    }
}

#[test]
fn cross_origin_true_rejected() {
    let f = fixture();
    let cdj = client_data(
        "webauthn.get",
        &f.challenge,
        ORIGIN,
        ",\"crossOrigin\":true",
    );
    let a = f.ed(auth_data(0x05, 1), cdj);
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key),
        Err(WebAuthnError::Origin)
    );
}

#[test]
fn wrong_rp_id_rejected() {
    let f = fixture();
    let mut exp = f.exp(true);
    exp.rp_id = "other.example.com";
    let a = f.ed(auth_data(0x05, 1), f.good_cdj());
    assert_eq!(
        verify_assertion(&a, &exp, &f.ed_key),
        Err(WebAuthnError::RpIdHash)
    );
}

#[test]
fn up_clear_rejected() {
    let f = fixture();
    let a = f.ed(auth_data(0x04, 1), f.good_cdj());
    assert_eq!(
        verify_assertion(&a, &f.exp(false), &f.ed_key),
        Err(WebAuthnError::UserPresence)
    );
}

#[test]
fn uv_clear_rejected_when_required() {
    let f = fixture();
    let a = f.ed(auth_data(0x01, 1), f.good_cdj());
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key),
        Err(WebAuthnError::UserVerification)
    );
}

#[test]
fn tampered_authenticator_data_rejected() {
    let f = fixture();
    for key in [&f.es_key, &f.ed_key] {
        let mut a = if matches!(key, CoseKey::Es256(_)) {
            f.es(auth_data(0x05, 1), f.good_cdj())
        } else {
            f.ed(auth_data(0x05, 1), f.good_cdj())
        };
        a.authenticator_data[36] ^= 1; // sign counter bit
        assert_eq!(
            verify_assertion(&a, &f.exp(true), key),
            Err(WebAuthnError::Signature)
        );
    }
}

#[test]
fn tampered_client_data_rejected() {
    let f = fixture();
    let mut a = f.ed(auth_data(0x05, 1), f.good_cdj());
    a.client_data_json.push(b' ');
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key),
        Err(WebAuthnError::Signature)
    );
}

#[test]
fn wrong_key_and_garbage_signature_rejected() {
    let f = fixture();
    let a = f.es(auth_data(0x05, 1), f.good_cdj());
    // ES256 assertion presented against an Ed25519 key.
    assert_eq!(
        verify_assertion(&a, &f.exp(true), &f.ed_key),
        Err(WebAuthnError::Signature)
    );
    let mut b = f.es(auth_data(0x05, 1), f.good_cdj());
    b.signature = vec![1, 2, 3];
    assert_eq!(
        verify_assertion(&b, &f.exp(true), &f.es_key),
        Err(WebAuthnError::Signature)
    );
}

#[test]
fn cose_key_errors() {
    let f = fixture();
    let pt = f.es_sk.verifying_key().to_sec1_point(false);
    let (x, y) = (pt.x().unwrap().to_vec(), pt.y().unwrap().to_vec());
    let bad = [
        cose_map(1, -7, 1, &x, Some(&y)),       // wrong kty for alg
        cose_map(2, -8, 1, &x, Some(&y)),       // wrong alg
        cose_map(2, -7, 6, &x, Some(&y)),       // wrong crv
        cose_map(2, -7, 1, &x, None),           // missing y
        cose_map(2, -7, 1, &x[..31], Some(&y)), // short x
        cose_map(2, -7, 1, &[0u8; 32], Some(&[1u8; 32])), // not on curve
        cose_map(1, -8, 6, &[0u8; 31], None),   // short OKP x
        vec![0xff],                             // not CBOR
        vec![0x01],                             // not a map
    ];
    for b in bad {
        assert!(
            matches!(parse_cose_key(&b), Err(WebAuthnError::CoseKey(_))),
            "{b:?}"
        );
    }
    let mut trailing = es_cose(&f.es_sk);
    trailing.push(0);
    assert!(matches!(
        parse_cose_key(&trailing),
        Err(WebAuthnError::CoseKey(_))
    ));
}

#[test]
fn assertion_cbor_round_trip() {
    let f = fixture();
    let a = f.ed(auth_data(0x05, 1), f.good_cdj());
    let bytes = to_canonical_vec(&a).unwrap();
    assert_eq!(from_canonical_slice::<Assertion>(&bytes).unwrap(), a);
}
