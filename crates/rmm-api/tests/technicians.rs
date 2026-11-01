//! Hardware-only WebAuthn registration and the techlist draft, against a
//! database. A test attestation CA, intermediate and authenticator are
//! generated here (fixed test seeds; no private keys are checked in) and
//! produce `packed` attestations the way a FIDO2 security key does.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciborium::Value as Cbor;
use ed25519_dalek::{Signer as _, SigningKey as EdKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::signature::Keypair;
use p256::ecdsa::{DerSignature, SigningKey as P256Key};
use rmm_api::attestation::{
    AttestationConfig, AttestationError, OID_FIDO_GEN_CE_AAGUID, verify_registration_at,
};
use rmm_api::auth::{AuthConfig, Authenticator, DEV_ISSUER, rsa_private_der_from_pem};
use rmm_api::{AppState, TrustRoots};
use rmm_db::repo;
use rmm_db::scope::{Scope, begin_scoped};
use rmm_db::shell;
use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{TechnicianList, TrustManifest};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_MANIFEST, signing_message,
};
use rmm_trust::keys::{Bytes, PublicKey, Sig64};
use rmm_trust::webauthn::parse_cose_key;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use sqlx::types::chrono::Utc;
use tower::ServiceExt;
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::asn1::{Any, BitString, OctetString};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, Document};
use x509_cert::spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Encode, EncodePem};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::{Time, Validity};

const AUD: &str = "api://rmm-test";
const RP_ID: &str = "console.test";
const ORIGIN: &str = "https://console.test";
const ROOT_SEED: u8 = 7;
/// A YubiKey 5 (firmware 5.2/5.4) AAGUID.
const AAGUID: [u8; 16] = [
    0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a,
];
const OTHER_AAGUID: [u8; 16] = [0x42; 16];

fn now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap()
}

fn b64(b: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(b)
}

// ---------------------------------------------------------------- X.509 CA

struct Profile {
    subject: Name,
    issuer: Name,
    ca: bool,
    aaguid_ext: Option<Vec<u8>>,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let bc = BasicConstraints {
            ca: self.ca,
            path_len_constraint: None,
        };
        let mut exts = vec![Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der()?)?,
        }];
        if let Some(a) = &self.aaguid_ext {
            exts.push(Extension {
                extn_id: OID_FIDO_GEN_CE_AAGUID,
                critical: false,
                extn_value: OctetString::new(OctetString::new(a.clone())?.to_der()?)?,
            });
        }
        Ok(exts)
    }
}

fn p256(seed: u8) -> P256Key {
    P256Key::from_slice(&[seed; 32]).unwrap()
}

fn spki(k: &P256Key) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_key(k.verifying_key()).unwrap()
}

fn validity(from: i64, to: i64) -> Validity {
    let at = |d: i64| {
        let t = if d >= 0 {
            SystemTime::now() + Duration::from_secs(d.unsigned_abs())
        } else {
            SystemTime::now() - Duration::from_secs(d.unsigned_abs())
        };
        Time::try_from(t).unwrap()
    };
    Validity::new(at(from), at(to))
}

const DAY: i64 = 86_400;

struct CertSpec<'a> {
    subject: &'a str,
    issuer: &'a str,
    key: &'a P256Key,
    issuer_key: &'a P256Key,
    ca: bool,
    aaguid_ext: Option<Vec<u8>>,
    validity: Validity,
}

fn make_cert(s: CertSpec<'_>) -> Certificate {
    let profile = Profile {
        subject: Name::from_str(s.subject).unwrap(),
        issuer: Name::from_str(s.issuer).unwrap(),
        ca: s.ca,
        aaguid_ext: s.aaguid_ext,
    };
    let builder =
        CertificateBuilder::new(profile, SerialNumber::from(42u32), s.validity, spki(s.key))
            .unwrap();
    builder.build::<_, DerSignature>(s.issuer_key).unwrap()
}

const ROOT_DN: &str = "CN=Test FIDO Root CA,O=Test Vendor,C=US";
const INT_DN: &str = "CN=Test FIDO Intermediate,O=Test Vendor,C=US";
const LEAF_DN: &str = "CN=Test Key EE,OU=Authenticator Attestation,O=Test Vendor,C=SE";

/// A self-signed root CA from `seed`.
fn root_ca(seed: u8) -> (P256Key, Certificate) {
    let k = p256(seed);
    let c = make_cert(CertSpec {
        subject: ROOT_DN,
        issuer: ROOT_DN,
        key: &k,
        issuer_key: &k,
        ca: true,
        aaguid_ext: None,
        validity: validity(-DAY, 3650 * DAY),
    });
    (k, c)
}

/// What the fake authenticator should do.
#[derive(Clone)]
struct Opts {
    fmt: &'static str,
    with_x5c: bool,
    /// Include an intermediate between leaf and root (x5c length 2).
    intermediate: bool,
    root_seed: u8,
    aaguid: [u8; 16],
    /// AAGUID in the leaf extension (None: omit the extension).
    cert_aaguid: Option<[u8; 16]>,
    leaf_validity: (i64, i64),
    leaf_ou: bool,
    flags: u8,
    rp_id: &'static str,
    origin: &'static str,
    ty: &'static str,
    cred_seed: u8,
    cred_id: Vec<u8>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            fmt: "packed",
            with_x5c: true,
            intermediate: true,
            root_seed: ROOT_SEED,
            aaguid: AAGUID,
            cert_aaguid: Some(AAGUID),
            leaf_validity: (-DAY, 365 * DAY),
            leaf_ou: true,
            flags: 0x01 | 0x04 | 0x40,
            rp_id: RP_ID,
            origin: ORIGIN,
            ty: "webauthn.create",
            cred_seed: 21,
            cred_id: vec![0xc1; 32],
        }
    }
}

fn cose_es256(k: &P256Key) -> Vec<u8> {
    let point = k.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let map = Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
        (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
        (
            Cbor::Integer((-2).into()),
            Cbor::Bytes(bytes[1..33].to_vec()),
        ),
        (
            Cbor::Integer((-3).into()),
            Cbor::Bytes(bytes[33..65].to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&map, &mut out).unwrap();
    out
}

struct Made {
    att_obj: Vec<u8>,
    client_data: Vec<u8>,
    cose: Vec<u8>,
}

/// Produce a registration response for `challenge`.
fn attest(o: &Opts, challenge: &[u8]) -> Made {
    let (x5c, leaf_key) = p256_chain(o);
    attest_with(o, challenge, x5c, &leaf_key)
}

/// A registration response for `challenge` with the given x5c and leaf key.
fn attest_with(o: &Opts, challenge: &[u8], x5c: Vec<Vec<u8>>, leaf_key: &P256Key) -> Made {
    let cred_key = p256(o.cred_seed);
    let cose = cose_es256(&cred_key);
    let mut ad = Sha256::digest(o.rp_id.as_bytes()).to_vec();
    ad.push(o.flags);
    ad.extend_from_slice(&5u32.to_be_bytes());
    ad.extend_from_slice(&o.aaguid);
    ad.extend_from_slice(&u16::try_from(o.cred_id.len()).unwrap().to_be_bytes());
    ad.extend_from_slice(&o.cred_id);
    ad.extend_from_slice(&cose);

    let client_data = serde_json::to_vec(&json!({
        "type": o.ty, "challenge": b64(challenge), "origin": o.origin, "crossOrigin": false
    }))
    .unwrap();
    assemble(o, ad, client_data, cose, x5c, leaf_key)
}

/// An all-P-256 x5c (leaf first) from `o`'s root, and the leaf key.
fn p256_chain(o: &Opts) -> (Vec<Vec<u8>>, P256Key) {
    let (root_key, _) = root_ca(o.root_seed);
    let int_key = p256(o.root_seed.wrapping_add(1));
    let leaf_key = p256(o.root_seed.wrapping_add(2));
    let leaf_dn = if o.leaf_ou {
        LEAF_DN
    } else {
        "CN=Test Key EE,O=Test Vendor,C=SE"
    };
    let mut x5c = Vec::new();
    if o.intermediate {
        let int = make_cert(CertSpec {
            subject: INT_DN,
            issuer: ROOT_DN,
            key: &int_key,
            issuer_key: &root_key,
            ca: true,
            aaguid_ext: None,
            validity: validity(-DAY, 3650 * DAY),
        });
        let leaf = make_cert(CertSpec {
            subject: leaf_dn,
            issuer: INT_DN,
            key: &leaf_key,
            issuer_key: &int_key,
            ca: false,
            aaguid_ext: o.cert_aaguid.map(|a| a.to_vec()),
            validity: validity(o.leaf_validity.0, o.leaf_validity.1),
        });
        x5c.push(leaf.to_der().unwrap());
        x5c.push(int.to_der().unwrap());
    } else {
        let leaf = make_cert(CertSpec {
            subject: leaf_dn,
            issuer: ROOT_DN,
            key: &leaf_key,
            issuer_key: &root_key,
            ca: false,
            aaguid_ext: o.cert_aaguid.map(|a| a.to_vec()),
            validity: validity(o.leaf_validity.0, o.leaf_validity.1),
        });
        x5c.push(leaf.to_der().unwrap());
    }

    (x5c, leaf_key)
}

/// Sign `ad || SHA-256(client_data)` with `leaf_key` and build the object.
fn assemble(
    o: &Opts,
    ad: Vec<u8>,
    client_data: Vec<u8>,
    cose: Vec<u8>,
    x5c: Vec<Vec<u8>>,
    leaf_key: &P256Key,
) -> Made {
    let mut msg = ad.clone();
    msg.extend_from_slice(&Sha256::digest(&client_data));
    let sig: DerSignature = leaf_key.sign(&msg);

    let mut stmt = vec![
        (Cbor::Text("alg".into()), Cbor::Integer((-7).into())),
        (
            Cbor::Text("sig".into()),
            Cbor::Bytes(sig.as_bytes().to_vec()),
        ),
    ];
    if o.with_x5c {
        stmt.push((
            Cbor::Text("x5c".into()),
            Cbor::Array(x5c.into_iter().map(Cbor::Bytes).collect()),
        ));
    }
    let stmt = if o.fmt == "none" {
        Cbor::Map(vec![])
    } else {
        Cbor::Map(stmt)
    };
    let obj = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text(o.fmt.into())),
        (Cbor::Text("attStmt".into()), stmt),
        (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
    ]);
    let mut att_obj = Vec::new();
    ciborium::ser::into_writer(&obj, &mut att_obj).unwrap();
    Made {
        att_obj,
        client_data,
        cose,
    }
}

fn config(root_seed: u8) -> AttestationConfig {
    let (_, root) = root_ca(root_seed);
    let pem = root.to_pem(LineEnding::LF).unwrap();
    AttestationConfig::from_parts(pem.as_bytes(), &data_encoding::HEXLOWER.encode(&AAGUID)).unwrap()
}

/// Verify directly (no database) with the default configuration.
fn verify(o: &Opts) -> Result<rmm_api::attestation::RegisteredCredential, AttestationError> {
    let challenge = [9u8; 32];
    let m = attest(o, &challenge);
    let cfg = config(ROOT_SEED);
    verify_registration_at(
        &m.att_obj,
        &m.client_data,
        &challenge,
        RP_ID,
        &[ORIGIN.to_owned()],
        &cfg.roots,
        &cfg.aaguids,
        now(),
    )
}

// ------------------------------------------------------- verifier matrix

#[test]
fn hardware_attestation_with_intermediate_verifies() {
    let o = Opts::default();
    let got = verify(&o).unwrap();
    assert_eq!(got.aaguid, AAGUID);
    assert_eq!(got.cred_id, o.cred_id);
    assert_eq!(got.alg, -7);
    assert_eq!(got.sign_count, 5);
    assert_eq!(got.cose_pubkey, cose_es256(&p256(o.cred_seed)));
    parse_cose_key(&got.cose_pubkey).unwrap();
}

#[test]
fn x5c_of_length_one_verifies_against_the_root() {
    let o = Opts {
        intermediate: false,
        ..Opts::default()
    };
    verify(&o).unwrap();
}

#[test]
fn leaf_without_aaguid_extension_still_needs_allowlist() {
    let o = Opts {
        cert_aaguid: None,
        ..Opts::default()
    };
    verify(&o).unwrap();
    let o = Opts {
        cert_aaguid: None,
        aaguid: OTHER_AAGUID,
        ..Opts::default()
    };
    assert!(matches!(
        verify(&o),
        Err(AttestationError::AaguidNotAllowed(_))
    ));
}

#[test]
fn none_and_self_attestation_are_rejected() {
    let none = Opts {
        fmt: "none",
        ..Opts::default()
    };
    assert!(matches!(verify(&none), Err(AttestationError::Format(_))));
    let selfatt = Opts {
        with_x5c: false,
        ..Opts::default()
    };
    assert!(matches!(verify(&selfatt), Err(AttestationError::Format(_))));
    let tpm = Opts {
        fmt: "fido-u2f",
        ..Opts::default()
    };
    assert!(matches!(verify(&tpm), Err(AttestationError::Format(_))));
}

#[test]
fn wrong_root_is_rejected() {
    for intermediate in [true, false] {
        let o = Opts {
            root_seed: 99,
            intermediate,
            ..Opts::default()
        };
        assert!(
            matches!(verify(&o), Err(AttestationError::Chain(_))),
            "intermediate={intermediate}"
        );
    }
}

#[test]
fn aaguid_not_allowlisted_or_mismatched_is_rejected() {
    let o = Opts {
        aaguid: OTHER_AAGUID,
        cert_aaguid: Some(OTHER_AAGUID),
        ..Opts::default()
    };
    assert!(matches!(
        verify(&o),
        Err(AttestationError::AaguidNotAllowed(_))
    ));
    // The authenticator claims an allowlisted AAGUID its certificate does not carry.
    let o = Opts {
        cert_aaguid: Some(OTHER_AAGUID),
        ..Opts::default()
    };
    assert_eq!(verify(&o), Err(AttestationError::AaguidMismatch));
}

#[test]
fn flags_are_enforced() {
    let no_uv = Opts {
        flags: 0x01 | 0x40,
        ..Opts::default()
    };
    assert_eq!(verify(&no_uv), Err(AttestationError::UserVerification));
    let no_up = Opts {
        flags: 0x04 | 0x40,
        ..Opts::default()
    };
    assert_eq!(verify(&no_up), Err(AttestationError::UserPresence));
    let synced = Opts {
        flags: 0x01 | 0x04 | 0x08 | 0x40,
        ..Opts::default()
    };
    assert_eq!(verify(&synced), Err(AttestationError::BackupEligible));
}

#[test]
fn client_data_and_rp_are_enforced() {
    let o = Opts {
        origin: "https://evil.test",
        ..Opts::default()
    };
    assert_eq!(verify(&o), Err(AttestationError::Origin));
    let o = Opts {
        ty: "webauthn.get",
        ..Opts::default()
    };
    assert_eq!(verify(&o), Err(AttestationError::ClientDataType));
    let o = Opts {
        rp_id: "evil.test",
        ..Opts::default()
    };
    assert_eq!(verify(&o), Err(AttestationError::RpIdHash));
    // Response made for another challenge.
    let m = attest(&Opts::default(), &[1u8; 32]);
    let cfg = config(ROOT_SEED);
    let err = verify_registration_at(
        &m.att_obj,
        &m.client_data,
        &[9u8; 32],
        RP_ID,
        &[ORIGIN.to_owned()],
        &cfg.roots,
        &cfg.aaguids,
        now(),
    );
    assert_eq!(err, Err(AttestationError::Challenge));
}

#[test]
fn expired_or_future_leaf_is_rejected() {
    let o = Opts {
        leaf_validity: (-30 * DAY, -DAY),
        ..Opts::default()
    };
    assert_eq!(verify(&o), Err(AttestationError::CertificateValidity));
    let o = Opts {
        leaf_validity: (DAY, 30 * DAY),
        intermediate: false,
        ..Opts::default()
    };
    assert_eq!(verify(&o), Err(AttestationError::CertificateValidity));
}

#[test]
fn leaf_must_be_an_attestation_certificate() {
    let o = Opts {
        leaf_ou: false,
        ..Opts::default()
    };
    assert!(matches!(verify(&o), Err(AttestationError::Chain(_))));
}

#[test]
fn tampered_signature_is_rejected() {
    let challenge = [9u8; 32];
    let m = attest(&Opts::default(), &challenge);
    let cfg = config(ROOT_SEED);
    let mut cd = m.client_data.clone();
    // Same JSON meaning, different bytes: the signature covers the hash.
    cd.push(b' ');
    let err = verify_registration_at(
        &m.att_obj,
        &cd,
        &challenge,
        RP_ID,
        &[ORIGIN.to_owned()],
        &cfg.roots,
        &cfg.aaguids,
        now(),
    );
    assert_eq!(err, Err(AttestationError::Signature));
    let _ = m.cose;
}

#[test]
fn config_parsing() {
    let (_, root) = root_ca(ROOT_SEED);
    let pem = root.to_pem(LineEnding::LF).unwrap();
    assert!(AttestationConfig::from_parts(pem.as_bytes(), "").is_err());
    assert!(AttestationConfig::from_parts(b"", "ee882879721c491397753dfcce97072a").is_err());
    assert!(AttestationConfig::from_parts(pem.as_bytes(), "zz").is_err());
    assert!(AttestationConfig::from_parts(pem.as_bytes(), &"00".repeat(16)).is_err());
    let cfg = AttestationConfig::from_parts(
        pem.as_bytes(),
        "ee882879-721c-4913-9775-3dfcce97072a, 42424242424242424242424242424242",
    )
    .unwrap();
    assert_eq!(cfg.aaguids, vec![AAGUID, OTHER_AAGUID]);
}

// ------------------------------------- P-384 and RSA roots (aws-lc-rs)
//
// Real vendor attestation CAs are not all P-256: Yubico's FIDO root is
// RSA-2048 and newer roots are P-384. These keys are generated per test run.

/// A test CA whose key lives in aws-lc-rs, usable as an x509-cert signer.
struct AwsCa {
    key: AwsKey,
    spki_der: Vec<u8>,
    /// Signature algorithm OID to claim (default: the one actually used).
    claim: Option<ObjectIdentifier>,
}

enum AwsKey {
    P384(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

#[derive(Clone)]
struct SpkiDer(Vec<u8>);

impl EncodePublicKey for SpkiDer {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<Document> {
        Ok(Document::try_from(self.0.as_slice())?)
    }
}

impl Keypair for AwsCa {
    type VerifyingKey = SpkiDer;
    fn verifying_key(&self) -> SpkiDer {
        SpkiDer(self.spki_der.clone())
    }
}

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

impl DynSignatureAlgorithmIdentifier for AwsCa {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(match self.key {
            AwsKey::P384(_) => AlgorithmIdentifierOwned {
                oid: self.claim.unwrap_or(OID_ECDSA_SHA384),
                parameters: None,
            },
            AwsKey::Rsa(_) => AlgorithmIdentifierOwned {
                oid: self.claim.unwrap_or(OID_SHA256_RSA),
                parameters: Some(Any::null()),
            },
        })
    }
}

impl AwsCa {
    fn p384() -> Self {
        let k = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING).unwrap();
        let spki_der = k.public_key().as_der().unwrap().as_ref().to_vec();
        Self {
            key: AwsKey::P384(k),
            spki_der,
            claim: None,
        }
    }

    fn rsa2048() -> Self {
        let k = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let spki_der = k.public_key().as_der().unwrap().as_ref().to_vec();
        Self {
            key: AwsKey::Rsa(k),
            spki_der,
            claim: None,
        }
    }

    fn spki(&self) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_der(&self.spki_der).unwrap()
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.key {
            AwsKey::P384(k) => k.sign(&rng, msg).unwrap().as_ref().to_vec(),
            AwsKey::Rsa(k) => {
                let mut out = vec![0u8; k.public_modulus_len()];
                k.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut out).unwrap();
                out
            }
        }
    }

    /// Issue a certificate for `subject_spki`, signed by this CA.
    fn issue(&self, profile: Profile, subject_spki: SubjectPublicKeyInfoOwned) -> Certificate {
        let mut b = CertificateBuilder::new(
            profile,
            SerialNumber::from(43u32),
            validity(-DAY, 3650 * DAY),
            subject_spki,
        )
        .unwrap();
        let tbs = b.finalize(self).unwrap();
        let sig = BitString::from_bytes(&self.sign(&tbs)).unwrap();
        b.assemble(sig, self).unwrap()
    }

    fn root(&self) -> Certificate {
        self.issue(profile(ROOT_DN, ROOT_DN, true, None), self.spki())
    }
}

fn profile(subject: &str, issuer: &str, ca: bool, aaguid: Option<[u8; 16]>) -> Profile {
    Profile {
        subject: Name::from_str(subject).unwrap(),
        issuer: Name::from_str(issuer).unwrap(),
        ca,
        aaguid_ext: aaguid.map(|a| a.to_vec()),
    }
}

/// x5c issued by `ca` (directly, or through a P-256 intermediate), and the
/// P-256 leaf key.
fn aws_chain(ca: &AwsCa, intermediate: bool) -> (Vec<Vec<u8>>, P256Key) {
    let leaf_key = p256(31);
    if intermediate {
        let int_key = p256(32);
        let int = ca.issue(profile(INT_DN, ROOT_DN, true, None), spki(&int_key));
        let leaf = make_cert(CertSpec {
            subject: LEAF_DN,
            issuer: INT_DN,
            key: &leaf_key,
            issuer_key: &int_key,
            ca: false,
            aaguid_ext: Some(AAGUID.to_vec()),
            validity: validity(-DAY, 365 * DAY),
        });
        (vec![leaf.to_der().unwrap(), int.to_der().unwrap()], leaf_key)
    } else {
        let leaf = ca.issue(profile(LEAF_DN, ROOT_DN, false, Some(AAGUID)), spki(&leaf_key));
        (vec![leaf.to_der().unwrap()], leaf_key)
    }
}

/// Verify a default response carrying `x5c` against `root` only.
fn verify_against(
    root: &Certificate,
    x5c: Vec<Vec<u8>>,
    leaf_key: &P256Key,
) -> Result<rmm_api::attestation::RegisteredCredential, AttestationError> {
    let challenge = [9u8; 32];
    let m = attest_with(&Opts::default(), &challenge, x5c, leaf_key);
    let pem = root.to_pem(LineEnding::LF).unwrap();
    let cfg =
        AttestationConfig::from_parts(pem.as_bytes(), &data_encoding::HEXLOWER.encode(&AAGUID))
            .unwrap();
    verify_registration_at(
        &m.att_obj,
        &m.client_data,
        &challenge,
        RP_ID,
        &[ORIGIN.to_owned()],
        &cfg.roots,
        &cfg.aaguids,
        now(),
    )
}

#[test]
fn p384_and_rsa2048_roots_verify_with_x5c_of_length_one_and_two() {
    for (name, ca) in [("p384", AwsCa::p384()), ("rsa2048", AwsCa::rsa2048())] {
        let root = ca.root();
        for intermediate in [false, true] {
            let (x5c, leaf_key) = aws_chain(&ca, intermediate);
            let got = verify_against(&root, x5c, &leaf_key)
                .unwrap_or_else(|e| panic!("{name} intermediate={intermediate}: {e:?}"));
            assert_eq!(got.aaguid, AAGUID);
        }
    }
}

#[test]
fn p384_and_rsa2048_chain_to_another_root_is_rejected() {
    for (name, ca, other) in [
        ("p384", AwsCa::p384(), AwsCa::p384()),
        ("rsa2048", AwsCa::rsa2048(), AwsCa::rsa2048()),
    ] {
        // Same DN, different key: the signature check must fail.
        let other_root = other.root();
        for intermediate in [false, true] {
            let (x5c, leaf_key) = aws_chain(&ca, intermediate);
            assert!(
                matches!(
                    verify_against(&other_root, x5c, &leaf_key),
                    Err(AttestationError::Chain(_))
                ),
                "{name} intermediate={intermediate}"
            );
        }
    }
}

#[test]
fn signature_algorithm_must_match_the_issuer_key() {
    // A P-384 CA claiming ecdsa-with-SHA256, and an RSA CA claiming
    // ecdsa-with-SHA384: both are rejected rather than reinterpreted.
    let mut p384 = AwsCa::p384();
    let p384_root = p384.root();
    p384.claim = Some(OID_ECDSA_SHA256);
    let mut rsa = AwsCa::rsa2048();
    let rsa_root = rsa.root();
    rsa.claim = Some(OID_ECDSA_SHA384);
    for (root, ca) in [(&p384_root, &p384), (&rsa_root, &rsa)] {
        let (x5c, leaf_key) = aws_chain(ca, false);
        assert!(matches!(
            verify_against(root, x5c, &leaf_key),
            Err(AttestationError::Chain(_))
        ));
    }
}

// ------------------------------------------------------------- HTTP flow

fn ed(seed: u8) -> EdKey {
    EdKey::from_bytes(&[seed; 32])
}

fn ed_pub(k: &EdKey) -> PublicKey {
    PublicKey::from_bytes(&k.verifying_key().to_bytes()).unwrap()
}

fn manifest() -> Vec<u8> {
    let root = ed(ROOT_SEED);
    let doc = TrustManifest {
        seq: 1,
        issued_at: now() - 100,
        expires_at: now() + 30 * 86_400,
        root_keys: vec![Bytes(ed_pub(&root).to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![],
        thresholds: BTreeMap::new(),
        revoked_keys: vec![],
        console_rp_id: RP_ID.into(),
        console_origins: vec![ORIGIN.into()],
        capability_ceiling: vec![],
        revocation_mirrors: vec![],
    };
    let payload = to_canonical_vec(&doc).unwrap();
    let msg = signing_message(TYPE_MANIFEST, &payload);
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: TYPE_MANIFEST.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: ed_pub(&root).key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(root.sign(&msg).to_bytes()),
        }],
    }
    .to_bytes()
    .unwrap()
}

fn dev_auth() -> Authenticator {
    Authenticator::from_config(AuthConfig {
        tenant_id: None,
        audience: AUD.into(),
        allow_dev: true,
        dev_pubkey_pem: Some(DEV_PUB.as_bytes().to_vec()),
    })
    .unwrap()
}

fn token(sub: &str, roles: &[&str]) -> String {
    let c = json!({"iss": DEV_ISSUER, "aud": AUD, "exp": now() + 600, "sub": sub,
        "oid": format!("oid-{sub}"), "name": format!("Name {sub}"), "roles": roles});
    let k = EncodingKey::from_rsa_der(&rsa_private_der_from_pem(DEV_KEY.as_bytes()).unwrap());
    format!(
        "Bearer {}",
        encode(&Header::new(Algorithm::RS256), &c, &k).unwrap()
    )
}

struct Ctx {
    pool: PgPool,
    app: Router,
}

async fn setup(pool: PgPool, attestation: bool, install_manifest: bool) -> Ctx {
    let api_pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE rmm_api").execute(conn).await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let roots = TrustRoots {
        keys: vec![ed_pub(&ed(ROOT_SEED)).to_bytes()],
        threshold: 1,
    };
    let state = AppState::new(api_pool, dev_auth(), None, roots, "wss://nats.test".into())
        .with_attestation(attestation.then(|| config(ROOT_SEED)));
    let ctx = Ctx {
        pool,
        app: rmm_api::router(state),
    };
    if install_manifest {
        let req = Request::put("/api/v1/trust/manifest")
            .header("authorization", token("admin", &["RMM.Admin"]))
            .header("content-type", "application/octet-stream")
            .body(Body::from(manifest()))
            .unwrap();
        assert_eq!(call(&ctx.app, req).await.0, StatusCode::NO_CONTENT);
    }
    ctx
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, v)
}

async fn begin(ctx: &Ctx, sub: &str) -> (StatusCode, Value) {
    let req = Request::post("/api/v1/technicians/me/credentials/register/begin")
        .header("authorization", token(sub, &[]))
        .body(Body::empty())
        .unwrap();
    call(&ctx.app, req).await
}

async fn finish(ctx: &Ctx, sub: &str, challenge_id: &str, m: &Made) -> (StatusCode, Value) {
    let body = json!({
        "challenge_id": challenge_id,
        "attestation_object_b64url": b64(&m.att_obj),
        "client_data_json_b64url": b64(&m.client_data),
    });
    let req = Request::post("/api/v1/technicians/me/credentials/register/finish")
        .header("authorization", token(sub, &[]))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    call(&ctx.app, req).await
}

/// begin + finish with `o`; returns the finish result.
async fn register(ctx: &Ctx, sub: &str, o: &Opts) -> (StatusCode, Value, String, Made) {
    let (st, opts) = begin(ctx, sub).await;
    assert_eq!(st, StatusCode::OK, "{opts}");
    let challenge = data_encoding::BASE64URL_NOPAD
        .decode(opts["challenge_b64url"].as_str().unwrap().as_bytes())
        .unwrap();
    let id = opts["challenge_id"].as_str().unwrap().to_owned();
    let m = attest(o, &challenge);
    let (st, body) = finish(ctx, sub, &id, &m).await;
    (st, body, id, m)
}

async fn draft(ctx: &Ctx, roles: &[&str]) -> (StatusCode, Value) {
    let req = Request::get("/api/v1/admin/techlist-draft")
        .header("authorization", token("admin", roles))
        .body(Body::empty())
        .unwrap();
    call(&ctx.app, req).await
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn begin_returns_creation_options(pool: PgPool) {
    let ctx = setup(pool, true, true).await;
    let (st, v) = begin(&ctx, "alice").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["rp_id"], RP_ID);
    assert_eq!(v["attestation"], "direct");
    assert_eq!(v["timeout_ms"], 300_000);
    assert_eq!(v["pub_key_cred_params"], json!([-7, -8]));
    assert_eq!(
        v["authenticator_selection"],
        json!({"user_verification": "required", "resident_key": "discouraged"})
    );
    let ch = data_encoding::BASE64URL_NOPAD
        .decode(v["challenge_b64url"].as_str().unwrap().as_bytes())
        .unwrap();
    assert_eq!(ch.len(), 32);
    assert!(!v["user_id_b64url"].as_str().unwrap().is_empty());
    // Unauthenticated callers get nothing.
    let req = Request::post("/api/v1/technicians/me/credentials/register/begin")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&ctx.app, req).await.0, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn registration_is_unavailable_without_configuration(pool: PgPool) {
    // Configured but without a trust manifest: no rp id to bind to.
    let ctx = setup(pool.clone(), true, false).await;
    assert_eq!(
        begin(&ctx, "alice").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Manifest installed but no attestation roots or AAGUID allowlist.
    let ctx = setup(pool, false, true).await;
    assert_eq!(
        begin(&ctx, "alice").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let m = attest(&Opts::default(), &[0; 32]);
    let (st, _) = finish(&ctx, "alice", "00000000-0000-0000-0000-000000000000", &m).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn hardware_key_registers_once_and_appears_in_the_draft(pool: PgPool) {
    let ctx = setup(pool, true, true).await;
    let o = Opts::default();
    let (st, body, id, m) = register(&ctx, "alice", &o).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    assert_eq!(body["aaguid_hex"], data_encoding::HEXLOWER.encode(&AAGUID));
    assert_eq!(body["cred_id_b64url"], b64(&o.cred_id));

    // The challenge is spent.
    let (st, body) = finish(&ctx, "alice", &id, &m).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // A second key for alice with a 1-certificate chain.
    let o2 = Opts {
        intermediate: false,
        cred_seed: 22,
        cred_id: vec![0xc2; 16],
        ..Opts::default()
    };
    let (st, body, _, _) = register(&ctx, "alice", &o2).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let (_, opts) = begin(&ctx, "alice").await;
    assert_eq!(
        opts["exclude_credentials_b64url"].as_array().unwrap().len(),
        2
    );

    // Assign a client scope and export the draft.
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    let client = repo::create_client(&mut tx, "Acme").await.unwrap();
    shell::add_technician_client(&mut tx, "alice", client)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(draft(&ctx, &[]).await.0, StatusCode::FORBIDDEN);
    let (st, v) = draft(&ctx, &["RMM.Admin"]).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["seq"], 1);
    let text = serde_json::to_string_pretty(&v).unwrap();
    // Parse exactly as rmm-sign's techlist draft loader does.
    let tl: TechnicianList = serde_json::from_str(&text).unwrap();
    tl.validate().unwrap();
    to_canonical_vec(&tl).unwrap();
    assert_eq!(tl.techs.len(), 1);
    let alice = &tl.techs[0];
    assert_eq!(alice.tech_id, "alice");
    assert_eq!(alice.client_scope, vec![client.to_string()]);
    assert_eq!(alice.perms, vec!["shell".to_owned()]);
    assert_eq!(alice.creds.len(), 2);
    let c = alice
        .creds
        .iter()
        .find(|c| c.cred_id.0 == o.cred_id)
        .unwrap();
    assert_eq!(c.aaguid.0, AAGUID.to_vec());
    assert_eq!(c.alg, -7);
    assert_eq!(c.cose_pubkey.0, cose_es256(&p256(o.cred_seed)));
    assert!(tl.expires_at > tl.issued_at);

    // An audit row was written for each registration.
    let mut tx = begin_scoped(&ctx.pool, &Scope::Service("test"), "test")
        .await
        .unwrap();
    assert_eq!(
        repo::count_audit(&mut tx, "webauthn.register", "technician:alice")
            .await
            .unwrap(),
        2
    );
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn rejected_attestations_do_not_register(pool: PgPool) {
    let ctx = setup(pool, true, true).await;
    let cases = [
        Opts {
            fmt: "none",
            ..Opts::default()
        },
        Opts {
            with_x5c: false,
            ..Opts::default()
        },
        Opts {
            root_seed: 99,
            ..Opts::default()
        },
        Opts {
            aaguid: OTHER_AAGUID,
            cert_aaguid: Some(OTHER_AAGUID),
            ..Opts::default()
        },
        Opts {
            flags: 0x01 | 0x40,
            ..Opts::default()
        },
        Opts {
            origin: "https://evil.test",
            ..Opts::default()
        },
        Opts {
            leaf_validity: (-30 * DAY, -DAY),
            ..Opts::default()
        },
    ];
    for (i, o) in cases.iter().enumerate() {
        let (st, body, _, _) = register(&ctx, "mallory", o).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "case {i}: {body}");
    }
    // Wrong challenge: a valid response bound to some other challenge.
    let (_, opts) = begin(&ctx, "mallory").await;
    let m = attest(&Opts::default(), &[3u8; 32]);
    let (st, _) = finish(&ctx, "mallory", opts["challenge_id"].as_str().unwrap(), &m).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);

    let (st, v) = draft(&ctx, &["RMM.Admin"]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["techs"], json!([]), "nothing registered");
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn challenges_are_per_technician_and_expire(pool: PgPool) {
    let ctx = setup(pool, true, true).await;
    // Bob cannot use alice's challenge.
    let (_, opts) = begin(&ctx, "alice").await;
    let challenge = data_encoding::BASE64URL_NOPAD
        .decode(opts["challenge_b64url"].as_str().unwrap().as_bytes())
        .unwrap();
    let id = opts["challenge_id"].as_str().unwrap().to_owned();
    let m = attest(&Opts::default(), &challenge);
    begin(&ctx, "bob").await;
    let (st, _) = finish(&ctx, "bob", &id, &m).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);

    // Alice's challenge used after 5 minutes fails.
    sqlx::query(
        "update msp.webauthn_challenge
         set expires_at = now() - interval '1 second' where id = $1::uuid",
    )
    .bind(&id)
    .execute(&ctx.pool)
    .await
    .unwrap();
    let (st, body) = finish(&ctx, "alice", &id, &m).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body["error"].as_str().unwrap().contains("expired"));

    // Malformed input is a 400.
    let bad = Made {
        att_obj: vec![],
        client_data: vec![],
        cose: vec![],
    };
    let body = json!({"challenge_id": id, "attestation_object_b64url": "a+b=",
                      "client_data_json_b64url": b64(&bad.client_data)});
    let req = Request::post("/api/v1/technicians/me/credentials/register/finish")
        .header("authorization", token("alice", &[]))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(call(&ctx.app, req).await.0, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../rmm-db/migrations")]
async fn two_technicians_cannot_share_a_credential_id(pool: PgPool) {
    let ctx = setup(pool, true, true).await;
    let o = Opts::default();
    let (st, body, _, _) = register(&ctx, "alice", &o).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let (st, body, _, _) = register(&ctx, "bob", &o).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");

    let (_, v) = draft(&ctx, &["RMM.Admin"]).await;
    let tl: TechnicianList = serde_json::from_value(v).unwrap();
    assert_eq!(tl.techs.len(), 1);
    assert_eq!(tl.techs[0].tech_id, "alice");
}

const DEV_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnwjZGao2uARmrdBW/iGXPrOmw0RZoMXO2hiNqo3Moq61Byvo
OuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXNC80T/sH28J4XX2+IRFpF8ohQyBN8
N6zfoU+iUzRi+r0S63Gh81s2ySEJ2foLkLpPeHEgIQoMbDWH88oPIl76kZfW4rl4
KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMmbwAqtn4x3KrazWuBMAM5PUyVpG8A
Se29uGszpsaifMVqICFmc+hjYZ8fQiwCxD1kVXKoEi3x+tP+S06CBQ7ab5OmWJi0
HT0spk0KPoelLvsK0KwCiPHPxS7J/uqU2aJaXwIDAQABAoIBABe5qTGz+//N4EeT
6jZ1amvXP0yoOLrMZ8SPnyrPhrTKXYVZXobSM50h+Y5ALZQz1WuedMr3xB/Fm+Pv
H3IrzVAyYwZBh4Zz/0aki+6ujPrWrT578a8YojAdgjjpes6vQFBRnniAphaxUBft
vqXztYFhVwq2xg2qmsKa5VEaXEU15nqi0EtYe5+VzZbOMI2NRJ2j5lW12S3yUo58
FbsTYbcoP5gXX1UKyq5qxRe8L8tt/OMyLyfujrOzN7UTVor1pNXDprhxPeOziZjP
kyXCYVb67rz+2KZMrYdD5a19j2MoxTzh+9y8X22kYUeOnhvCvjczEfs9jnulO0p/
kF6YCPECgYEA04Y1RV+RZxXDRJV+J6Yb/XpEMULmA9uM86XdsblRj29bk0AAgTNt
3oF7NdweSfJPpfY9RqaSQIFcRLURvb+zkycEfj5ippAeoLjNhMNY+gL4kSIhmQFU
nguv8ugeCP5OowdE0CfFSlXEa5mnKKMDh75WhY3Dw4RNUMhrThCSzscCgYEAwHlC
N39LvthIJr2fy44n5cPQ1TBLMAgdFrtwOF2yPQr0kFT5+VY0sUY3/6Scpz6v8oDk
6yYZ4cEngmd7CX4yfxbYWEzGUxbaFnj/6sM91Kv3Yw5hTCQC+xNOGO9ZKgeqcGH5
kAv69NOCtEYKoArOOHml66BOwkCgWxUQatYkX6kCgYEA0pQdnH7T5mhICZM6EIbR
/rsmAFS1YMnFvRo3ZqMzizQ1Wpaw6e8lRgppeuk0TjGpEXPe9OMHXqhqDwykKN8c
Czcgxf2dgGyh0Sepkq5Xei5S/0mXYRduAhlohM6IeDOUXcDyxLeTNbnE3coOG+qN
rSnUQQktBwxDXFTqXsEpJikCgYBFuuiJcJ3Be1vQZTyCI3NC44lB4ygqM5ZOSQPj
99X+FXz62T5i3Z9jZhwdisaSNLzLr3S/2GLiDfdBYDoL+2NR9bXVb6MeMRY7tASL
ScaZyN9sTKZlTlqiGaFemUAFYReXdXdTf3OgxQwCQanRx3hkr3W0ArTl3UH7HYuA
GSq+WQKBgDkV2DcRKvDK1RIlEPYSyXnP3V0xQ5j3s/xZbfqzqMq2SYYbPA3r23Ty
kj4UNoQqBmzJ5CVUWUx6MLTqX3IFCJErSXbfjiD6CSWl6rObT4VUOoeg9Qho2MBJ
SWf9oefLMwUqfemP0ZQM+bJ2VQMG5rll3zGtfkOS6T0JN70mQNIs
-----END RSA PRIVATE KEY-----
";
const DEV_PUB: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnwjZGao2uARmrdBW/iGX
PrOmw0RZoMXO2hiNqo3Moq61ByvoOuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXN
C80T/sH28J4XX2+IRFpF8ohQyBN8N6zfoU+iUzRi+r0S63Gh81s2ySEJ2foLkLpP
eHEgIQoMbDWH88oPIl76kZfW4rl4KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMm
bwAqtn4x3KrazWuBMAM5PUyVpG8ASe29uGszpsaifMVqICFmc+hjYZ8fQiwCxD1k
VXKoEi3x+tP+S06CBQ7ab5OmWJi0HT0spk0KPoelLvsK0KwCiPHPxS7J/uqU2aJa
XwIDAQAB
-----END PUBLIC KEY-----
";
