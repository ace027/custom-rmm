//! ReleaseManifest validation, round trip and role-checked verification.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{
    Cert, ReleaseArtifact, ReleaseManifest, Role, TrustManifest, decode_doc, verify_release,
};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_MANIFEST, TYPE_RELEASE, signing_message,
};
use rmm_trust::error::TrustError;
use rmm_trust::keys::{Bytes, PublicKey, Sig64};
use rmm_trust::verify::{FixedClock, MemorySeqStore, TrustStore};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(k: &SigningKey) -> PublicKey {
    PublicKey::from_bytes(&k.verifying_key().to_bytes()).unwrap()
}

fn sign(type_: &str, payload: Vec<u8>, signer: &SigningKey) -> Vec<u8> {
    let msg = signing_message(type_, &payload);
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: type_.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: public(signer).key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(signer.sign(&msg).to_bytes()),
        }],
    }
    .to_bytes()
    .unwrap()
}

const ROOT: u8 = 1;
const RELEASE: u8 = 2;
const CATALOG: u8 = 3;

fn installed_store() -> TrustStore {
    let cert = |seed: u8, roles: Vec<Role>| Cert {
        key_id: public(&key(seed)).key_id(),
        pubkey: Bytes(public(&key(seed)).to_bytes().to_vec()),
        alg: ALG_ED25519.to_owned(),
        roles,
        not_before: NOW - DAY,
        not_after: NOW + 365 * DAY,
        label: "k".into(),
    };
    let doc = TrustManifest {
        seq: 1,
        issued_at: NOW - 10,
        expires_at: NOW + 100 * DAY,
        root_keys: vec![Bytes(public(&key(ROOT)).to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![
            cert(RELEASE, vec![Role::Release]),
            cert(CATALOG, vec![Role::Catalog]),
        ],
        thresholds: BTreeMap::from([(Role::Release, 1), (Role::Catalog, 1)]),
        revoked_keys: vec![],
        console_rp_id: "rmm.example".into(),
        console_origins: vec!["https://rmm.example".into()],
        capability_ceiling: vec![],
        revocation_mirrors: vec![],
    };
    let env = sign(TYPE_MANIFEST, to_canonical_vec(&doc).unwrap(), &key(ROOT));
    let mut store = TrustStore::new(vec![public(&key(ROOT))], 1);
    store
        .apply_manifest(&env, &FixedClock(NOW), &mut MemorySeqStore::new())
        .unwrap();
    store
}

fn artifact(platform: &str) -> ReleaseArtifact {
    ReleaseArtifact {
        platform: platform.into(),
        sha256: Bytes(vec![0xab; 32]),
        size: 1234,
        name: "rmm-agent.exe".into(),
    }
}

fn release() -> ReleaseManifest {
    ReleaseManifest {
        seq: 1,
        version: "1.2.3".into(),
        issued_at: NOW - 10,
        expires_at: NOW + 30 * DAY,
        artifacts: vec![artifact("windows-x86_64"), artifact("linux-x86_64")],
    }
}

fn rejects(edit: impl FnOnce(&mut ReleaseManifest)) {
    let mut r = release();
    edit(&mut r);
    assert!(
        matches!(r.validate(), Err(TrustError::InvalidDocument(_))),
        "{r:?} should be invalid"
    );
}

#[test]
fn valid_release_passes_and_round_trips() {
    let r = release();
    r.validate().unwrap();
    let payload = to_canonical_vec(&r).unwrap();
    let back: ReleaseManifest = decode_doc(&payload).unwrap();
    assert_eq!(back, r);
    assert_eq!(
        back.artifact_for("linux-x86_64").unwrap().platform,
        "linux-x86_64"
    );
    assert!(back.artifact_for("macos-arm64").is_none());
}

#[test]
fn unknown_field_is_rejected() {
    let mut v = serde_json::to_value(release()).unwrap();
    v["extra"] = 1.into();
    assert!(serde_json::from_value::<ReleaseManifest>(v).is_err());
}

#[test]
fn bad_semver_is_rejected() {
    for v in [
        "", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.x", "v1.2.3", "1.2.3-", "1.2.3-01",
    ] {
        rejects(|r| r.version = v.into());
    }
    for v in ["0.1.0", "1.2.3-rc.1", "1.2.3+build.5", "1.0.0-alpha-1+x"] {
        let mut r = release();
        r.version = v.into();
        r.validate().unwrap_or_else(|e| panic!("{v}: {e}"));
    }
}

#[test]
fn structural_rejections() {
    rejects(|r| r.artifacts.clear());
    rejects(|r| r.artifacts[1].platform = "windows-x86_64".into());
    rejects(|r| r.artifacts[0].sha256 = Bytes(vec![1; 31]));
    rejects(|r| r.artifacts[0].sha256 = Bytes(vec![1; 33]));
    rejects(|r| r.artifacts[0].size = 0);
    rejects(|r| r.artifacts[0].size = 268_435_457);
    rejects(|r| r.artifacts[0].name = "../evil".into());
    rejects(|r| r.expires_at = r.issued_at);
    let mut max = release();
    max.artifacts[0].size = 268_435_456;
    max.validate().unwrap();
}

#[test]
fn release_role_signature_verifies() {
    let store = installed_store();
    let env = sign(
        TYPE_RELEASE,
        to_canonical_vec(&release()).unwrap(),
        &key(RELEASE),
    );
    let (_, doc) = verify_release(&store, &env, NOW).unwrap();
    assert_eq!(doc, release());
}

#[test]
fn catalog_key_cannot_sign_a_release() {
    let store = installed_store();
    let env = sign(
        TYPE_RELEASE,
        to_canonical_vec(&release()).unwrap(),
        &key(CATALOG),
    );
    assert_eq!(
        verify_release(&store, &env, NOW).unwrap_err(),
        TrustError::WrongRole
    );
}

#[test]
fn wrong_type_expired_and_invalid_documents_are_refused() {
    let store = installed_store();
    let payload = to_canonical_vec(&release()).unwrap();
    let wrong = sign("rmm.techlist/1", payload.clone(), &key(RELEASE));
    assert_eq!(
        verify_release(&store, &wrong, NOW).unwrap_err(),
        TrustError::WrongType
    );
    let env = sign(TYPE_RELEASE, payload, &key(RELEASE));
    assert_eq!(
        verify_release(&store, &env, NOW + 31 * DAY).unwrap_err(),
        TrustError::Expired
    );
    let mut bad = release();
    bad.artifacts.clear();
    let env = sign(TYPE_RELEASE, to_canonical_vec(&bad).unwrap(), &key(RELEASE));
    assert!(matches!(
        verify_release(&store, &env, NOW),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn release_without_manifest_is_refused() {
    let store = TrustStore::new(vec![public(&key(ROOT))], 1);
    let env = sign(
        TYPE_RELEASE,
        to_canonical_vec(&release()).unwrap(),
        &key(RELEASE),
    );
    assert_eq!(
        verify_release(&store, &env, NOW).unwrap_err(),
        TrustError::NoManifest
    );
}
