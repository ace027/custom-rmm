//! The periodic refresh logic against an in-memory trust state (no NATS): a
//! newer technician list replaces the cached one and reaches the shell
//! manager hook, an older one is ignored, and only releases signed with the
//! release role are handed on.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use rmm_agent_core::commands::Agent;
use rmm_agent_core::refresh::{apply_trust_latest, offer_release, verify_release_latest};
use rmm_agent_core::store::{STORE_KEY_FILE, Store};
use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{
    ArtifactRevocations, Cert, Credential, ReleaseArtifact, ReleaseLatest, ReleaseManifest, Role,
    Technician, TechnicianList, TrustLatest, TrustManifest,
};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_MANIFEST, TYPE_RELEASE,
    TYPE_REVOCATIONS, TYPE_TECHLIST, signing_message,
};
use rmm_trust::keys::{Bytes, KeyId, PublicKey, Sig64};
use rmm_trust::verify::{DocKind, FixedClock, SeqStore};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const ROOT: u8 = 1;
const TECH: u8 = 2;
const REL: u8 = 3;
const CAT: u8 = 4;
const REVOKE: u8 = 5;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmm-refresh-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
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

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&key(seed).verifying_key().to_bytes()).unwrap()
}

fn sign(type_: &str, payload: Vec<u8>, seed: u8) -> Vec<u8> {
    let msg = signing_message(type_, &payload);
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: type_.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: public(seed).key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(key(seed).sign(&msg).to_bytes()),
        }],
    }
    .to_bytes()
    .unwrap()
}

fn manifest() -> Vec<u8> {
    let cert = |seed: u8, roles: Vec<Role>| Cert {
        key_id: public(seed).key_id(),
        pubkey: Bytes(public(seed).to_bytes().to_vec()),
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
        root_keys: vec![Bytes(public(ROOT).to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![
            cert(TECH, vec![Role::Techlist]),
            cert(REL, vec![Role::Release]),
            cert(CAT, vec![Role::Catalog]),
            cert(REVOKE, vec![Role::ArtifactRevoke]),
        ],
        thresholds: BTreeMap::from([
            (Role::Techlist, 1),
            (Role::Release, 1),
            (Role::Catalog, 1),
            (Role::ArtifactRevoke, 1),
        ]),
        revoked_keys: vec![],
        console_rp_id: "rmm.example".into(),
        console_origins: vec!["https://rmm.example".into()],
        capability_ceiling: vec![],
        revocation_mirrors: vec![],
    };
    sign(TYPE_MANIFEST, to_canonical_vec(&doc).unwrap(), ROOT)
}

fn techlist(seq: u64, tech: &str) -> Vec<u8> {
    let doc = TechnicianList {
        seq,
        issued_at: NOW - 10,
        expires_at: NOW + 30 * DAY,
        techs: vec![Technician {
            tech_id: tech.into(),
            client_scope: vec!["*".into()],
            perms: vec!["shell".into()],
            creds: vec![Credential {
                cred_id: Bytes(vec![1; 8]),
                alg: -7,
                cose_pubkey: Bytes(vec![0xa5]),
                aaguid: Bytes(vec![2; 16]),
            }],
        }],
    };
    sign(TYPE_TECHLIST, to_canonical_vec(&doc).unwrap(), TECH)
}

fn release(seq: u64, signer: u8) -> Vec<u8> {
    let doc = ReleaseManifest {
        seq,
        version: "1.2.3".into(),
        issued_at: NOW - 10,
        expires_at: NOW + 30 * DAY,
        artifacts: vec![ReleaseArtifact {
            platform: "linux-x86_64".into(),
            sha256: Bytes(vec![9; 32]),
            size: 100,
            name: "rmm-agent".into(),
        }],
    };
    sign(TYPE_RELEASE, to_canonical_vec(&doc).unwrap(), signer)
}

fn agent() -> Agent {
    Agent::new("agent-1", "client-1", [0x55; 32], vec![public(ROOT)], 1)
}

/// A store as after enrollment: the manifest is cached.
fn store(dir: &Path) -> Store {
    let k = rmm_platform::keystore_named(dir, STORE_KEY_FILE);
    let store = Store::open(dir, k.as_ref()).unwrap();
    store.trust_put(DocKind::Manifest, &manifest()).unwrap();
    store
}

fn reply_trust(techlist: Option<Vec<u8>>) -> Vec<u8> {
    to_canonical_vec(&TrustLatest {
        manifest: None,
        revocations: None,
        techlist: techlist.map(Bytes),
    })
    .unwrap()
}

fn reply_release(env: Option<Vec<u8>>) -> Vec<u8> {
    to_canonical_vec(&ReleaseLatest {
        release: env.map(Bytes),
    })
    .unwrap()
}

/// Seq of the techlist the hook was called with, in order.
fn apply(store: &Store, payload: &[u8]) -> (Result<(), ()>, Vec<u64>) {
    let seen = RefCell::new(Vec::new());
    let hook = |l: &TechnicianList| seen.borrow_mut().push(l.seq);
    let r = apply_trust_latest(payload, &agent(), store, &FixedClock(NOW), &hook).map_err(|_| ());
    (r, seen.into_inner())
}

fn cached_techlist_seq(store: &Store) -> Option<u64> {
    let s = store;
    s.get(DocKind::Techlist).map(|(seq, _)| seq)
}

#[test]
fn newer_techlist_replaces_the_cached_one_and_calls_the_hook() {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    let v1 = techlist(1, "alice");
    let v2 = techlist(2, "bob");

    let (r, seen) = apply(&store, &reply_trust(Some(v1.clone())));
    assert!(r.is_ok());
    assert_eq!(seen, vec![1]);
    assert_eq!(store.trust_get(DocKind::Techlist).unwrap(), Some(v1));

    let (r, seen) = apply(&store, &reply_trust(Some(v2.clone())));
    assert!(r.is_ok());
    assert_eq!(seen, vec![2], "the shell manager hears about the new list");
    assert_eq!(store.trust_get(DocKind::Techlist).unwrap(), Some(v2));
    assert_eq!(cached_techlist_seq(&store), Some(2));
}

#[test]
fn identical_and_empty_replies_change_nothing() {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    let v1 = techlist(1, "alice");
    assert!(apply(&store, &reply_trust(Some(v1.clone()))).0.is_ok());

    let (r, seen) = apply(&store, &reply_trust(Some(v1.clone())));
    assert!(r.is_ok());
    assert!(seen.is_empty(), "an unchanged list is not re-applied");
    let (r, seen) = apply(&store, &reply_trust(None));
    assert!(r.is_ok());
    assert!(seen.is_empty());
    assert_eq!(store.trust_get(DocKind::Techlist).unwrap(), Some(v1));
}

#[test]
fn older_techlist_is_ignored() {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    let v2 = techlist(2, "bob");
    assert!(apply(&store, &reply_trust(Some(v2.clone()))).0.is_ok());

    let (r, _) = apply(&store, &reply_trust(Some(techlist(1, "alice"))));
    assert!(r.is_err(), "rollback is refused");
    assert_eq!(store.trust_get(DocKind::Techlist).unwrap(), Some(v2));
    assert_eq!(cached_techlist_seq(&store), Some(2));
}

#[test]
fn techlist_signed_by_the_wrong_role_is_refused() {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    let doc = TechnicianList {
        seq: 1,
        issued_at: NOW - 10,
        expires_at: NOW + DAY,
        techs: vec![],
    };
    let forged = sign(TYPE_TECHLIST, to_canonical_vec(&doc).unwrap(), CAT);
    let (r, _) = apply(&store, &reply_trust(Some(forged)));
    assert!(r.is_err());
    assert_eq!(store.trust_get(DocKind::Techlist).unwrap(), None);
}

#[test]
fn garbage_reply_is_not_fatal() {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    assert!(apply(&store, b"\xff\x00garbage").0.is_err());
    assert!(
        verify_release_latest(b"\xff\x00garbage", &agent(), &store, &FixedClock(NOW)).is_none()
    );
}

#[test]
fn release_signed_by_the_wrong_role_is_dropped() {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    let got = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&got);
    let cb = move |r: ReleaseManifest| sink.lock().unwrap().push(r);

    let bad = reply_release(Some(release(1, CAT)));
    assert!(!offer_release(
        &bad,
        &agent(),
        &store,
        &FixedClock(NOW),
        Some(&cb)
    ));
    let none = reply_release(None);
    assert!(!offer_release(
        &none,
        &agent(),
        &store,
        &FixedClock(NOW),
        Some(&cb)
    ));
    assert!(got.lock().unwrap().is_empty());
}

#[test]
fn callback_receives_a_valid_release() {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    let got = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&got);
    let cb = move |r: ReleaseManifest| sink.lock().unwrap().push(r);

    let good = reply_release(Some(release(7, REL)));
    assert!(offer_release(
        &good,
        &agent(),
        &store,
        &FixedClock(NOW),
        Some(&cb)
    ));
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].seq, 7);
    assert_eq!(got[0].version, "1.2.3");
}

#[test]
fn release_without_a_cached_manifest_is_dropped() {
    let tmp = TempDir::new();
    let k = rmm_platform::keystore_named(tmp.path(), STORE_KEY_FILE);
    let store = Store::open(tmp.path(), k.as_ref()).unwrap();
    let good = reply_release(Some(release(1, REL)));
    assert!(verify_release_latest(&good, &agent(), &store, &FixedClock(NOW)).is_none());
}

fn revocations(hash: [u8; 32]) -> Vec<u8> {
    let doc = ArtifactRevocations {
        seq: 1,
        issued_at: NOW - 10,
        expires_at: NOW + DAY,
        revoked_hashes: vec![KeyId(hash)],
    };
    sign(TYPE_REVOCATIONS, to_canonical_vec(&doc).unwrap(), REVOKE)
}

/// Offer `rel` to a store holding a revocation list that revokes `hash`.
fn offered_with_revoked(rel: &[u8], hash: [u8; 32]) -> bool {
    let tmp = TempDir::new();
    let store = store(tmp.path());
    store
        .trust_put(DocKind::Revocations, &revocations(hash))
        .unwrap();
    let reply = reply_release(Some(rel.to_vec()));
    verify_release_latest(&reply, &agent(), &store, &FixedClock(NOW)).is_some()
}

#[test]
fn release_with_a_revoked_artifact_hash_is_dropped() {
    let rel = release(1, REL);
    assert!(!offered_with_revoked(&rel, [9; 32]));
}

#[test]
fn release_with_a_revoked_envelope_is_dropped() {
    let rel = release(1, REL);
    let id = Envelope::from_bytes(&rel).unwrap().content_id();
    assert!(!offered_with_revoked(&rel, id));
}

#[test]
fn unrelated_revocation_leaves_the_release_accepted() {
    assert!(offered_with_revoked(&release(1, REL), [0x42; 32]));
}
