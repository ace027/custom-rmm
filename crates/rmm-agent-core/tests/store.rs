//! Encrypted store: encryption at rest, tamper detection, queue bounds and
//! trust rollback protection across restarts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use ed25519_dalek::{Signer as _, SigningKey};
use rmm_agent_core::store::{
    DB_FILE, Limits, MAX_OUTBOX_BYTES, MAX_OUTBOX_ROWS, STORE_KEY_FILE, Store, StoreError,
};
use rmm_platform::{KeyStore, keystore_named};
use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{Cert, Role, TrustManifest};
use rmm_trust::envelope::TYPE_MANIFEST;
use rmm_trust::envelope::{ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, signing_message};
use rmm_trust::error::TrustError;
use rmm_trust::keys::Bytes;
use rmm_trust::keys::{KeyId, PublicKey, Sig64};
use rmm_trust::verify::{DocKind, FixedClock, ReplayCache, SeqStore, TrustStore};
use rusqlite::{Connection, params};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const FAR_FUTURE: u64 = 4_000_000_000;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmm-store-test-{}-{}",
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

fn keys(dir: &Path) -> Box<dyn KeyStore> {
    keystore_named(dir, STORE_KEY_FILE)
}

fn open(dir: &Path) -> Store {
    Store::open(dir, keys(dir).as_ref()).expect("open store")
}

fn open_limited(dir: &Path, max_rows: u64, max_bytes: u64) -> Store {
    Store::open_with_limits(
        dir,
        keys(dir).as_ref(),
        Limits {
            max_rows,
            max_bytes,
        },
    )
    .expect("open store")
}

fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

fn raw(dir: &Path) -> Connection {
    Connection::open(dir.join(DB_FILE)).expect("raw connection")
}

fn msg_ids(items: &[rmm_agent_core::store::OutboxItem]) -> Vec<u8> {
    items.iter().map(|i| i.msg_id[0]).collect()
}

/// Test-only signer: the `sign` feature of rmm-trust must not reach the agent
/// crate graph (scripts/check-layering.sh), so envelopes are signed directly.
struct TestSigner(SigningKey);

impl TestSigner {
    fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(&self.0.verifying_key().to_bytes()).expect("valid key")
    }

    fn key_id(&self) -> KeyId {
        self.public_key().key_id()
    }
}

fn sign_envelope(type_: &str, payload: Vec<u8>, signer: &TestSigner) -> Envelope {
    let sig = signer.0.sign(&signing_message(type_, &payload)).to_bytes();
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: type_.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: signer.key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(sig),
        }],
    }
}

fn manifest_bytes(seq: u64) -> Vec<u8> {
    let root = TestSigner::from_seed(&[0xa1; 32]);
    let signer = TestSigner::from_seed(&[0x51; 32]);
    let doc = TrustManifest {
        seq,
        issued_at: NOW - 10,
        expires_at: NOW + 365 * DAY,
        root_keys: vec![Bytes(root.public_key().to_bytes().to_vec())],
        root_threshold: 1,
        certs: vec![Cert {
            key_id: signer.key_id(),
            pubkey: Bytes(signer.public_key().to_bytes().to_vec()),
            alg: "ed25519".into(),
            roles: vec![Role::Techlist],
            not_before: NOW - DAY,
            not_after: NOW + 730 * DAY,
            label: "k".into(),
        }],
        thresholds: BTreeMap::from([(Role::Techlist, 1)]),
        revoked_keys: vec![],
        console_rp_id: "rmm.example.com".into(),
        console_origins: vec!["https://rmm.example.com".into()],
        capability_ceiling: vec![],
        revocation_mirrors: vec![],
    };
    sign_envelope(
        TYPE_MANIFEST,
        to_canonical_vec(&doc).expect("encode"),
        &root,
    )
    .to_bytes()
    .expect("envelope")
}

fn trust_store() -> TrustStore {
    let root = TestSigner::from_seed(&[0xa1; 32]);
    TrustStore::new(vec![root.public_key()], 1)
}

#[test]
fn store_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<Store>();
    assert_eq!(MAX_OUTBOX_ROWS, 50_000);
    assert_eq!(MAX_OUTBOX_BYTES, 64 * 1024 * 1024);
}

#[test]
fn first_open_creates_store_key_and_db() {
    let tmp = TempDir::new();
    assert_eq!(keys(tmp.path()).load().expect("load"), None);
    let _store = open(tmp.path());
    assert!(keys(tmp.path()).load().expect("load").is_some());
    assert!(tmp.path().join(DB_FILE).exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for name in [DB_FILE, STORE_KEY_FILE] {
            let mode = std::fs::metadata(tmp.path().join(name))
                .expect("stat")
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }
}

#[test]
fn outbox_trust_and_policy_round_trip() {
    let tmp = TempDir::new();
    let store = open(tmp.path());
    assert!(
        store
            .outbox_push(id(1), "telemetry.a", 2, b"payload-1")
            .expect("push")
    );
    let items = store.outbox_peek(10).expect("peek");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].msg_id, id(1));
    assert_eq!(items[0].subject, "telemetry.a");
    assert_eq!(items[0].priority, 2);
    assert_eq!(items[0].payload, b"payload-1");
    assert_eq!(store.outbox_len().expect("len"), 1);
    store.outbox_delete(items[0].seq).expect("delete");
    store
        .outbox_delete(items[0].seq)
        .expect("delete is idempotent");
    assert_eq!(store.outbox_len().expect("len"), 0);

    assert_eq!(store.trust_get(DocKind::Manifest).expect("get"), None);
    store.trust_put(DocKind::Manifest, b"env-1").expect("put");
    store
        .trust_put(DocKind::Manifest, b"env-2")
        .expect("replace");
    assert_eq!(
        store.trust_get(DocKind::Manifest).expect("get"),
        Some(b"env-2".to_vec())
    );
    assert_eq!(store.trust_get(DocKind::Techlist).expect("get"), None);

    assert_eq!(store.policy_get("p").expect("get"), None);
    store.policy_put("p", b"v1").expect("put");
    store.policy_put("p", b"v2").expect("replace");
    assert_eq!(store.policy_get("p").expect("get"), Some(b"v2".to_vec()));
}

#[test]
fn database_bytes_hold_no_plaintext() {
    let tmp = TempDir::new();
    let marker = b"PLAINTEXT-MARKER-0123456789";
    {
        let store = open(tmp.path());
        store.outbox_push(id(1), "s", 1, marker).expect("push");
        store.trust_put(DocKind::Manifest, marker).expect("trust");
        store.policy_put("k", marker).expect("policy");
        // Look at the main file and the WAL while the store is still open.
        for entry in std::fs::read_dir(tmp.path()).expect("read dir") {
            let path = entry.expect("entry").path();
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .to_string();
            if name.starts_with(DB_FILE) {
                let bytes = std::fs::read(&path).expect("read db file");
                assert!(
                    !bytes.windows(marker.len()).any(|w| w == marker),
                    "{name} contains plaintext"
                );
            }
        }
    }
}

#[test]
fn different_store_key_fails_on_read() {
    let tmp = TempDir::new();
    {
        let store = open(tmp.path());
        store.outbox_push(id(1), "s", 1, b"x").expect("push");
        store.trust_put(DocKind::Manifest, b"m").expect("trust");
        store.policy_put("k", b"v").expect("policy");
    }
    keys(tmp.path()).store(&[7; 32]).expect("swap key");
    let store = open(tmp.path());
    assert!(matches!(store.outbox_peek(1), Err(StoreError::Decrypt)));
    assert!(matches!(
        store.trust_get(DocKind::Manifest),
        Err(StoreError::Decrypt)
    ));
    assert!(matches!(store.policy_get("k"), Err(StoreError::Decrypt)));
}

#[test]
fn flipped_ciphertext_byte_fails() {
    let tmp = TempDir::new();
    let store = open(tmp.path());
    store
        .outbox_push(id(1), "s", 1, b"hello world")
        .expect("push");
    let conn = raw(tmp.path());
    let mut blob: Vec<u8> = conn
        .query_row("SELECT payload FROM outbox", [], |r| r.get(0))
        .expect("blob");
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    conn.execute("UPDATE outbox SET payload = ?1", params![blob])
        .expect("tamper");
    assert!(matches!(store.outbox_peek(1), Err(StoreError::Decrypt)));
}

#[test]
fn copying_a_blob_into_another_row_fails() {
    let tmp = TempDir::new();
    let store = open(tmp.path());
    store.outbox_push(id(1), "s", 1, b"first").expect("push");
    store.outbox_push(id(2), "s", 1, b"second").expect("push");
    assert_eq!(store.outbox_peek(10).expect("peek").len(), 2);
    let conn = raw(tmp.path());
    conn.execute(
        "UPDATE outbox SET payload = (SELECT payload FROM outbox WHERE msg_id = ?1)
         WHERE msg_id = ?2",
        params![&id(1)[..], &id(2)[..]],
    )
    .expect("copy");
    assert!(matches!(store.outbox_peek(10), Err(StoreError::Decrypt)));

    store.policy_put("a", b"va").expect("put");
    store.policy_put("b", b"vb").expect("put");
    conn.execute(
        "UPDATE policy SET value = (SELECT value FROM policy WHERE key = 'a') WHERE key = 'b'",
        [],
    )
    .expect("copy");
    assert_eq!(store.policy_get("a").expect("a"), Some(b"va".to_vec()));
    assert!(matches!(store.policy_get("b"), Err(StoreError::Decrypt)));
}

#[test]
fn missing_store_key_with_existing_db_errors() {
    let tmp = TempDir::new();
    {
        let store = open(tmp.path());
        store.outbox_push(id(1), "s", 1, b"x").expect("push");
    }
    let ks = keys(tmp.path());
    ks.delete().expect("delete key");
    let err = Store::open(tmp.path(), ks.as_ref()).expect_err("must not start a new store");
    assert!(matches!(err, StoreError::MissingKey), "{err}");
    assert_eq!(ks.load().expect("load"), None, "no key was created");
}

#[test]
fn outbox_drains_by_priority_then_seq() {
    let tmp = TempDir::new();
    let store = open(tmp.path());
    for (n, prio) in [(1, 2), (2, 1), (3, 2), (4, 1), (5, 0)] {
        store.outbox_push(id(n), "s", prio, b"x").expect("push");
    }
    assert_eq!(
        msg_ids(&store.outbox_peek(10).expect("peek")),
        vec![5, 2, 4, 1, 3]
    );
    assert_eq!(msg_ids(&store.outbox_peek(2).expect("peek")), vec![5, 2]);
}

#[test]
fn row_bound_drops_oldest_priority_2_and_keeps_priority_0() {
    let tmp = TempDir::new();
    let store = open_limited(tmp.path(), 3, u64::MAX / 2);
    for n in 1..=3 {
        assert!(store.outbox_push(id(n), "s", 2, b"x").expect("push"));
    }
    assert!(store.outbox_push(id(4), "s", 0, b"x").expect("push"));
    assert_eq!(
        msg_ids(&store.outbox_peek(10).expect("peek")),
        vec![4, 2, 3]
    );
    assert_eq!(store.dropped_count(), 1);

    for n in 5..=7 {
        assert!(store.outbox_push(id(n), "s", 0, b"x").expect("push"));
    }
    // Only priority 0 is left: it exceeds the bound instead of being dropped.
    let left = store.outbox_peek(10).expect("peek");
    assert_eq!(msg_ids(&left), vec![4, 5, 6, 7]);
    assert!(left.iter().all(|i| i.priority == 0));
    assert_eq!(store.dropped_count(), 3);

    // A new low-priority message is itself dropped when nothing can make room.
    assert!(!store.outbox_push(id(8), "s", 2, b"x").expect("push"));
    assert_eq!(store.outbox_len().expect("len"), 4);
    assert_eq!(store.dropped_count(), 4);
}

#[test]
fn bound_drops_priority_2_before_priority_1_and_never_for_lower_importance() {
    let tmp = TempDir::new();
    let store = open_limited(tmp.path(), 2, u64::MAX / 2);
    assert!(store.outbox_push(id(1), "s", 1, b"x").expect("push"));
    assert!(store.outbox_push(id(2), "s", 2, b"x").expect("push"));
    // A newer priority-1 row evicts the priority-2 row, not the older priority-1.
    assert!(store.outbox_push(id(3), "s", 1, b"x").expect("push"));
    assert_eq!(msg_ids(&store.outbox_peek(10).expect("peek")), vec![1, 3]);
    // A priority-2 row cannot displace priority-1 rows; it is dropped.
    assert!(!store.outbox_push(id(4), "s", 2, b"x").expect("push"));
    assert_eq!(msg_ids(&store.outbox_peek(10).expect("peek")), vec![1, 3]);
}

#[test]
fn byte_bound_drops_oldest_priority_2() {
    let tmp = TempDir::new();
    // Each 50-byte payload is stored as 50 + 24 (nonce) + 16 (tag) = 90 bytes.
    let store = open_limited(tmp.path(), 1000, 200);
    for n in 1..=3 {
        assert!(store.outbox_push(id(n), "s", 2, &[n; 50]).expect("push"));
    }
    let left = store.outbox_peek(10).expect("peek");
    assert_eq!(msg_ids(&left), vec![2, 3]);
    assert_eq!(left[0].payload, vec![2; 50]);
    assert_eq!(store.dropped_count(), 1);
}

#[test]
fn duplicate_msg_id_is_a_noop() {
    let tmp = TempDir::new();
    let store = open(tmp.path());
    assert!(store.outbox_push(id(1), "s", 1, b"first").expect("push"));
    assert!(
        store
            .outbox_push(id(1), "other", 0, b"second")
            .expect("dup")
    );
    let items = store.outbox_peek(10).expect("peek");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].payload, b"first");
    assert_eq!(items[0].subject, "s");
    assert_eq!(items[0].priority, 1);
}

#[test]
fn committed_rows_survive_a_crash() {
    let tmp = TempDir::new();
    let store = open(tmp.path());
    for n in 1..=3 {
        store.outbox_push(id(n), "s", 1, &[n]).expect("push");
    }
    store.trust_put(DocKind::Techlist, b"t").expect("trust");
    // No orderly shutdown: the connection is never closed or checkpointed.
    std::mem::forget(store);
    let again = open(tmp.path());
    assert_eq!(
        msg_ids(&again.outbox_peek(10).expect("peek")),
        vec![1, 2, 3]
    );
    assert_eq!(
        again.trust_get(DocKind::Techlist).expect("trust"),
        Some(b"t".to_vec())
    );
}

#[test]
fn seq_floor_rejects_rollback_after_restart() {
    let tmp = TempDir::new();
    {
        let mut store = open(tmp.path());
        trust_store()
            .apply_manifest(&manifest_bytes(5), &FixedClock(NOW), &mut store)
            .expect("manifest 5");
        assert!(!store.seq_write_failed());
    }
    let mut store = open(tmp.path());
    assert_eq!(store.get(DocKind::Manifest).map(|f| f.0), Some(5));
    assert_eq!(store.get(DocKind::Techlist), None);
    // A fresh TrustStore, as after an agent restart.
    let err = trust_store()
        .apply_manifest(&manifest_bytes(4), &FixedClock(NOW), &mut store)
        .expect_err("rollback");
    assert_eq!(err, TrustError::Rollback { stored: 5, got: 4 });
    trust_store()
        .apply_manifest(&manifest_bytes(5), &FixedClock(NOW), &mut store)
        .expect("same document again");
    trust_store()
        .apply_manifest(&manifest_bytes(6), &FixedClock(NOW), &mut store)
        .expect("newer document");
    assert_eq!(store.get(DocKind::Manifest).map(|f| f.0), Some(6));
}

#[test]
fn edited_seq_floor_fails_closed() {
    let tmp = TempDir::new();
    {
        let mut store = open(tmp.path());
        trust_store()
            .apply_manifest(&manifest_bytes(5), &FixedClock(NOW), &mut store)
            .expect("manifest 5");
    }
    raw(tmp.path())
        .execute("UPDATE seq_floor SET seq = 1", [])
        .expect("tamper");
    let mut store = open(tmp.path());
    let err = trust_store()
        .apply_manifest(&manifest_bytes(6), &FixedClock(NOW), &mut store)
        .expect_err("tampered floor must not lower the bar");
    assert!(matches!(err, TrustError::Rollback { .. }), "{err:?}");
}

#[test]
fn replay_cache_detects_repeats_across_restart() {
    let tmp = TempDir::new();
    {
        let mut store = open(tmp.path());
        assert!(!store.seen(b"cmd-1", FAR_FUTURE));
        assert!(store.seen(b"cmd-1", FAR_FUTURE));
        assert!(!store.seen(b"cmd-2", FAR_FUTURE));
    }
    let mut store = open(tmp.path());
    assert!(store.seen(b"cmd-1", FAR_FUTURE));
    assert!(store.seen(b"cmd-2", FAR_FUTURE));
    assert!(!store.seen(b"cmd-3", FAR_FUTURE));
    // The table keys on a hash, never on the raw command id.
    let n: i64 = raw(tmp.path())
        .query_row(
            "SELECT COUNT(*) FROM replay WHERE length(cmd_id_hash) = 32",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 3);
}

#[test]
fn replay_cache_prunes_expired_entries_on_insert() {
    let tmp = TempDir::new();
    let mut store = open(tmp.path());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    assert!(
        !store.seen(b"fresh-enough", now - 100),
        "within skew window"
    );
    assert!(!store.seen(b"long-gone", now - 400), "beyond skew window");
    assert_eq!(store.replay_len().expect("len"), 2);
    // The next insert prunes `long-gone` only.
    assert!(!store.seen(b"later", FAR_FUTURE));
    assert_eq!(store.replay_len().expect("len"), 2);
    assert!(store.seen(b"fresh-enough", now - 100));
    assert!(!store.seen(b"long-gone", FAR_FUTURE), "was pruned");
}
