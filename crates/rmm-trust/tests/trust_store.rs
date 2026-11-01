//! TrustStore negative, rotation and binding tests.
#![cfg(feature = "sign")]

use std::collections::BTreeMap;

use rmm_proto::canonical::to_canonical_vec;
use rmm_trust::docs::{
    ArtifactRevocations, Cert, Command, CommandBody, Credential, Role, Technician, TechnicianList,
    TrustManifest,
};
use rmm_trust::envelope::{Envelope, TYPE_COMMAND, TYPE_MANIFEST, TYPE_REVOCATIONS, TYPE_TECHLIST};
use rmm_trust::error::TrustError;
use rmm_trust::keys::{Bytes, KeyId};
use rmm_trust::sign::{Ed25519Signer, Signer, sign_envelope};
use rmm_trust::verify::{
    DocKind, FixedClock, MemoryReplayCache, MemorySeqStore, SeqStore, TrustStore,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const AGENT: &str = "agent-1";
const CLIENT: &str = "client-1";

struct Fx {
    a: Ed25519Signer,
    b: Ed25519Signer,
    s1: Ed25519Signer,
    s2: Ed25519Signer,
    c: Ed25519Signer,
}

fn pk_bytes(s: &Ed25519Signer) -> Bytes {
    Bytes(s.public_key().to_bytes().to_vec())
}

fn sign<T: Serialize>(type_: &str, doc: &T, signers: &[&Ed25519Signer]) -> Vec<u8> {
    let dyn_signers: Vec<&dyn Signer> = signers.iter().map(|s| *s as &dyn Signer).collect();
    sign_envelope(type_, to_canonical_vec(doc).expect("encode"), &dyn_signers)
        .expect("sign")
        .to_bytes()
        .expect("envelope")
}

fn clock() -> FixedClock {
    FixedClock(NOW)
}

fn collect() -> CommandBody {
    CommandBody::Collect {
        kind: "inventory".into(),
    }
}

fn trust_update() -> CommandBody {
    CommandBody::TrustUpdate {
        manifest: None,
        revocations: None,
        techlist: None,
    }
}

impl Fx {
    fn new() -> Self {
        Self {
            a: Ed25519Signer::from_seed(&[0xa1; 32]),
            b: Ed25519Signer::from_seed(&[0xb2; 32]),
            s1: Ed25519Signer::from_seed(&[0x51; 32]),
            s2: Ed25519Signer::from_seed(&[0x52; 32]),
            c: Ed25519Signer::from_seed(&[0xc0; 32]),
        }
    }

    fn cert(&self, s: &Ed25519Signer, roles: Vec<Role>) -> Cert {
        Cert {
            key_id: s.key_id(),
            pubkey: pk_bytes(s),
            alg: "ed25519".into(),
            roles,
            not_before: NOW - DAY,
            not_after: NOW + 730 * DAY,
            label: "k".into(),
        }
    }

    fn manifest(&self, seq: u64) -> TrustManifest {
        let signing = vec![
            Role::Catalog,
            Role::Release,
            Role::Techlist,
            Role::ArtifactRevoke,
        ];
        TrustManifest {
            seq,
            issued_at: NOW - 10,
            expires_at: NOW + 365 * DAY,
            root_keys: vec![pk_bytes(&self.a)],
            root_threshold: 1,
            certs: vec![
                self.cert(&self.s1, signing.clone()),
                self.cert(&self.s2, signing),
                self.cert(&self.c, vec![Role::Command]),
            ],
            thresholds: BTreeMap::from([
                (Role::Catalog, 1),
                (Role::Release, 1),
                (Role::Techlist, 1),
                (Role::ArtifactRevoke, 1),
                (Role::Command, 1),
            ]),
            revoked_keys: vec![],
            console_rp_id: "rmm.example.com".into(),
            console_origins: vec!["https://rmm.example.com".into()],
            capability_ceiling: vec!["inventory".into()],
            revocation_mirrors: vec![],
        }
    }

    fn revocations(&self, seq: u64) -> ArtifactRevocations {
        ArtifactRevocations {
            seq,
            issued_at: NOW - 10,
            expires_at: NOW + 45 * DAY,
            revoked_hashes: vec![KeyId([0x11; 32])],
        }
    }

    fn techlist(&self, seq: u64) -> TechnicianList {
        TechnicianList {
            seq,
            issued_at: NOW - 10,
            expires_at: NOW + 90 * DAY,
            techs: vec![Technician {
                tech_id: "tech-alice".into(),
                client_scope: vec!["*".into()],
                perms: vec!["shell".into()],
                creds: vec![Credential {
                    cred_id: Bytes(vec![0xc1; 20]),
                    alg: -7,
                    cose_pubkey: Bytes(vec![0xa5]),
                    aaguid: Bytes(vec![0xaa; 16]),
                }],
            }],
        }
    }

    fn command(&self, n: u8, body: CommandBody) -> Command {
        Command {
            cmd_id: Bytes(vec![n; 16]),
            agent_id: AGENT.into(),
            client_id: CLIENT.into(),
            issued_at: NOW,
            expires_at: NOW + 600,
            policy_hash: Bytes(vec![0x5a; 32]),
            body,
        }
    }

    fn signed_cmd(&self, cmd: &Command) -> Vec<u8> {
        sign(TYPE_COMMAND, cmd, &[&self.c])
    }

    fn store(&self) -> TrustStore {
        TrustStore::new(vec![self.a.public_key()], 1)
    }

    /// Store with manifest 1, revocations 1 and techlist 1 (both by S1).
    fn ready(&self) -> (TrustStore, MemorySeqStore) {
        let mut store = self.store();
        let mut seq = MemorySeqStore::new();
        store
            .apply_manifest(
                &sign(TYPE_MANIFEST, &self.manifest(1), &[&self.a]),
                &clock(),
                &mut seq,
            )
            .expect("manifest");
        store
            .apply_revocations(
                &sign(TYPE_REVOCATIONS, &self.revocations(1), &[&self.s1]),
                &clock(),
                &mut seq,
            )
            .expect("revocations");
        store
            .apply_techlist(
                &sign(TYPE_TECHLIST, &self.techlist(1), &[&self.s1]),
                &clock(),
                &mut seq,
            )
            .expect("techlist");
        (store, seq)
    }
}

fn duplicate_first_sig(env_bytes: &[u8]) -> Vec<u8> {
    let mut env = Envelope::from_bytes(env_bytes).expect("env");
    let first = env.sigs[0].clone();
    env.sigs.push(first);
    env.to_bytes().expect("enc")
}

#[test]
fn happy_path_chain() {
    let fx = Fx::new();
    let (store, seq) = fx.ready();
    assert_eq!(store.manifest().map(|m| m.seq), Some(1));
    assert_eq!(store.revocations().map(|r| r.seq), Some(1));
    assert_eq!(store.techlist().map(|t| t.seq), Some(1));
    assert_eq!(seq.get(DocKind::Manifest).map(|s| s.0), Some(1));
    store.trust_fresh(NOW).expect("fresh");

    let mut replay = MemoryReplayCache::new(FixedClock(NOW));
    let cmd = fx.command(1, collect());
    let got = store
        .verify_command(&fx.signed_cmd(&cmd), AGENT, CLIENT, &clock(), &mut replay)
        .expect("command");
    assert_eq!(got, cmd);
}

#[test]
fn manifest_signed_by_cert_holder_not_root_is_below_threshold() {
    let fx = Fx::new();
    let mut store = fx.store();
    let mut seq = MemorySeqStore::new();
    let bytes = sign(TYPE_MANIFEST, &fx.manifest(1), &[&fx.s1]);
    assert_eq!(
        store.apply_manifest(&bytes, &clock(), &mut seq),
        Err(TrustError::BelowThreshold {
            role: Role::Root,
            got: 0,
            need: 1
        })
    );
    assert!(store.manifest().is_none());
    assert_eq!(seq, MemorySeqStore::new());
}

#[test]
fn duplicate_root_signature_counted_once() {
    let fx = Fx::new();
    let mut store = TrustStore::new(vec![fx.a.public_key(), fx.b.public_key()], 2);
    let mut m = fx.manifest(1);
    m.root_keys = vec![pk_bytes(&fx.a), pk_bytes(&fx.b)];
    m.root_threshold = 2;
    let bytes = duplicate_first_sig(&sign(TYPE_MANIFEST, &m, &[&fx.a]));
    assert_eq!(
        store.apply_manifest(&bytes, &clock(), &mut MemorySeqStore::new()),
        Err(TrustError::BelowThreshold {
            role: Role::Root,
            got: 1,
            need: 2
        })
    );
    let both = sign(TYPE_MANIFEST, &m, &[&fx.a, &fx.b]);
    store
        .apply_manifest(&both, &clock(), &mut MemorySeqStore::new())
        .expect("2-of-2 roots");
}

#[test]
fn duplicate_role_signature_counted_once() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut m = fx.manifest(2);
    m.thresholds.insert(Role::Techlist, 2);
    store
        .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq)
        .expect("manifest 2");
    let bytes = duplicate_first_sig(&sign(TYPE_TECHLIST, &fx.techlist(2), &[&fx.s1]));
    assert_eq!(
        store.apply_techlist(&bytes, &clock(), &mut seq),
        Err(TrustError::BelowThreshold {
            role: Role::Techlist,
            got: 1,
            need: 2
        })
    );
}

#[test]
fn threshold_zero_is_invalid() {
    let fx = Fx::new();
    let mut m = fx.manifest(1);
    m.thresholds.insert(Role::Techlist, 0);
    let bytes = sign(TYPE_MANIFEST, &m, &[&fx.a]);
    assert!(matches!(
        fx.store()
            .apply_manifest(&bytes, &clock(), &mut MemorySeqStore::new()),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn threshold_above_cert_holders_is_invalid() {
    let fx = Fx::new();
    let mut m = fx.manifest(1);
    m.thresholds.insert(Role::Command, 2);
    let bytes = sign(TYPE_MANIFEST, &m, &[&fx.a]);
    assert!(matches!(
        fx.store()
            .apply_manifest(&bytes, &clock(), &mut MemorySeqStore::new()),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn root_change_signed_only_by_old_roots_is_rejected() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut m = fx.manifest(2);
    m.root_keys = vec![pk_bytes(&fx.b)];
    let bytes = sign(TYPE_MANIFEST, &m, &[&fx.a]);
    assert_eq!(
        store.apply_manifest(&bytes, &clock(), &mut seq),
        Err(TrustError::BelowThreshold {
            role: Role::Root,
            got: 0,
            need: 1
        })
    );
    // Signed only by the new root is not enough either.
    let bytes = sign(TYPE_MANIFEST, &m, &[&fx.b]);
    assert!(matches!(
        store.apply_manifest(&bytes, &clock(), &mut seq),
        Err(TrustError::BelowThreshold {
            role: Role::Root,
            ..
        })
    ));
    assert_eq!(store.manifest().map(|m| m.seq), Some(1));
}

#[test]
fn root_rotation_a_to_b() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut m2 = fx.manifest(2);
    m2.root_keys = vec![pk_bytes(&fx.b)];
    store
        .apply_manifest(
            &sign(TYPE_MANIFEST, &m2, &[&fx.a, &fx.b]),
            &clock(),
            &mut seq,
        )
        .expect("rotation");

    let mut m3 = fx.manifest(3);
    m3.root_keys = vec![pk_bytes(&fx.b)];
    assert!(matches!(
        store.apply_manifest(&sign(TYPE_MANIFEST, &m3, &[&fx.a]), &clock(), &mut seq),
        Err(TrustError::BelowThreshold {
            role: Role::Root,
            ..
        })
    ));
    // Old root A, even re-adding itself, is no longer trusted.
    let m3a = fx.manifest(3);
    assert!(matches!(
        store.apply_manifest(&sign(TYPE_MANIFEST, &m3a, &[&fx.a]), &clock(), &mut seq),
        Err(TrustError::BelowThreshold {
            role: Role::Root,
            ..
        })
    ));
    store
        .apply_manifest(&sign(TYPE_MANIFEST, &m3, &[&fx.b]), &clock(), &mut seq)
        .expect("B alone now suffices");
    assert_eq!(seq.get(DocKind::Manifest).map(|s| s.0), Some(3));
}

#[test]
fn same_seq_same_payload_is_idempotent() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let bytes = sign(TYPE_MANIFEST, &fx.manifest(1), &[&fx.a]);
    store
        .apply_manifest(&bytes, &clock(), &mut seq)
        .expect("idempotent");
    // A fresh process with the persisted SeqStore accepts it too.
    let mut fresh = fx.store();
    fresh
        .apply_manifest(&bytes, &clock(), &mut seq)
        .expect("idempotent after restart");
}

#[test]
fn same_seq_different_payload_is_equivocation() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let before = seq.clone();
    let mut m = fx.manifest(1);
    m.console_rp_id = "evil.example.com".into();
    assert_eq!(
        store.apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq),
        Err(TrustError::Equivocation)
    );
    let mut t = fx.techlist(1);
    t.techs.clear();
    assert_eq!(
        store.apply_techlist(&sign(TYPE_TECHLIST, &t, &[&fx.s1]), &clock(), &mut seq),
        Err(TrustError::Equivocation)
    );
    assert_eq!(seq, before);
    assert_eq!(
        store.manifest().map(|m| m.console_rp_id.as_str()),
        Some("rmm.example.com")
    );
}

#[test]
fn lower_seq_is_rollback() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    store
        .apply_manifest(
            &sign(TYPE_MANIFEST, &fx.manifest(2), &[&fx.a]),
            &clock(),
            &mut seq,
        )
        .expect("seq 2");
    assert_eq!(
        store.apply_manifest(
            &sign(TYPE_MANIFEST, &fx.manifest(1), &[&fx.a]),
            &clock(),
            &mut seq
        ),
        Err(TrustError::Rollback { stored: 2, got: 1 })
    );
    store
        .apply_revocations(
            &sign(TYPE_REVOCATIONS, &fx.revocations(5), &[&fx.s1]),
            &clock(),
            &mut seq,
        )
        .expect("rev 5");
    assert_eq!(
        store.apply_revocations(
            &sign(TYPE_REVOCATIONS, &fx.revocations(4), &[&fx.s1]),
            &clock(),
            &mut seq
        ),
        Err(TrustError::Rollback { stored: 5, got: 4 })
    );
}

#[test]
fn rollback_detected_from_persisted_seq_after_restart() {
    let fx = Fx::new();
    let mut seq = MemorySeqStore::new();
    seq.put(DocKind::Manifest, 9, [0; 32]);
    let mut store = fx.store();
    assert_eq!(
        store.apply_manifest(
            &sign(TYPE_MANIFEST, &fx.manifest(8), &[&fx.a]),
            &clock(),
            &mut seq
        ),
        Err(TrustError::Rollback { stored: 9, got: 8 })
    );
}

#[test]
fn revocations_expired_by_one_second_are_stale() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut r = fx.revocations(2);
    r.expires_at = NOW + 100;
    store
        .apply_revocations(&sign(TYPE_REVOCATIONS, &r, &[&fx.s1]), &clock(), &mut seq)
        .expect("rev");
    let later = FixedClock(NOW + 101);
    store.trust_fresh(NOW + 99).expect("still fresh");
    assert_eq!(store.trust_fresh(NOW + 101), Err(TrustError::Stale));

    let mut replay = MemoryReplayCache::new(FixedClock(NOW));
    let cmd = fx.command(1, collect());
    assert_eq!(
        store.verify_command(&fx.signed_cmd(&cmd), AGENT, CLIENT, &later, &mut replay),
        Err(TrustError::Stale)
    );
    let upd = fx.command(2, trust_update());
    store
        .verify_command(&fx.signed_cmd(&upd), AGENT, CLIENT, &later, &mut replay)
        .expect("trust update still accepted");
}

#[test]
fn missing_revocations_are_stale() {
    let fx = Fx::new();
    let mut store = fx.store();
    let mut seq = MemorySeqStore::new();
    assert_eq!(store.trust_fresh(NOW), Err(TrustError::NoManifest));
    store
        .apply_manifest(
            &sign(TYPE_MANIFEST, &fx.manifest(1), &[&fx.a]),
            &clock(),
            &mut seq,
        )
        .expect("manifest");
    assert_eq!(store.trust_fresh(NOW), Err(TrustError::Stale));
}

#[test]
fn command_for_other_agent_or_client() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let mut replay = MemoryReplayCache::new(FixedClock(NOW));
    let mut cmd = fx.command(1, collect());
    cmd.agent_id = "agent-2".into();
    assert_eq!(
        store.verify_command(&fx.signed_cmd(&cmd), AGENT, CLIENT, &clock(), &mut replay),
        Err(TrustError::WrongAgent)
    );
    let mut cmd = fx.command(2, collect());
    cmd.client_id = "client-2".into();
    assert_eq!(
        store.verify_command(&fx.signed_cmd(&cmd), AGENT, CLIENT, &clock(), &mut replay),
        Err(TrustError::WrongClient)
    );
    assert!(
        replay.is_empty(),
        "rejected commands do not enter the replay cache"
    );
}

#[test]
fn replayed_command_is_rejected() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let mut replay = MemoryReplayCache::new(FixedClock(NOW));
    let bytes = fx.signed_cmd(&fx.command(1, collect()));
    store
        .verify_command(&bytes, AGENT, CLIENT, &clock(), &mut replay)
        .expect("first");
    assert_eq!(
        store.verify_command(&bytes, AGENT, CLIENT, &clock(), &mut replay),
        Err(TrustError::Replay)
    );
}

#[test]
fn expired_command_is_rejected() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let mut replay = MemoryReplayCache::new(FixedClock(NOW));
    let cmd = fx.command(1, collect());
    assert_eq!(
        store.verify_command(
            &fx.signed_cmd(&cmd),
            AGENT,
            CLIENT,
            &FixedClock(cmd.expires_at),
            &mut replay
        ),
        Err(TrustError::Expired)
    );
}

#[test]
fn command_from_the_future_beyond_skew() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let mut replay = MemoryReplayCache::new(FixedClock(NOW));
    let mut cmd = fx.command(1, collect());
    cmd.issued_at = NOW + 301;
    cmd.expires_at = NOW + 900;
    assert_eq!(
        store.verify_command(&fx.signed_cmd(&cmd), AGENT, CLIENT, &clock(), &mut replay),
        Err(TrustError::NotYetValid)
    );
    let mut cmd = fx.command(2, collect());
    cmd.issued_at = NOW + 300;
    cmd.expires_at = NOW + 900;
    store
        .verify_command(&fx.signed_cmd(&cmd), AGENT, CLIENT, &clock(), &mut replay)
        .expect("300 s skew is tolerated");
}

#[test]
fn command_ttl_over_seven_days_is_invalid() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let mut cmd = fx.command(1, collect());
    cmd.expires_at = cmd.issued_at + 7 * DAY + 1;
    assert!(matches!(
        store.verify_command(
            &fx.signed_cmd(&cmd),
            AGENT,
            CLIENT,
            &clock(),
            &mut MemoryReplayCache::new(FixedClock(NOW))
        ),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn tampered_command_fails_signature() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let bytes = fx.signed_cmd(&fx.command(1, collect()));
    let mut env = Envelope::from_bytes(&bytes).expect("env");
    let mut cmd = fx.command(1, collect());
    cmd.agent_id = "agent-2".into();
    env.payload = Bytes(to_canonical_vec(&cmd).expect("enc"));
    assert_eq!(
        store.verify_command(
            &env.to_bytes().expect("enc"),
            "agent-2",
            CLIENT,
            &clock(),
            &mut MemoryReplayCache::new(FixedClock(NOW))
        ),
        Err(TrustError::BadSignature)
    );
}

#[test]
fn command_signed_by_wrong_role_key() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let bytes = sign(TYPE_COMMAND, &fx.command(1, collect()), &[&fx.s1]);
    assert_eq!(
        store.verify_command(
            &bytes,
            AGENT,
            CLIENT,
            &clock(),
            &mut MemoryReplayCache::new(FixedClock(NOW))
        ),
        Err(TrustError::WrongRole)
    );
}

#[test]
fn unknown_signer_is_rejected() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let stranger = Ed25519Signer::from_seed(&[0x99; 32]);
    let bytes = sign(TYPE_COMMAND, &fx.command(1, collect()), &[&stranger]);
    assert_eq!(
        store.verify_command(
            &bytes,
            AGENT,
            CLIENT,
            &clock(),
            &mut MemoryReplayCache::new(FixedClock(NOW))
        ),
        Err(TrustError::UnknownKey)
    );
}

#[test]
fn expired_cert_does_not_count() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut m = fx.manifest(2);
    for cert in &mut m.certs {
        if cert.key_id == fx.c.key_id() {
            cert.not_after = NOW;
        }
    }
    store
        .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq)
        .expect("manifest");
    assert_eq!(
        store.verify_command(
            &fx.signed_cmd(&fx.command(1, collect())),
            AGENT,
            CLIENT,
            &clock(),
            &mut MemoryReplayCache::new(FixedClock(NOW))
        ),
        Err(TrustError::CertNotValid)
    );
}

#[test]
fn role_without_threshold_is_wrong_role() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let env = Envelope::from_bytes(&sign("rmm.policy/1", &1u8, &[&fx.s1])).expect("env");
    assert_eq!(
        store.verify_role(&env, Role::Policy, NOW),
        Err(TrustError::WrongRole)
    );
}

#[test]
fn revoked_signing_key_cannot_sign_techlist() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut m = fx.manifest(2);
    m.revoked_keys = vec![fx.s1.key_id()];
    store
        .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq)
        .expect("manifest revoking S1");
    assert_eq!(
        store.apply_techlist(
            &sign(TYPE_TECHLIST, &fx.techlist(2), &[&fx.s1]),
            &clock(),
            &mut seq
        ),
        Err(TrustError::KeyRevoked)
    );
    store
        .apply_techlist(
            &sign(TYPE_TECHLIST, &fx.techlist(2), &[&fx.s2]),
            &clock(),
            &mut seq,
        )
        .expect("S2-signed techlist");
    assert_eq!(seq.get(DocKind::Techlist).map(|s| s.0), Some(2));
}

#[test]
fn revoking_key_drops_documents_it_signed() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut m = fx.manifest(2);
    m.revoked_keys = vec![fx.s1.key_id()];
    store
        .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq)
        .expect("manifest revoking S1");
    assert!(store.techlist().is_none());
    assert!(store.revocations().is_none());
    assert_eq!(store.trust_fresh(NOW), Err(TrustError::Stale));
}

#[test]
fn techlist_two_of_two_needs_both_keys() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut m = fx.manifest(2);
    m.thresholds.insert(Role::Techlist, 2);
    store
        .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq)
        .expect("manifest");
    assert_eq!(
        store.apply_techlist(
            &sign(TYPE_TECHLIST, &fx.techlist(2), &[&fx.s1]),
            &clock(),
            &mut seq
        ),
        Err(TrustError::BelowThreshold {
            role: Role::Techlist,
            got: 1,
            need: 2
        })
    );
    let both = sign(TYPE_TECHLIST, &fx.techlist(2), &[&fx.s1, &fx.s2]);
    let env = Envelope::from_bytes(&both).expect("env");
    let mut ids = store
        .verify_role(&env, Role::Techlist, NOW)
        .expect("2-of-2");
    ids.sort();
    let mut want = vec![fx.s1.key_id(), fx.s2.key_id()];
    want.sort();
    assert_eq!(ids, want);
    store
        .apply_techlist(&both, &clock(), &mut seq)
        .expect("techlist");
}

#[test]
fn artifact_revocation_by_content_id() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let definition = b"signed definition bytes".to_vec();
    let id: [u8; 32] = Sha256::digest(&definition).into();
    assert!(!store.is_artifact_revoked(&id));
    let mut r = fx.revocations(2);
    r.revoked_hashes.push(KeyId(id));
    store
        .apply_revocations(&sign(TYPE_REVOCATIONS, &r, &[&fx.s1]), &clock(), &mut seq)
        .expect("revocations");
    assert!(store.is_artifact_revoked(&id));
    assert!(store.is_artifact_revoked(&[0x11; 32]));
    assert!(!store.is_artifact_revoked(&[0x12; 32]));

    let cmd = fx.command(
        1,
        CommandBody::Invoke {
            definition: Bytes(definition),
            params: BTreeMap::new(),
        },
    );
    let mut replay = MemoryReplayCache::new(FixedClock(NOW));
    assert_eq!(
        store.verify_command(&fx.signed_cmd(&cmd), AGENT, CLIENT, &clock(), &mut replay),
        Err(TrustError::ArtifactRevoked)
    );
    assert!(replay.is_empty());
}

#[test]
fn documents_without_manifest_are_rejected() {
    let fx = Fx::new();
    let mut store = fx.store();
    let mut seq = MemorySeqStore::new();
    assert_eq!(
        store.apply_revocations(
            &sign(TYPE_REVOCATIONS, &fx.revocations(1), &[&fx.s1]),
            &clock(),
            &mut seq
        ),
        Err(TrustError::NoManifest)
    );
    assert_eq!(
        store.apply_techlist(
            &sign(TYPE_TECHLIST, &fx.techlist(1), &[&fx.s1]),
            &clock(),
            &mut seq
        ),
        Err(TrustError::NoManifest)
    );
    assert_eq!(
        store.verify_command(
            &fx.signed_cmd(&fx.command(1, trust_update())),
            AGENT,
            CLIENT,
            &clock(),
            &mut MemoryReplayCache::new(FixedClock(NOW))
        ),
        Err(TrustError::NoManifest)
    );
}

#[test]
fn manifest_time_window() {
    let fx = Fx::new();
    let mut seq = MemorySeqStore::new();
    let mut m = fx.manifest(1);
    m.issued_at = NOW - 20;
    m.expires_at = NOW;
    assert_eq!(
        fx.store()
            .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq),
        Err(TrustError::Expired)
    );
    let mut m = fx.manifest(1);
    m.issued_at = NOW + 301;
    assert_eq!(
        fx.store()
            .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq),
        Err(TrustError::NotYetValid)
    );
    let mut m = fx.manifest(1);
    m.expires_at = m.issued_at + 400 * DAY + 1;
    assert!(matches!(
        fx.store()
            .apply_manifest(&sign(TYPE_MANIFEST, &m, &[&fx.a]), &clock(), &mut seq),
        Err(TrustError::InvalidDocument(_))
    ));
    assert_eq!(seq, MemorySeqStore::new());
}

#[test]
fn revocations_window_over_sixty_days_is_invalid() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut r = fx.revocations(2);
    r.expires_at = r.issued_at + 60 * DAY + 1;
    assert!(matches!(
        store.apply_revocations(&sign(TYPE_REVOCATIONS, &r, &[&fx.s1]), &clock(), &mut seq),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn techlist_bad_credential_is_invalid() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let mut t = fx.techlist(2);
    t.techs[0].creds[0].alg = -257;
    assert!(matches!(
        store.apply_techlist(&sign(TYPE_TECHLIST, &t, &[&fx.s1]), &clock(), &mut seq),
        Err(TrustError::InvalidDocument(_))
    ));
    let mut t = fx.techlist(2);
    t.techs[0].creds[0].aaguid = Bytes(vec![0; 15]);
    assert!(matches!(
        store.apply_techlist(&sign(TYPE_TECHLIST, &t, &[&fx.s1]), &clock(), &mut seq),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn wrong_payload_type_is_rejected() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    // A root-signed manifest presented as a techlist, and vice versa.
    let as_rev = sign(TYPE_REVOCATIONS, &fx.manifest(2), &[&fx.a]);
    assert_eq!(
        store.apply_manifest(&as_rev, &clock(), &mut seq),
        Err(TrustError::WrongType)
    );
    let tl = sign(TYPE_TECHLIST, &fx.techlist(2), &[&fx.s1]);
    assert_eq!(
        store.apply_revocations(&tl, &clock(), &mut seq),
        Err(TrustError::WrongType)
    );
}

#[test]
fn too_many_signatures_rejected() {
    let fx = Fx::new();
    let (store, _) = fx.ready();
    let bytes = fx.signed_cmd(&fx.command(1, collect()));
    let mut env = Envelope::from_bytes(&bytes).expect("env");
    let first = env.sigs[0].clone();
    env.sigs = vec![first; 17];
    assert!(matches!(
        store.verify_command(
            &env.to_bytes().expect("enc"),
            AGENT,
            CLIENT,
            &clock(),
            &mut MemoryReplayCache::new(FixedClock(NOW))
        ),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn compiled_threshold_zero_fails_closed() {
    let fx = Fx::new();
    let mut store = TrustStore::new(vec![fx.a.public_key()], 0);
    assert!(matches!(
        store.apply_manifest(
            &sign(TYPE_MANIFEST, &fx.manifest(1), &[&fx.a]),
            &clock(),
            &mut MemorySeqStore::new()
        ),
        Err(TrustError::InvalidDocument(_))
    ));
}

#[test]
fn seq_store_unchanged_after_rejected_documents() {
    let fx = Fx::new();
    let (mut store, mut seq) = fx.ready();
    let before = seq.clone();
    let manifest_before = seq.get(DocKind::Manifest);
    let rev_before = seq.get(DocKind::Revocations);
    let tl_before = seq.get(DocKind::Techlist);

    let mut bad = fx.manifest(5);
    bad.thresholds.insert(Role::Command, 0);
    let rejected_manifests = [
        sign(TYPE_MANIFEST, &fx.manifest(5), &[&fx.s1]),
        sign(TYPE_MANIFEST, &bad, &[&fx.a]),
        sign(TYPE_MANIFEST, &fx.manifest(0), &[&fx.a]),
    ];
    for bytes in &rejected_manifests {
        assert!(store.apply_manifest(bytes, &clock(), &mut seq).is_err());
    }
    let mut expired = fx.revocations(5);
    expired.expires_at = NOW;
    let rejected_revs = [
        sign(TYPE_REVOCATIONS, &fx.revocations(5), &[&fx.c]),
        sign(TYPE_REVOCATIONS, &expired, &[&fx.s1]),
        sign(TYPE_REVOCATIONS, &fx.revocations(0), &[&fx.s1]),
    ];
    for bytes in &rejected_revs {
        assert!(store.apply_revocations(bytes, &clock(), &mut seq).is_err());
    }
    let mut t = fx.techlist(5);
    t.techs[0].creds[0].alg = 1;
    let rejected_tls = [
        sign(TYPE_TECHLIST, &fx.techlist(5), &[&fx.c]),
        sign(TYPE_TECHLIST, &t, &[&fx.s1]),
    ];
    for bytes in &rejected_tls {
        assert!(store.apply_techlist(bytes, &clock(), &mut seq).is_err());
    }

    assert_eq!(seq.get(DocKind::Manifest), manifest_before);
    assert_eq!(seq.get(DocKind::Revocations), rev_before);
    assert_eq!(seq.get(DocKind::Techlist), tl_before);
    assert_eq!(seq, before);
    assert_eq!(store.manifest().map(|m| m.seq), Some(1));
    assert_eq!(store.revocations().map(|r| r.seq), Some(1));
    assert_eq!(store.techlist().map(|t| t.seq), Some(1));
}
