//! Independent release verification and slot install, against the golden
//! fixtures from `cargo run -p xtask -- action-fixtures`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use rmm_trust::keys::PublicKey;
use rmm_watchdog::apply::{self, ApplyReject, Staged};
use rmm_watchdog::state::{Slot, State};
use rmm_watchdog::{AGENT_FILE, hex, parse_roots};
use sha2::{Digest, Sha256};

/// Fixture time (see tests/fixtures/README.md).
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const PLATFORM: &str = "linux-x86_64";

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn roots() -> Vec<PublicKey> {
    let hex = String::from_utf8(fixture("root.pub.hex")).expect("utf8");
    parse_roots(&hex, None).expect("roots").0
}

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmm-wd-apply-{}-{}-{name}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bootstrap")).expect("mkdir");
        fs::write(dir.join("bootstrap").join(AGENT_FILE), BOOTSTRAP).expect("bootstrap");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                dir.join("bootstrap").join(AGENT_FILE),
                fs::Permissions::from_mode(0o755),
            )
            .expect("chmod");
        }
        Self(dir)
    }

    fn pending(&self) -> PathBuf {
        self.0.join(apply::PENDING_DIR)
    }

    /// Stage `release` with `artifact` (and the fixture manifest), READY last.
    fn stage(&self, release: &[u8], artifact: &[u8]) {
        let p = self.pending();
        fs::create_dir_all(&p).expect("mkdir pending");
        fs::write(p.join(apply::MANIFEST_FILE), fixture("manifest.env")).expect("manifest");
        fs::write(p.join(apply::RELEASE_FILE), release).expect("release");
        fs::write(p.join(apply::ARTIFACT_FILE), artifact).expect("artifact");
        fs::write(p.join(apply::READY_FILE), b"").expect("ready");
    }

    fn check(&self, state: &State) -> Result<Option<Staged>, ApplyReject> {
        self.check_at(state, NOW, &roots(), 1, PLATFORM)
    }

    fn check_at(
        &self,
        state: &State,
        now: u64,
        roots: &[PublicKey],
        threshold: u8,
        platform: &str,
    ) -> Result<Option<Staged>, ApplyReject> {
        apply::check_pending(&self.0, roots, threshold, platform, state, now)
    }

    /// Stage, check and assert the reject reason and that pending/ is gone.
    fn rejects(&self, state: &State, release: &[u8], artifact: &[u8], want: ApplyReject) {
        self.stage(release, artifact);
        assert_eq!(self.check(state), Err(want));
        assert!(!self.pending().exists(), "{want}: pending/ must be deleted");
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const BOOTSTRAP: &[u8] = b"#!/bin/sh\necho 'rmm-agent 0.1.0'\n";

fn fresh() -> State {
    State::bootstrap("0.1.0".into())
}

fn good() -> Vec<u8> {
    fixture("agent-0.1.1.sh")
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

#[test]
fn nothing_staged_or_not_ready_is_left_alone() {
    let r = Root::new("noop");
    assert_eq!(r.check(&fresh()), Ok(None));
    r.stage(&fixture("release-0.1.1.env"), &good());
    fs::remove_file(r.pending().join(apply::READY_FILE)).expect("rm READY");
    assert_eq!(r.check(&fresh()), Ok(None));
    assert!(
        r.pending().join(apply::RELEASE_FILE).exists(),
        "kept while incomplete"
    );
}

#[test]
fn ready_without_release_is_no_pending() {
    let r = Root::new("nopending");
    r.stage(&fixture("release-0.1.1.env"), &good());
    fs::remove_file(r.pending().join(apply::RELEASE_FILE)).expect("rm");
    assert_eq!(r.check(&fresh()), Err(ApplyReject::NoPending));
    assert!(!r.pending().exists());

    r.stage(&fixture("release-0.1.1.env"), &good());
    fs::remove_file(r.pending().join(apply::ARTIFACT_FILE)).expect("rm");
    assert_eq!(r.check(&fresh()), Err(ApplyReject::NoPending));
    assert_eq!(ApplyReject::NoPending.reason(), "no_pending");
}

#[test]
fn manifest_must_chain_to_compiled_roots() {
    let r = Root::new("manifest");
    r.stage(&fixture("release-0.1.1.env"), &good());
    fs::write(r.pending().join(apply::MANIFEST_FILE), b"garbage").expect("write");
    assert_eq!(r.check(&fresh()), Err(ApplyReject::BadManifest));
    assert!(!r.pending().exists());

    // One root signature does not meet a compiled threshold of 2.
    r.stage(&fixture("release-0.1.1.env"), &good());
    assert_eq!(
        r.check_at(&fresh(), NOW, &roots(), 2, PLATFORM),
        Err(ApplyReject::BadManifest)
    );
    // No compiled roots at all.
    r.stage(&fixture("release-0.1.1.env"), &good());
    assert_eq!(
        r.check_at(&fresh(), NOW, &[], 0, PLATFORM),
        Err(ApplyReject::BadManifest)
    );
    assert_eq!(ApplyReject::BadManifest.reason(), "bad_manifest");
}

#[test]
fn wrong_role_and_tampered_envelopes_are_bad_release() {
    let r = Root::new("badrelease");
    r.rejects(
        &fresh(),
        &fixture("release-wrong-role.env"),
        &good(),
        ApplyReject::BadRelease,
    );
    let mut flipped = fixture("release-0.1.1.env");
    let at = flipped.len() - 70; // one bit inside the signature entry
    flipped[at] ^= 1;
    r.rejects(&fresh(), &flipped, &good(), ApplyReject::BadRelease);
    r.rejects(&fresh(), b"not cbor", &good(), ApplyReject::BadRelease);
    assert_eq!(ApplyReject::BadRelease.reason(), "bad_release");
}

#[test]
fn expired_release_is_rejected() {
    let r = Root::new("expired");
    r.stage(&fixture("release-0.1.1.env"), &good());
    assert_eq!(
        r.check_at(&fresh(), NOW + 31 * DAY, &roots(), 1, PLATFORM),
        Err(ApplyReject::Expired)
    );
    assert!(!r.pending().exists());
    assert_eq!(ApplyReject::Expired.reason(), "expired");
}

#[test]
fn downgrade_and_equal_versions_are_rejected() {
    let r = Root::new("downgrade");
    // 0.1.0 equals the bootstrap version.
    r.rejects(
        &fresh(),
        &fixture("release-downgrade.env"),
        &good(),
        ApplyReject::Downgrade,
    );
    // Higher seq than the floor, lower version than the active one.
    let mut s = fresh();
    s.active = Slot::A;
    s.active_version = "0.1.1".into();
    s.release_seq_floor = 2;
    r.rejects(
        &s,
        &fixture("release-downgrade.env"),
        &good(),
        ApplyReject::Downgrade,
    );
    assert_eq!(ApplyReject::Downgrade.reason(), "downgrade");
}

#[test]
fn seq_at_or_below_floor_is_replayed() {
    let r = Root::new("replay");
    let mut s = fresh();
    s.release_seq_floor = 2;
    r.rejects(
        &s,
        &fixture("release-0.1.1.env"),
        &good(),
        ApplyReject::ReplayedSeq,
    );
    assert_eq!(ApplyReject::ReplayedSeq.reason(), "replayed_seq");
}

#[test]
fn missing_platform_is_rejected() {
    let r = Root::new("platform");
    r.stage(&fixture("release-0.1.1.env"), &good());
    assert_eq!(
        r.check_at(&fresh(), NOW, &roots(), 1, "plan9-x86_64"),
        Err(ApplyReject::NoArtifactForPlatform)
    );
    assert_eq!(
        ApplyReject::NoArtifactForPlatform.reason(),
        "no_artifact_for_platform"
    );
}

#[test]
fn artifact_size_and_hash_must_match() {
    let r = Root::new("hash");
    let mut longer = good();
    longer.push(b'\n');
    r.rejects(
        &fresh(),
        &fixture("release-0.1.1.env"),
        &longer,
        ApplyReject::SizeMismatch,
    );
    let mut flipped = good();
    flipped[0] ^= 1;
    r.rejects(
        &fresh(),
        &fixture("release-0.1.1.env"),
        &flipped,
        ApplyReject::HashMismatch,
    );
    // A validly signed release whose hash does not match the file.
    r.rejects(
        &fresh(),
        &fixture("release-tampered-hash.env"),
        &good(),
        ApplyReject::HashMismatch,
    );
    assert_eq!(ApplyReject::SizeMismatch.reason(), "size_mismatch");
    assert_eq!(ApplyReject::HashMismatch.reason(), "hash_mismatch");
}

#[test]
fn known_bad_hash_is_rejected() {
    let r = Root::new("knownbad");
    let mut s = fresh();
    s.bad_hashes.push(hex(&sha(&good())));
    r.rejects(
        &s,
        &fixture("release-0.1.1.env"),
        &good(),
        ApplyReject::KnownBad,
    );
    assert_eq!(ApplyReject::KnownBad.reason(), "known_bad");
}

fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| {
            let p = e.expect("entry").path();
            let b = fs::read(&p).expect("read");
            (p, b)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn valid_release_installs_into_inactive_slot_as_trial() {
    let r = Root::new("install");
    let before = snapshot(&r.0.join("bootstrap"));
    let mut state = fresh();
    r.stage(&fixture("release-0.1.1.env"), &good());
    let staged = r.check(&state).expect("verify").expect("staged");
    assert_eq!(
        staged,
        Staged {
            version: "0.1.1".into(),
            sha256: sha(&good()),
            size: good().len() as u64,
            release_seq: 2,
        }
    );

    let slot = apply::install(&r.0, &mut state, &staged, NOW).expect("install");
    assert_eq!(slot, Slot::A);
    let bin = Slot::A.binary(&r.0);
    assert_eq!(fs::read(&bin).expect("slot binary"), good());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&bin).expect("meta").permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "slot binary is executable");
    }
    assert!(!Slot::A.dir(&r.0).join(format!("{AGENT_FILE}.tmp")).exists());
    assert!(!r.pending().exists(), "pending/ consumed");

    let trial = state.trial.clone().expect("trial set");
    assert_eq!(
        (trial.slot, trial.version.as_str(), trial.started_at),
        (Slot::A, "0.1.1", NOW)
    );
    assert_eq!(trial.sha256, hex(&sha(&good())));
    assert_eq!(
        (state.active, state.release_seq_floor),
        (Slot::Bootstrap, 2)
    );
    assert_eq!(State::load(&r.0).expect("load"), state, "trial is durable");
    assert_eq!(
        snapshot(&r.0.join("bootstrap")),
        before,
        "bootstrap untouched"
    );

    // With slot a active, the next release goes to b.
    let mut s = state.clone();
    s.active = Slot::A;
    s.trial = None;
    s.release_seq_floor = 1;
    s.active_version = "0.1.0".into();
    r.stage(&fixture("release-0.1.1.env"), &good());
    let staged = r.check(&s).expect("verify").expect("staged");
    assert_eq!(
        apply::install(&r.0, &mut s, &staged, NOW).expect("install"),
        Slot::B
    );
    assert_eq!(fs::read(Slot::B.binary(&r.0)).expect("slot b"), good());
    assert_eq!(
        snapshot(&r.0.join("bootstrap")),
        before,
        "bootstrap untouched"
    );
}

#[test]
fn install_refuses_an_artifact_swapped_after_verification() {
    let r = Root::new("swap");
    let mut state = fresh();
    r.stage(&fixture("release-0.1.1.env"), &good());
    let staged = r.check(&state).expect("verify").expect("staged");
    let mut flipped = good();
    flipped[0] ^= 1;
    fs::write(r.pending().join(apply::ARTIFACT_FILE), flipped).expect("swap");
    assert!(apply::install(&r.0, &mut state, &staged, NOW).is_err());
    assert!(!Slot::A.binary(&r.0).exists());
    assert!(state.trial.is_none());
    assert!(!r.pending().exists());
}

#[test]
fn state_round_trips_and_corrupt_state_falls_back_to_bootstrap() {
    let r = Root::new("state");
    let mut s = fresh();
    s.active = Slot::B;
    s.previous = Some(Slot::A);
    s.release_seq_floor = 9;
    s.bad_hashes.push("ab".repeat(32));
    s.save(&r.0).expect("save");
    assert_eq!(State::load(&r.0).expect("load"), s);
    assert!(!r.0.join("state.json.tmp").exists());

    fs::write(r.0.join("state.json"), b"{ not json").expect("corrupt");
    let fallback = State::load(&r.0).expect("load");
    assert_eq!(fallback.active, Slot::Bootstrap);
    assert!(fallback.trial.is_none());
}

#[cfg(unix)]
#[test]
fn missing_state_uses_bootstrap_version() {
    let r = Root::new("bootver");
    assert_eq!(State::load(&r.0).expect("load"), fresh());
    fs::remove_file(r.0.join("bootstrap").join(AGENT_FILE)).expect("rm");
    assert_eq!(
        State::load(&r.0).expect("load").active_version,
        rmm_watchdog::state::UNKNOWN_VERSION
    );
}
