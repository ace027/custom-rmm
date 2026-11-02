//! The executor pipeline on the fake test platform: the spooler recipe's
//! success, rollback and failure paths, and the signed result.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rmm_agent_core::blocks::{PlatformBlocks, SPOOL_ROOT, TEST_SPOOL_DIR};
use rmm_agent_core::commands::Verified;
use rmm_agent_core::executor::{run, sign_result};
use rmm_platform::fake::FakeServices;
use rmm_platform::services::{self, ServiceState, Services};
use rmm_recipe::definition::{Definition, Stage};
use rmm_recipe::result::{ActionResult, Outcome, TYPE_RESULT};
use rmm_trust::docs::{Command, CommandBody};
use rmm_trust::envelope::Envelope;
use rmm_trust::keys::{Bytes, PublicKey};

const AGENT_ID: &str = "agent_0000000000000001";
const CMD_ID: [u8; 16] = [0xc1; 16];

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmm-exec-test-{}-{}",
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

/// Lets the test inspect the fake after handing it to the blocks.
#[derive(Debug)]
struct Shared(Arc<FakeServices>);

impl Services for Shared {
    fn query(&self, name: &str) -> services::Result<ServiceState> {
        self.0.query(name)
    }
    fn stop(&self, name: &str, timeout: Duration) -> services::Result<()> {
        self.0.stop(name, timeout)
    }
    fn start(&self, name: &str, timeout: Duration) -> services::Result<()> {
        self.0.start(name, timeout)
    }
    fn wait(&self, name: &str, want: ServiceState, timeout: Duration) -> services::Result<()> {
        self.0.wait(name, want, timeout)
    }
}

fn definition_env() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/definition-valid.env");
    std::fs::read(path).expect("definition fixture")
}

/// The signed spooler definition, as verified.
fn spooler() -> Verified {
    let env_bytes = definition_env();
    let env = Envelope::from_bytes(&env_bytes).expect("envelope");
    let definition = Definition::from_envelope_payload(&env.payload.0).expect("definition");
    assert_eq!(definition.id, "printing.spooler-restart");
    Verified {
        command: Command {
            cmd_id: Bytes(CMD_ID.to_vec()),
            agent_id: AGENT_ID.into(),
            client_id: "client_0000000000000001".into(),
            issued_at: 0,
            expires_at: 1,
            policy_hash: Bytes(vec![0; 32]),
            body: CommandBody::Invoke {
                definition: Bytes(env_bytes),
                params: BTreeMap::new(),
            },
        },
        definition,
        content_id: env.content_id(),
    }
}

struct Rig {
    tmp: TempDir,
    fake: Arc<FakeServices>,
    blocks: PlatformBlocks,
}

impl Rig {
    fn new(fake: FakeServices) -> Self {
        let tmp = TempDir::new();
        let fake = Arc::new(fake);
        let blocks = PlatformBlocks::test_platform(Box::new(Shared(Arc::clone(&fake))), tmp.path())
            .expect("test platform");
        let rig = Self { tmp, fake, blocks };
        for (name, data) in [("00001.SPL", "job one"), ("00001.SHD", "shadow")] {
            std::fs::write(rig.spool().join(name), data).expect("spool file");
        }
        rig
    }

    fn spool(&self) -> PathBuf {
        self.tmp.path().join(TEST_SPOOL_DIR)
    }

    fn spool_files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.spool())
            .expect("spool")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn state(&self) -> ServiceState {
        self.fake.query("Spooler").expect("query")
    }
}

fn stages(r: &ActionResult) -> Vec<(Stage, bool)> {
    r.stages.iter().map(|s| (s.stage, s.ok)).collect()
}

const SPOOL: [&str; 2] = ["00001.SHD", "00001.SPL"];

#[test]
fn spooler_recipe_succeeds() {
    let rig = Rig::new(FakeServices::new());
    let r = run(&spooler(), &rig.blocks);
    assert_eq!(r.outcome, Outcome::Succeeded, "{r:#?}");
    assert_eq!(r.reason, None);
    assert_eq!(
        stages(&r),
        [
            (Stage::Precheck, true),
            (Stage::Snapshot, true),
            (Stage::Steps, true),
            (Stage::Verify, true)
        ]
    );
    assert!(r.stages[1].detail.contains("service.query=running"));
    assert!(rig.spool_files().is_empty(), "spool cleared");
    let q = rig.blocks.quarantine_dir(&CMD_ID);
    assert!(q.join("manifest.json").exists());
    assert_eq!(std::fs::read_dir(&q).expect("quarantine").count(), 3);
    assert_eq!(rig.fake.calls(), ["stop spooler", "start spooler"]);
    assert_eq!(rig.state(), ServiceState::Running);
    assert_eq!(r.cmd_id.0, CMD_ID);
    assert_eq!(r.agent_id, AGENT_ID);
    for s in &r.stages {
        assert!(s.started_at <= s.finished_at);
    }
}

#[test]
fn failed_start_rolls_back_and_restores_files() {
    let rig = Rig::new(FakeServices::new().fail_start("Spooler"));
    let r = run(&spooler(), &rig.blocks);
    assert_eq!(r.outcome, Outcome::RolledBack, "{r:#?}");
    assert_eq!(
        stages(&r),
        [
            (Stage::Precheck, true),
            (Stage::Snapshot, true),
            (Stage::Steps, false),
            (Stage::Rollback, true)
        ]
    );
    assert!(r.stages[2].detail.contains("service.wait: FAILED"));
    assert_eq!(rig.spool_files(), SPOOL, "files restored");
    assert!(!rig.blocks.quarantine_dir(&CMD_ID).exists());
    assert_eq!(
        rig.fake.calls(),
        ["stop spooler", "start spooler", "start spooler"]
    );
}

#[test]
fn verify_failure_triggers_rollback() {
    let rig = Rig::new(FakeServices::new().fail_start("Spooler"));
    // Without the in-step wait the failed start is only caught by verify.
    let mut v = spooler();
    let last = v.definition.steps.pop().expect("wait step");
    assert_eq!(last.block, "service.wait");
    let r = run(&v, &rig.blocks);
    assert_eq!(r.outcome, Outcome::RolledBack, "{r:#?}");
    assert_eq!(
        stages(&r),
        [
            (Stage::Precheck, true),
            (Stage::Snapshot, true),
            (Stage::Steps, true),
            (Stage::Verify, false),
            (Stage::Rollback, true)
        ]
    );
    assert_eq!(rig.spool_files(), SPOOL, "files restored");
}

#[test]
fn precheck_failure_runs_no_steps() {
    let rig = Rig::new(FakeServices::with_services(&[]));
    let r = run(&spooler(), &rig.blocks);
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(stages(&r), [(Stage::Precheck, false)]);
    assert!(r.stages[0].detail.contains("does not exist"));
    assert!(rig.fake.calls().is_empty(), "no service touched");
    assert_eq!(rig.spool_files(), SPOOL, "no file touched");
}

#[test]
fn irreversible_failure_is_failed_without_rollback() {
    let rig = Rig::new(FakeServices::new().fail_start("Spooler"));
    let mut v = spooler();
    v.definition.reversible = false;
    let r = run(&v, &rig.blocks);
    assert_eq!(r.outcome, Outcome::Failed);
    assert!(r.stages.iter().all(|s| s.stage != Stage::Rollback));
    assert!(rig.spool_files().is_empty(), "files stay quarantined");
}

#[test]
fn already_stopped_service_still_succeeds() {
    let rig = Rig::new(FakeServices::with_services(&[(
        "Spooler",
        ServiceState::Stopped,
    )]));
    let r = run(&spooler(), &rig.blocks);
    assert_eq!(r.outcome, Outcome::Succeeded, "{r:#?}");
    assert!(r.stages[1].detail.contains("service.query=stopped"));
    assert_eq!(rig.state(), ServiceState::Running);
}

#[test]
fn root_outside_allowlist_fails_before_touching_files() {
    let tmp = TempDir::new();
    let spool = tmp.path().join("spool");
    std::fs::create_dir_all(&spool).expect("spool");
    std::fs::write(spool.join("job.spl"), b"job").expect("job");
    let fake = Arc::new(FakeServices::new());
    // `spool` maps to a directory that is not allowlisted.
    let blocks = PlatformBlocks::new(
        Box::new(Shared(Arc::clone(&fake))),
        BTreeMap::from([(SPOOL_ROOT.to_owned(), spool.clone())]),
        Vec::new(),
        tmp.path(),
    );
    let r = run(&spooler(), &blocks);
    assert_eq!(r.outcome, Outcome::RolledBack, "{r:#?}");
    let steps = r
        .stages
        .iter()
        .find(|s| s.stage == Stage::Steps)
        .expect("steps");
    assert!(!steps.ok);
    assert!(
        steps.detail.contains("not an allowlisted root"),
        "{}",
        steps.detail
    );
    assert!(spool.join("job.spl").exists(), "file untouched");
    assert_eq!(fake.query("Spooler").expect("q"), ServiceState::Running);
}

#[cfg(unix)]
#[test]
fn symlink_in_spool_is_skipped() {
    let rig = Rig::new(FakeServices::new());
    let outside = rig.tmp.path().join("outside.txt");
    std::fs::write(&outside, b"not spool").expect("outside");
    std::os::unix::fs::symlink(&outside, rig.spool().join("link.SPL")).expect("symlink");
    let r = run(&spooler(), &rig.blocks);
    assert_eq!(r.outcome, Outcome::Succeeded, "{r:#?}");
    assert_eq!(rig.spool_files(), ["link.SPL"], "only the symlink remains");
    assert!(outside.exists());
}

#[test]
fn signed_result_verifies_with_agent_key() {
    let rig = Rig::new(FakeServices::new());
    let v = spooler();
    let r = run(&v, &rig.blocks);
    let seed = [0x55; 32];
    let env = sign_result(&r, &seed).expect("sign");
    assert_eq!(env.r#type, TYPE_RESULT);
    assert_eq!(env.sigs.len(), 1);
    let public = PublicKey::from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    )
    .expect("key");
    assert_eq!(env.sigs[0].key_id, public.key_id());
    env.verify_sig(&env.sigs[0], &public).expect("signature");

    let bytes = env.to_bytes().expect("encode");
    let back = Envelope::from_bytes(&bytes).expect("decode");
    let decoded = ActionResult::from_envelope_payload(&back.payload.0).expect("result");
    assert_eq!(decoded, r);
    assert_eq!(decoded.cmd_id.0, CMD_ID);
    assert_eq!(decoded.definition_content_id.0, v.content_id);

    let mut tampered = back.clone();
    let last = tampered.payload.0.len() - 1;
    tampered.payload.0[last] ^= 1;
    assert!(tampered.verify_sig(&tampered.sigs[0], &public).is_err());
    let other = PublicKey::from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&[0x66; 32])
            .verifying_key()
            .to_bytes(),
    )
    .expect("key");
    assert!(back.verify_sig(&back.sigs[0], &other).is_err());
}
