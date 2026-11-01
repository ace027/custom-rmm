//! The command verification chain against the 06-01 golden fixtures, plus
//! inbox redelivery and restart behaviour.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use rmm_agent_core::blocks::{Args, BlockOutput, BlockRunner, StepCtx};
use rmm_agent_core::commands::{
    self, Agent, Verified, VerifyCtx, accept, handle, load_trust, process_pending,
};
use rmm_agent_core::store::{STORE_KEY_FILE, Store};
use rmm_recipe::result::{ActionResult, Outcome, RejectReason, TYPE_RESULT};
use rmm_trust::envelope::Envelope;
use rmm_trust::keys::PublicKey;
use rmm_trust::verify::{DocKind, FixedClock, TrustStore};

const NOW: u64 = 1_800_000_000;
const AGENT_ID: &str = "agent_0000000000000001";
const CLIENT_ID: &str = "client_0000000000000001";
const AGENT_SEED: [u8; 32] = [0x55; 32];

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmm-cmd-test-{}-{}",
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

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn root_key() -> PublicKey {
    let hex = String::from_utf8(fixture("root.pub.hex")).expect("utf8");
    let (keys, threshold) = commands::parse_roots(hex.trim(), None).expect("root key");
    assert_eq!(threshold, 1);
    keys.into_iter().next().expect("one root")
}

fn open(dir: &Path) -> Store {
    let key = rmm_platform::keystore_named(dir, STORE_KEY_FILE);
    Store::open(dir, key.as_ref()).expect("open store")
}

/// A store holding the fixture manifest and revocations, as after enrollment.
fn enrolled_store(dir: &Path) -> Store {
    let store = open(dir);
    store
        .trust_put(DocKind::Manifest, &fixture("manifest.env"))
        .expect("manifest");
    store
        .trust_put(DocKind::Revocations, &fixture("revocations.env"))
        .expect("revocations");
    store
}

fn trust(store: &Store) -> TrustStore {
    load_trust(store, vec![root_key()], 1, &FixedClock(NOW))
}

fn verify_with(
    store: &Store,
    trust: &TrustStore,
    env: &[u8],
    version: &str,
) -> Result<Verified, RejectReason> {
    let mut replay = store;
    let mut ctx = VerifyCtx {
        trust,
        agent_id: AGENT_ID,
        client_id: CLIENT_ID,
        clock: &FixedClock(NOW),
        replay: &mut replay,
        agent_version: version,
    };
    commands::verify(env, &mut ctx)
}

/// Verify one fixture against a freshly enrolled store.
fn verify_fixture(name: &str) -> Result<Verified, RejectReason> {
    let tmp = TempDir::new();
    let store = enrolled_store(tmp.path());
    let trust = trust(&store);
    verify_with(&store, &trust, &fixture(name), "0.1.0")
}

fn agent() -> Agent {
    Agent::new(AGENT_ID, CLIENT_ID, AGENT_SEED, vec![root_key()], 1)
}

/// Accepts every block; records what ran.
#[derive(Debug, Default)]
struct Recorder(Mutex<Vec<String>>);

impl Recorder {
    fn calls(&self) -> Vec<String> {
        self.0.lock().expect("lock").clone()
    }
}

impl BlockRunner for Recorder {
    fn run(&self, block: &str, _args: &Args, _ctx: &StepCtx<'_>) -> Result<BlockOutput, String> {
        self.0.lock().expect("lock").push(block.to_owned());
        Ok(BlockOutput {
            snapshot: Some("running".into()),
            detail: String::new(),
        })
    }
}

/// Decode and check every queued result envelope (agent-signed).
fn queued_results(store: &Store) -> Vec<ActionResult> {
    let public = PublicKey::from_bytes(
        &ed25519_dalek::SigningKey::from_bytes(&AGENT_SEED)
            .verifying_key()
            .to_bytes(),
    )
    .expect("agent key");
    store
        .outbox_peek(100)
        .expect("peek")
        .into_iter()
        .map(|item| {
            assert_eq!(item.priority, 0);
            assert_eq!(item.subject, format!("result.{CLIENT_ID}.{AGENT_ID}"));
            let env = Envelope::from_bytes(&item.payload).expect("envelope");
            assert_eq!(env.r#type, TYPE_RESULT);
            env.verify_sig(&env.sigs[0], &public)
                .expect("agent signature");
            ActionResult::from_envelope_payload(&env.payload.0).expect("result")
        })
        .collect()
}

fn definition_id(name: &str) -> [u8; 32] {
    Envelope::from_bytes(&fixture(name))
        .expect("definition envelope")
        .content_id()
}

#[test]
fn valid_command_verifies() {
    let v = verify_fixture("cmd-valid.env").expect("valid command");
    assert_eq!(v.definition.id, "printing.spooler-restart");
    assert_eq!(v.content_id, definition_id("definition-valid.env"));
    assert_eq!(v.command.agent_id, AGENT_ID);
    assert_eq!(v.command.cmd_id.0.len(), 16);
}

#[test]
fn good_param_verifies() {
    let v = verify_fixture("cmd-good-param.env").expect("param within bounds");
    assert_eq!(v.content_id, definition_id("definition-param.env"));
}

#[test]
fn expired_is_rejected() {
    assert_eq!(
        verify_fixture("cmd-expired.env").err(),
        Some(RejectReason::Expired)
    );
}

#[test]
fn second_delivery_is_a_replay() {
    let tmp = TempDir::new();
    let store = enrolled_store(tmp.path());
    let trust = trust(&store);
    let env = fixture("cmd-replay.env");
    assert!(verify_with(&store, &trust, &env, "0.1.0").is_ok());
    assert_eq!(
        verify_with(&store, &trust, &env, "0.1.0").err(),
        Some(RejectReason::Replay)
    );
    // The replay cache is persisted: a restarted agent still refuses it.
    drop(store);
    let store = open(tmp.path());
    let trust = self::trust(&store);
    assert_eq!(
        verify_with(&store, &trust, &env, "0.1.0").err(),
        Some(RejectReason::Replay)
    );
}

#[test]
fn tampered_is_a_bad_signature() {
    assert_eq!(
        verify_fixture("cmd-tampered.env").err(),
        Some(RejectReason::BadSignature)
    );
}

#[test]
fn revoked_definition_is_rejected() {
    assert_eq!(
        verify_fixture("cmd-revoked.env").err(),
        Some(RejectReason::Revoked)
    );
}

#[test]
fn non_catalog_definition_is_unsigned() {
    assert_eq!(
        verify_fixture("cmd-rogue-definition.env").err(),
        Some(RejectReason::UnsignedDefinition)
    );
}

#[test]
fn wrong_agent_is_rejected() {
    assert_eq!(
        verify_fixture("cmd-wrong-agent.env").err(),
        Some(RejectReason::WrongAgent)
    );
}

#[test]
fn unknown_block_fails_validation() {
    assert_eq!(
        verify_fixture("cmd-unknown-block.env").err(),
        Some(RejectReason::Validation)
    );
}

#[test]
fn bad_param_fails_validation() {
    assert_eq!(
        verify_fixture("cmd-bad-param.env").err(),
        Some(RejectReason::Validation)
    );
}

#[test]
fn old_agent_is_rejected() {
    let tmp = TempDir::new();
    let store = enrolled_store(tmp.path());
    let trust = trust(&store);
    assert_eq!(
        verify_with(&store, &trust, &fixture("cmd-valid.env"), "0.0.9").err(),
        Some(RejectReason::AgentVersion)
    );
}

#[test]
fn missing_trust_is_stale() {
    let tmp = TempDir::new();
    let store = open(tmp.path());
    let none = trust(&store);
    assert_eq!(
        verify_with(&store, &none, &fixture("cmd-valid.env"), "0.1.0").err(),
        Some(RejectReason::StaleTrust)
    );
    // A manifest without revocations is not fresh either.
    store
        .trust_put(DocKind::Manifest, &fixture("manifest.env"))
        .expect("manifest");
    let partial = trust(&store);
    assert!(partial.manifest().is_some());
    assert_eq!(
        verify_with(&store, &partial, &fixture("cmd-valid.env"), "0.1.0").err(),
        Some(RejectReason::StaleTrust)
    );
}

#[test]
fn rejected_commands_run_no_block_and_still_report() {
    let cases = [
        ("cmd-expired.env", RejectReason::Expired),
        ("cmd-tampered.env", RejectReason::BadSignature),
        ("cmd-revoked.env", RejectReason::Revoked),
        ("cmd-rogue-definition.env", RejectReason::UnsignedDefinition),
        ("cmd-wrong-agent.env", RejectReason::WrongAgent),
        ("cmd-unknown-block.env", RejectReason::Validation),
        ("cmd-bad-param.env", RejectReason::Validation),
    ];
    for (name, reason) in cases {
        let tmp = TempDir::new();
        let store = enrolled_store(tmp.path());
        let blocks = Recorder::default();
        accept(&store, &fixture(name)).expect("accept");
        let n = process_pending(&store, &agent(), &blocks, &FixedClock(NOW)).expect("process");
        assert_eq!(n, 1, "{name}");
        assert!(blocks.calls().is_empty(), "{name}: no block may run");
        let results = queued_results(&store);
        assert_eq!(results.len(), 1, "{name}");
        assert_eq!(results[0].outcome, Outcome::Rejected, "{name}");
        assert_eq!(results[0].reason, Some(reason), "{name}");
        assert_eq!(results[0].agent_id, AGENT_ID);
        assert_eq!(results[0].cmd_id.0.len(), 16);
        assert_eq!(store.inbox_pending_len().expect("pending"), 0);
    }
}

#[test]
fn redelivery_is_rejected_as_replay_and_reported() {
    let tmp = TempDir::new();
    let store = enrolled_store(tmp.path());
    let blocks = Recorder::default();
    let env = fixture("cmd-valid.env");
    let agent = agent();

    accept(&store, &env).expect("first delivery");
    assert_eq!(
        process_pending(&store, &agent, &blocks, &FixedClock(NOW)).expect("run"),
        1
    );
    let ran = blocks.calls().len();
    assert!(ran > 0, "the valid command runs");

    accept(&store, &env).expect("redelivery");
    assert_eq!(
        process_pending(&store, &agent, &blocks, &FixedClock(NOW)).expect("run"),
        1
    );
    assert_eq!(blocks.calls().len(), ran, "the replay runs nothing");

    let results = queued_results(&store);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].outcome, Outcome::Succeeded);
    assert_eq!(results[1].outcome, Outcome::Rejected);
    assert_eq!(results[1].reason, Some(RejectReason::Replay));
    assert_eq!(results[0].cmd_id, results[1].cmd_id);
    assert_eq!(
        results[0].definition_content_id.0,
        definition_id("definition-valid.env")
    );
}

#[test]
fn pending_command_survives_restart() {
    let tmp = TempDir::new();
    {
        let store = enrolled_store(tmp.path());
        accept(&store, &fixture("cmd-valid.env")).expect("accept");
        assert_eq!(store.inbox_pending_len().expect("pending"), 1);
        // Crash before executing: the store is dropped with the row pending.
    }
    let store = open(tmp.path());
    assert_eq!(store.inbox_pending_len().expect("pending"), 1);
    let blocks = Recorder::default();
    assert_eq!(
        process_pending(&store, &agent(), &blocks, &FixedClock(NOW)).expect("run"),
        1
    );
    assert_eq!(store.inbox_pending_len().expect("pending"), 0);
    let results = queued_results(&store);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].outcome, Outcome::Succeeded);

    // Crash after verifying but before the result was queued: the replay
    // cache already holds the id, so the retry is reported as a replay.
    accept(&store, &fixture("cmd-valid.env")).expect("accept again");
    drop(store);
    let store = open(tmp.path());
    let before = queued_results(&store).len();
    process_pending(&store, &agent(), &blocks, &FixedClock(NOW)).expect("run");
    let results = queued_results(&store);
    assert_eq!(results.len(), before + 1);
    assert_eq!(results[before].reason, Some(RejectReason::Replay));
}

#[test]
fn handle_reports_definition_and_command_ids() {
    let tmp = TempDir::new();
    let store = enrolled_store(tmp.path());
    let env = fixture("cmd-valid.env");
    let (cmd_id, def_id) = commands::envelope_ids(&env);
    let r = handle(
        &env,
        &agent(),
        &store,
        &Recorder::default(),
        &FixedClock(NOW),
    );
    assert_eq!(r.outcome, Outcome::Succeeded);
    assert_eq!(r.cmd_id.0, cmd_id);
    assert_eq!(r.definition_content_id.0, def_id);
    assert_eq!(def_id, definition_id("definition-valid.env"));
}
