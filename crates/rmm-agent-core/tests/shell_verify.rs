//! ShellOpen verification: every `ShellReject` reason, the success path, and
//! that the server command key alone can never open a shell. Trust documents
//! come from the xtask fixtures; assertions are signed here with the
//! documented software credential seeds (see `fixtures/README.md`).

use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use rmm_agent_core::commands::{self, Agent, handle_with, load_trust};
use rmm_agent_core::shell::{
    MemoryLink, PtyFactory, REASON_TECH_REMOVED, SessionConfig, ShellManager,
};
use rmm_agent_core::shell_verify::{ShellReject, VerifiedGrant, verify_shell_open};
use rmm_agent_core::store::{STORE_KEY_FILE, Store};
use rmm_platform::PlatformError;
use rmm_platform::pty::{Pty, ShellKind};
use rmm_proto::canonical::to_canonical_vec;
use rmm_proto::shell::ShellOut;
use rmm_recipe::result::{ActionResult, Outcome, RejectReason};
use rmm_trust::docs::{Command, CommandBody, ShellGrant};
use rmm_trust::envelope::{
    ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, TYPE_COMMAND, signing_message,
};
use rmm_trust::keys::{Bytes, PublicKey, Sig64};
use rmm_trust::verify::{DocKind, FixedClock, TrustStore};
use rmm_trust::webauthn::{Assertion, shell_challenge};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000;
const AGENT_ID: &str = "agent_0000000000000001";
const CLIENT_ID: &str = "client_0000000000000001";
const AGENT_SEED: [u8; 32] = [0x55; 32];
const COMMAND_SEED: [u8; 32] = [0x33; 32];
const ALICE_SEED: [u8; 32] = [0x66; 32];
const BOB_SEED: [u8; 32] = [0x67; 32];
const CAROL_SEED: [u8; 32] = [0x68; 32];
const RP_ID: &str = "console.example.test";
const ORIGIN: &str = "https://console.example.test";
/// The allowlisted shell of the platform the tests run on.
const SHELL: &str = if cfg!(windows) { "cmd" } else { "sh" };
const KIND: ShellKind = if cfg!(windows) {
    ShellKind::Cmd
} else {
    ShellKind::Sh
};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmm-shell-verify-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
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
    let (keys, _) = commands::parse_roots(hex.trim(), None).expect("root key");
    keys.into_iter().next().expect("one root")
}

/// A store holding the fixture manifest, revocations and technician list.
fn store(dir: &TempDir, with_techlist: bool) -> Store {
    let key = rmm_platform::keystore_named(&dir.0, STORE_KEY_FILE);
    let store = Store::open(&dir.0, key.as_ref()).expect("open store");
    store
        .trust_put(DocKind::Manifest, &fixture("manifest.env"))
        .expect("manifest");
    store
        .trust_put(DocKind::Revocations, &fixture("revocations.env"))
        .expect("revocations");
    if with_techlist {
        store
            .trust_put(DocKind::Techlist, &fixture("techlist.env"))
            .expect("techlist");
    }
    store
}

fn trust(store: &Store) -> TrustStore {
    load_trust(store, vec![root_key()], 1, &FixedClock(NOW))
}

fn agent() -> Agent {
    Agent::new(AGENT_ID, CLIENT_ID, AGENT_SEED, vec![root_key()], 1)
}

fn grant(n: u8) -> ShellGrant {
    ShellGrant {
        grant_id: Bytes(vec![n; 16]),
        agent_id: AGENT_ID.into(),
        client_id: CLIENT_ID.into(),
        tech_id: "tech_alice".into(),
        cred_id: Bytes(vec![0xA1; 16]),
        issued_at: NOW - 5,
        open_by: NOW + 60,
        max_duration: 3600,
        shell: SHELL.into(),
        record: true,
        e2e_pubkey: None,
    }
}

fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
    to_canonical_vec(v).expect("encode")
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for ch in data.chunks(3) {
        let n = ch
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, b)| a | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=ch.len() {
            s.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    s
}

/// What the authenticator returns for `challenge_over`.
struct Auth<'a> {
    seed: [u8; 32],
    flags: u8,
    rp_id: &'a str,
    origin: &'a str,
}

const ALICE: Auth<'static> = Auth {
    seed: ALICE_SEED,
    flags: 0x05,
    rp_id: RP_ID,
    origin: ORIGIN,
};

fn assertion(grant_bytes: &[u8], a: &Auth<'_>) -> Assertion {
    let mut ad = Sha256::digest(a.rp_id.as_bytes()).to_vec();
    ad.push(a.flags);
    ad.extend_from_slice(&7u32.to_be_bytes());
    let cdj = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
        b64url(&shell_challenge(grant_bytes)),
        a.origin
    )
    .into_bytes();
    let mut msg = ad.clone();
    msg.extend_from_slice(&Sha256::digest(&cdj));
    let sig = SigningKey::from_bytes(&a.seed).sign(&msg);
    Assertion {
        authenticator_data: ad,
        client_data_json: cdj,
        signature: sig.to_bytes().to_vec(),
    }
}

fn command(n: u8, body: CommandBody) -> Command {
    Command {
        cmd_id: Bytes(vec![n; 16]),
        agent_id: AGENT_ID.into(),
        client_id: CLIENT_ID.into(),
        issued_at: NOW - 10,
        expires_at: NOW + 590,
        policy_hash: Bytes(vec![0; 32]),
        body,
    }
}

/// Sign a command with the fixture server command key (seed 0x33).
fn signed(cmd: &Command) -> Vec<u8> {
    let payload = enc(cmd);
    let key = SigningKey::from_bytes(&COMMAND_SEED);
    let public = PublicKey::from_bytes(&key.verifying_key().to_bytes()).expect("key");
    let sig = key.sign(&signing_message(TYPE_COMMAND, &payload));
    Envelope {
        v: ENVELOPE_VERSION,
        r#type: TYPE_COMMAND.into(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: public.key_id(),
            alg: ALG_ED25519.into(),
            sig: Sig64(sig.to_bytes()),
        }],
    }
    .to_bytes()
    .expect("envelope")
}

fn shell_open(n: u8, grant_bytes: Vec<u8>, a: &Assertion) -> Command {
    command(
        n,
        CommandBody::ShellOpen {
            grant: Bytes(grant_bytes),
            assertion: Bytes(enc(a)),
        },
    )
}

/// Runs `verify_shell_open` against the fixture trust with a fresh replay set.
struct Verifier {
    trust: TrustStore,
    seen: RefCell<BTreeSet<Vec<u8>>>,
    _dir: TempDir,
}

impl Verifier {
    fn new(with_techlist: bool) -> Self {
        let dir = TempDir::new();
        let trust = trust(&store(&dir, with_techlist));
        assert!(trust.manifest().is_some());
        assert_eq!(trust.techlist().is_some(), with_techlist);
        Self {
            trust,
            seen: RefCell::new(BTreeSet::new()),
            _dir: dir,
        }
    }

    fn check_cmd(
        &self,
        cmd: &Command,
        grant_bytes: &[u8],
        a: &Assertion,
    ) -> Result<VerifiedGrant, ShellReject> {
        let seen = |k: &[u8]| !self.seen.borrow_mut().insert(k.to_vec());
        verify_shell_open(
            cmd,
            grant_bytes,
            a,
            &self.trust,
            AGENT_ID,
            CLIENT_ID,
            NOW,
            &seen,
        )
    }

    fn check_bytes(&self, grant_bytes: &[u8], a: &Assertion) -> Result<VerifiedGrant, ShellReject> {
        self.check_cmd(
            &command(
                1,
                CommandBody::Collect {
                    kind: String::new(),
                },
            ),
            grant_bytes,
            a,
        )
    }

    /// Grant signed by `auth`.
    fn check(&self, g: &ShellGrant, auth: &Auth<'_>) -> Result<VerifiedGrant, ShellReject> {
        let bytes = enc(g);
        self.check_bytes(&bytes, &assertion(&bytes, auth))
    }
}

fn err(r: Result<VerifiedGrant, ShellReject>) -> ShellReject {
    r.expect_err("expected a rejection")
}

#[test]
fn valid_co_signed_grant_is_accepted() {
    let v = Verifier::new(true);
    let ok = v.check(&grant(1), &ALICE).expect("accepted");
    assert_eq!(ok.tech_id, "tech_alice");
    assert_eq!(ok.kind, KIND);
    assert_eq!(ok.sid(), "01".repeat(16));
    // Scope "*" covers every client.
    let mut g = grant(2);
    g.tech_id = "tech_carol".into();
    g.cred_id = Bytes(vec![0xC1; 16]);
    let carol = Auth {
        seed: CAROL_SEED,
        ..ALICE
    };
    assert!(v.check(&g, &carol).is_ok());
}

#[test]
fn bad_grant() {
    let v = Verifier::new(true);
    let a = assertion(b"junk", &ALICE);
    assert_eq!(err(v.check_bytes(b"junk", &a)), ShellReject::BadGrant);
    let mut g = grant(1);
    g.grant_id = Bytes(vec![1; 15]);
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::BadGrant);
    let mut g = grant(1);
    g.e2e_pubkey = Some(Bytes(vec![9; 32]));
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::BadGrant);
    // Non-canonical bytes (a trailing byte) are not the grant.
    let mut bytes = enc(&grant(1));
    bytes.push(0);
    let a = assertion(&bytes, &ALICE);
    assert_eq!(err(v.check_bytes(&bytes, &a)), ShellReject::BadGrant);
}

#[test]
fn binding() {
    let v = Verifier::new(true);
    let mut g = grant(1);
    g.agent_id = "agent_0000000000000002".into();
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::Binding);
    let mut g = grant(2);
    g.client_id = "client_0000000000000099".into();
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::Binding);
    // The command carrying the grant is for another agent.
    let bytes = enc(&grant(3));
    let mut cmd = command(
        1,
        CommandBody::Collect {
            kind: String::new(),
        },
    );
    cmd.agent_id = "agent_0000000000000002".into();
    let a = assertion(&bytes, &ALICE);
    assert_eq!(err(v.check_cmd(&cmd, &bytes, &a)), ShellReject::Binding);
}

#[test]
fn expired() {
    let v = Verifier::new(true);
    let mut g = grant(1);
    g.issued_at = NOW - 300;
    g.open_by = NOW - 31;
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::Expired);
    // Within the 30 s grace it is still accepted.
    let mut g = grant(2);
    g.issued_at = NOW - 300;
    g.open_by = NOW - 30;
    assert!(v.check(&g, &ALICE).is_ok());
}

#[test]
fn max_duration() {
    let v = Verifier::new(true);
    for d in [0, 14_401, u32::MAX] {
        let mut g = grant(1);
        g.max_duration = d;
        assert_eq!(err(v.check(&g, &ALICE)), ShellReject::MaxDuration, "{d}");
    }
    let mut g = grant(2);
    g.max_duration = 14_400;
    assert!(v.check(&g, &ALICE).is_ok());
}

#[test]
fn shell_not_allowed() {
    let v = Verifier::new(true);
    let foreign = if cfg!(windows) { "sh" } else { "cmd" };
    for s in [
        "bash",
        "/bin/sh",
        "sh -c id",
        "powershell -EncodedCommand x",
        foreign,
        "",
    ] {
        let mut g = grant(1);
        g.shell = s.into();
        assert_eq!(
            err(v.check(&g, &ALICE)),
            ShellReject::ShellNotAllowed,
            "{s}"
        );
    }
}

#[test]
fn replay() {
    let v = Verifier::new(true);
    let g = grant(1);
    assert!(v.check(&g, &ALICE).is_ok());
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::Replay);
}

#[test]
fn refused_open_does_not_burn_the_grant_id() {
    let v = Verifier::new(true);
    let g = grant(1);
    // A forged assertion is refused, and must not use up the grant id...
    let forged = Auth {
        seed: COMMAND_SEED,
        ..ALICE
    };
    assert_eq!(err(v.check(&g, &forged)), ShellReject::BadAssertion);
    // ...so the technician's real co-signature still opens it, once.
    assert!(v.check(&g, &ALICE).is_ok());
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::Replay);
}

#[test]
fn unknown_tech() {
    let v = Verifier::new(true);
    let mut g = grant(1);
    g.tech_id = "tech_mallory".into();
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::UnknownTech);
    // Without a technician list nobody may open a shell.
    let v = Verifier::new(false);
    assert_eq!(err(v.check(&grant(2), &ALICE)), ShellReject::UnknownTech);
}

#[test]
fn out_of_scope() {
    let v = Verifier::new(true);
    let mut g = grant(1);
    g.tech_id = "tech_bob".into();
    g.cred_id = Bytes(vec![0xB1; 16]);
    let bob = Auth {
        seed: BOB_SEED,
        ..ALICE
    };
    assert_eq!(err(v.check(&g, &bob)), ShellReject::OutOfScope);
}

#[test]
fn unknown_credential() {
    let v = Verifier::new(true);
    let mut g = grant(1);
    g.cred_id = Bytes(vec![0xB1; 16]); // Bob's credential, not Alice's.
    assert_eq!(err(v.check(&g, &ALICE)), ShellReject::UnknownCredential);
}

#[test]
fn bad_assertion() {
    let v = Verifier::new(true);
    let cases: [(&str, Auth<'_>); 5] = [
        (
            "wrong key",
            Auth {
                seed: BOB_SEED,
                ..ALICE
            },
        ),
        (
            "server key",
            Auth {
                seed: COMMAND_SEED,
                ..ALICE
            },
        ),
        (
            "no user verification",
            Auth {
                flags: 0x01,
                ..ALICE
            },
        ),
        (
            "wrong rp",
            Auth {
                rp_id: "evil.example",
                ..ALICE
            },
        ),
        (
            "wrong origin",
            Auth {
                origin: "https://evil.example",
                ..ALICE
            },
        ),
    ];
    for (i, (what, auth)) in cases.iter().enumerate() {
        let g = grant(u8::try_from(i + 1).expect("small"));
        assert_eq!(err(v.check(&g, auth)), ShellReject::BadAssertion, "{what}");
    }
    // A valid assertion, but over a different grant.
    let other = enc(&grant(20));
    let bytes = enc(&grant(21));
    let a = assertion(&other, &ALICE);
    assert_eq!(err(v.check_bytes(&bytes, &a)), ShellReject::BadAssertion);
    // An empty assertion.
    let bytes = enc(&grant(22));
    let empty = Assertion {
        authenticator_data: vec![],
        client_data_json: vec![],
        signature: vec![],
    };
    assert_eq!(
        err(v.check_bytes(&bytes, &empty)),
        ShellReject::BadAssertion
    );
}

// ---- Full command chain -------------------------------------------------

#[derive(Debug, Default)]
struct IdleState {
    killed: bool,
}

/// A shell that prints nothing and runs until killed.
#[derive(Debug, Clone, Default)]
struct IdlePty(Arc<(Mutex<IdleState>, Condvar)>);

impl IdlePty {
    fn killed(&self) -> bool {
        self.0.0.lock().expect("lock").killed
    }
}

struct IdleReader(IdlePty);

impl Read for IdleReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        let (lock, cv) = &*self.0.0;
        let mut s = lock.lock().expect("lock");
        while !s.killed {
            s = cv.wait(s).expect("wait");
        }
        Ok(0)
    }
}

impl Pty for IdlePty {
    fn reader(&mut self) -> Box<dyn Read + Send> {
        Box::new(IdleReader(self.clone()))
    }
    fn writer(&mut self) -> Box<dyn Write + Send> {
        Box::new(std::io::sink())
    }
    fn resize(&self, _: u16, _: u16) -> Result<(), PlatformError> {
        Ok(())
    }
    fn kill(&mut self) -> Result<(), PlatformError> {
        self.0.0.lock().expect("lock").killed = true;
        self.0.1.notify_all();
        Ok(())
    }
    fn try_wait(&mut self) -> Result<Option<i32>, PlatformError> {
        Ok(self.killed().then_some(137))
    }
}

struct Chain {
    store: Arc<Store>,
    agent: Arc<Agent>,
    link: Arc<MemoryLink>,
    manager: ShellManager,
    ptys: Arc<Mutex<VecDeque<IdlePty>>>,
    _dir: TempDir,
}

impl Chain {
    fn new() -> Self {
        let dir = TempDir::new();
        let store = Arc::new(store(&dir, true));
        let link = Arc::new(MemoryLink::new());
        let ptys: Arc<Mutex<VecDeque<IdlePty>>> = Arc::default();
        let made = Arc::clone(&ptys);
        let factory: PtyFactory = Arc::new(move |_, _, _| {
            let p = IdlePty::default();
            made.lock().expect("lock").push_back(p.clone());
            Ok(Box::new(p) as Box<dyn Pty>)
        });
        let manager = ShellManager::with_pty_factory(
            AGENT_ID,
            link.clone(),
            None,
            SessionConfig::default(),
            factory,
        );
        Self {
            store,
            agent: Arc::new(agent()),
            link,
            manager,
            ptys,
            _dir: dir,
        }
    }

    /// Run one envelope through the full chain on a blocking thread.
    async fn handle(&self, env: Vec<u8>, with_manager: bool) -> ActionResult {
        let (store, agent) = (Arc::clone(&self.store), Arc::clone(&self.agent));
        let manager = with_manager.then(|| self.manager.clone());
        tokio::task::spawn_blocking(move || {
            let blocks = rmm_agent_core::blocks::PlatformBlocks::for_agent(Path::new("."));
            handle_with(
                &env,
                &agent,
                &store,
                &blocks,
                &FixedClock(NOW),
                manager.as_ref(),
            )
        })
        .await
        .expect("handle task")
    }
}

fn detail(r: &ActionResult) -> serde_json::Value {
    let stage = r.stages.first().expect("one stage");
    serde_json::from_str(&stage.detail).expect("json detail")
}

fn rejected_with(r: &ActionResult, reason: &str) {
    assert_eq!(r.outcome, Outcome::Rejected, "{r:?}");
    assert_eq!(detail(r)["status"], "rejected");
    assert_eq!(detail(r)["reason"], reason, "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_command_key_alone_never_opens_a_shell() {
    let c = Chain::new();
    // The checked-in fixture: a valid grant and command, forged assertion.
    let r = c.handle(fixture("cmd-shell-server-only.env"), true).await;
    rejected_with(
        &r,
        if cfg!(windows) {
            "shell_not_allowed"
        } else {
            "bad_assertion"
        },
    );
    // Everything else the server can make with its own key.
    let bytes = enc(&grant(0x30));
    let mut forged = assertion(
        &bytes,
        &Auth {
            seed: COMMAND_SEED,
            ..ALICE
        },
    );
    let r = c
        .handle(signed(&shell_open(0x31, bytes.clone(), &forged)), true)
        .await;
    rejected_with(&r, "bad_assertion");
    assert_eq!(r.reason, Some(RejectReason::BadSignature));
    forged.signature.clear();
    let bytes = enc(&grant(0x32));
    let r = c
        .handle(signed(&shell_open(0x33, bytes, &forged)), true)
        .await;
    rejected_with(&r, "bad_assertion");
    let cmd = command(
        0x34,
        CommandBody::ShellOpen {
            grant: Bytes(enc(&grant(0x35))),
            assertion: Bytes(b"not an assertion".to_vec()),
        },
    );
    rejected_with(&c.handle(signed(&cmd), true).await, "bad_assertion");
    assert_eq!(c.manager.active(), 0, "no session may have started");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn co_signed_open_starts_and_a_replayed_grant_is_refused() {
    let c = Chain::new();
    let bytes = enc(&grant(0x40));
    let a = assertion(&bytes, &ALICE);
    let r = c
        .handle(signed(&shell_open(0x41, bytes.clone(), &a)), true)
        .await;
    assert_eq!(r.outcome, Outcome::Succeeded, "{r:?}");
    assert_eq!(r.cmd_id.0, vec![0x41; 16]);
    assert_eq!(detail(&r)["status"], "started");
    assert_eq!(detail(&r)["sid"], "40".repeat(16));
    assert_eq!(c.manager.active(), 1);

    // The same grant and assertion in a new command (new cmd_id).
    let r = c
        .handle(signed(&shell_open(0x42, bytes.clone(), &a)), true)
        .await;
    rejected_with(&r, "replay");
    // The same command again is a command replay (generic reason, no stage).
    let r = c.handle(signed(&shell_open(0x41, bytes, &a)), true).await;
    assert_eq!(r.reason, Some(RejectReason::Replay));
    assert_eq!(c.manager.active(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_shell_manager_open_is_refused() {
    let c = Chain::new();
    let bytes = enc(&grant(0x50));
    let a = assertion(&bytes, &ALICE);
    let r = c.handle(signed(&shell_open(0x51, bytes, &a)), false).await;
    rejected_with(&r, "too_many_sessions");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_limit_is_reported() {
    let c = Chain::new();
    for n in [0x60u8, 0x62] {
        let bytes = enc(&grant(n));
        let a = assertion(&bytes, &ALICE);
        let r = c.handle(signed(&shell_open(n + 1, bytes, &a)), true).await;
        assert_eq!(r.outcome, Outcome::Succeeded);
    }
    let bytes = enc(&grant(0x64));
    let a = assertion(&bytes, &ALICE);
    let r = c.handle(signed(&shell_open(0x65, bytes, &a)), true).await;
    rejected_with(&r, "too_many_sessions");
    assert_eq!(c.manager.active(), 2);
}

fn trust_update(n: u8, techlist: Vec<u8>) -> Vec<u8> {
    signed(&command(
        n,
        CommandBody::TrustUpdate {
            manifest: None,
            revocations: None,
            techlist: Some(Bytes(techlist)),
        },
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn techlist_update_locks_out_removed_technicians() {
    let c = Chain::new();
    let bytes = enc(&grant(0x70));
    let a = assertion(&bytes, &ALICE);
    let r = c.handle(signed(&shell_open(0x71, bytes, &a)), true).await;
    assert_eq!(r.outcome, Outcome::Succeeded, "{r:?}");
    let sid = "70".repeat(16);
    let mut relay = c.link.relay(&sid).expect("relay");

    // seq 2 without Alice: her open session is closed.
    let r = c
        .handle(trust_update(0x72, fixture("techlist-removed.env")), true)
        .await;
    assert_eq!(r.outcome, Outcome::Succeeded, "{r:?}");
    let msg = tokio::time::timeout(Duration::from_secs(2), relay.out.recv())
        .await
        .expect("closed in time")
        .expect("message");
    assert_eq!(
        msg,
        ShellOut::Closed {
            reason: REASON_TECH_REMOVED.into()
        }
    );
    for _ in 0..200 {
        if c.manager.active() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(c.manager.active(), 0);
    assert!(c.ptys.lock().expect("lock").iter().all(IdlePty::killed));

    // And she cannot open a new one.
    let bytes = enc(&grant(0x73));
    let a = assertion(&bytes, &ALICE);
    let r = c.handle(signed(&shell_open(0x74, bytes, &a)), true).await;
    rejected_with(&r, "unknown_tech");

    // Rolling back to seq 1 is refused and Alice stays locked out.
    let r = c
        .handle(trust_update(0x75, fixture("techlist.env")), true)
        .await;
    assert_eq!(r.outcome, Outcome::Rejected);
    let list = trust(&c.store);
    assert_eq!(list.techlist().map(|l| l.seq), Some(2));
    let bytes = enc(&grant(0x76));
    let a = assertion(&bytes, &ALICE);
    let r = c.handle(signed(&shell_open(0x77, bytes, &a)), true).await;
    rejected_with(&r, "unknown_tech");

    // A techlist not signed by the techlist role is refused.
    let r = c
        .handle(trust_update(0x78, fixture("manifest.env")), true)
        .await;
    assert_eq!(r.outcome, Outcome::Rejected);
    assert_eq!(trust(&c.store).techlist().map(|l| l.seq), Some(2));
}
