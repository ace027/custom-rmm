//! Supervisor behaviour with shell-script "agents" in a temp root: restart
//! backoff, trial promotion, health-timeout rollback and crash-loop rollback.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rmm_watchdog::apply;
use rmm_watchdog::state::{Slot, State};
use rmm_watchdog::supervisor::{Config, Supervisor};
use rmm_watchdog::{AGENT_FILE, hex, parse_roots};
use sha2::{Digest, Sha256};

/// Fixture time (see tests/fixtures/README.md).
const NOW: u64 = 1_800_000_000;

fn fixture_now() -> u64 {
    NOW
}

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Bootstrap agent 0.1.0: records its pid, then idles.
const BOOTSTRAP: &str = "#!/bin/sh\n\
if [ \"$1\" = --version ]; then echo 'rmm-agent 0.1.0'; exit 0; fi\n\
echo $$ >> \"$RMM_AGENT_STATE_DIR/bootstrap.pids\"\n\
exec sleep 600\n";

struct Harness {
    root: PathBuf,
    state_dir: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    started: Instant,
}

impl Harness {
    /// A root with a bootstrap agent; `stage` puts a release in pending/
    /// before the watchdog starts.
    fn start(name: &str, health_timeout: Duration, stage: Option<(&str, &str)>) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir().join(format!(
            "rmm-wd-sup-{}-{}-{name}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("root");
        let state_dir = base.join("state");
        let boot = root.join("bootstrap");
        fs::create_dir_all(&boot).expect("mkdir");
        fs::write(boot.join(AGENT_FILE), BOOTSTRAP).expect("bootstrap");
        fs::set_permissions(boot.join(AGENT_FILE), fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let h = Self {
            root,
            state_dir,
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
            started: Instant::now(),
        };
        if let Some((release, artifact)) = stage {
            h.stage(release, artifact);
        }
        h.spawn(health_timeout)
    }

    fn spawn(mut self, health_timeout: Duration) -> Self {
        let hex_key = String::from_utf8(fixture("root.pub.hex")).expect("utf8");
        let (roots, threshold) = parse_roots(&hex_key, None).expect("roots");
        let cfg = Config {
            root: self.root.clone(),
            state_dir: self.state_dir.clone(),
            agent_args: vec!["run".into()],
            health_timeout,
            roots,
            threshold,
            platform: "linux-x86_64".into(),
            clock: fixture_now,
        };
        let mut sup = Supervisor::new(cfg).expect("supervisor");
        let stop = self.stop.clone();
        self.started = Instant::now();
        self.handle = Some(thread::spawn(move || sup.run(&stop)));
        self
    }

    fn stage(&self, release: &str, artifact: &str) {
        let p = self.root.join(apply::PENDING_DIR);
        fs::create_dir_all(&p).expect("mkdir pending");
        fs::write(p.join(apply::MANIFEST_FILE), fixture("manifest.env")).expect("manifest");
        fs::write(p.join(apply::RELEASE_FILE), fixture(release)).expect("release");
        fs::write(p.join(apply::ARTIFACT_FILE), fixture(artifact)).expect("artifact");
        fs::write(p.join(apply::READY_FILE), b"").expect("ready");
    }

    fn state(&self) -> Option<State> {
        let b = fs::read(self.root.join("state.json")).ok()?;
        serde_json::from_slice(&b).ok()
    }

    fn bootstrap_pids(&self) -> Vec<u32> {
        fs::read_to_string(self.state_dir.join("bootstrap.pids"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    /// Poll `f` every 50 ms until it returns Some or `limit` passes.
    fn wait<T>(&self, limit: Duration, what: &str, mut f: impl FnMut(&Self) -> Option<T>) -> T {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(v) = f(self) {
                return v;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if let Some(base) = self.root.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

fn sha_hex(name: &str) -> String {
    hex(&Sha256::digest(fixture(name)))
}

#[test]
fn killed_agent_restarts_at_first_backoff() {
    let h = Harness::start("restart", Duration::from_secs(3), None);
    let pid = h.wait(Duration::from_secs(5), "first start", |h| {
        h.bootstrap_pids().first().copied()
    });
    let status = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .expect("kill");
    assert!(status.success());
    let killed = Instant::now();
    let next = h.wait(Duration::from_secs(5), "restart", |h| {
        h.bootstrap_pids().get(1).copied()
    });
    let took = killed.elapsed();
    assert_ne!(next, pid);
    assert!(took < Duration::from_secs(2), "restart took {took:?}");
    assert!(
        took >= Duration::from_millis(900),
        "backoff skipped: {took:?}"
    );
}

#[test]
fn healthy_trial_is_promoted() {
    let h = Harness::start(
        "promote",
        Duration::from_secs(3),
        Some(("release-0.1.1.env", "agent-0.1.1.sh")),
    );
    let s = h.wait(Duration::from_secs(5), "promotion", |h| {
        h.state()
            .filter(|s| s.trial.is_none() && s.active == Slot::A)
    });
    assert_eq!(s.active_version, "0.1.1");
    assert_eq!(s.previous, Some(Slot::Bootstrap));
    assert_eq!(s.release_seq_floor, 2);
    assert!(s.bad_hashes.is_empty());
    assert!(h.bootstrap_pids().is_empty(), "bootstrap never ran");
    assert!(!h.root.join(apply::PENDING_DIR).exists());
}

#[test]
fn silent_trial_rolls_back_within_timeout_and_is_never_retried() {
    let timeout = Duration::from_secs(3);
    let h = Harness::start(
        "silent",
        timeout,
        Some(("release-silent.env", "agent-silent.sh")),
    );
    let bad = sha_hex("agent-silent.sh");
    h.wait(Duration::from_secs(3), "trial", |h| {
        h.state().and_then(|s| s.trial)
    });
    let s = h.wait(timeout + Duration::from_secs(2), "rollback", |h| {
        h.state()
            .filter(|s| s.trial.is_none() && s.bad_hashes.contains(&bad))
    });
    let took = h.started.elapsed();
    assert!(took >= timeout, "rolled back early: {took:?}");
    assert_eq!(
        (s.active, s.active_version.as_str()),
        (Slot::Bootstrap, "0.1.0")
    );
    assert_eq!(s.release_seq_floor, 6, "floor stays at the bad release");
    let pid = h.wait(Duration::from_secs(3), "bootstrap restart", |h| {
        h.bootstrap_pids().first().copied()
    });

    // Staging the same release again is rejected without touching the agent.
    h.stage("release-silent.env", "agent-silent.sh");
    h.wait(Duration::from_secs(7), "pending discarded", |h| {
        (!h.root.join(apply::PENDING_DIR).exists()).then_some(())
    });
    let after = h.state().expect("state");
    assert_eq!(after, s);
    assert_eq!(h.bootstrap_pids(), vec![pid], "bootstrap kept running");
}

#[test]
fn crash_looping_trial_rolls_back_after_three_crashes() {
    // Long health timeout: only the crash rule can explain a quick rollback.
    let h = Harness::start(
        "crash",
        Duration::from_secs(60),
        Some(("release-crash.env", "agent-crash.sh")),
    );
    let bad = sha_hex("agent-crash.sh");
    let s = h.wait(Duration::from_secs(10), "rollback", |h| {
        h.state()
            .filter(|s| s.trial.is_none() && s.bad_hashes.contains(&bad))
    });
    let took = h.started.elapsed();
    // Crashes at about 0 s, 1 s and 3 s (backoff 1 s then 2 s).
    assert!(took >= Duration::from_millis(2500), "too early: {took:?}");
    assert!(took < Duration::from_secs(8), "too late: {took:?}");
    assert_eq!(s.active, Slot::Bootstrap);
    h.wait(Duration::from_secs(3), "bootstrap restart", |h| {
        h.bootstrap_pids().first().copied()
    });
}
