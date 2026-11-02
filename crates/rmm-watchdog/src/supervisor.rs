//! Runs the agent of the active (or trial) slot, restarts it with backoff,
//! polls `pending/` for releases and decides trials by the agent's health
//! signal. std threads and processes only.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rmm_trust::keys::PublicKey;
use serde::Deserialize;
use serde_json::json;

use crate::apply::{self, Staged};
use crate::log;
use crate::state::State;

/// Restart delays after consecutive exits (the last one repeats).
pub const BACKOFF: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];
/// Uptime after which the backoff starts over.
pub const BACKOFF_RESET: Duration = Duration::from_secs(60);
/// How often `pending/` is checked.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Grace period between asking the agent to stop and killing it.
pub const STOP_GRACE: Duration = Duration::from_secs(10);
/// Exits during a trial that trigger a rollback.
pub const TRIAL_MAX_CRASHES: u32 = 3;
/// Default time a trial has to report healthy.
pub const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(180);
/// Largest accepted health timeout.
pub const MAX_HEALTH_TIMEOUT: Duration = Duration::from_secs(300);
/// Health signal file written by the agent into its state dir.
pub const HEALTH_FILE: &str = "health.json";
/// Environment variable that tells the agent its state dir.
pub const STATE_DIR_ENV: &str = "RMM_AGENT_STATE_DIR";

const TICK: Duration = Duration::from_millis(100);

/// Supervisor settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Watchdog root (slots, bootstrap, pending, state.json).
    pub root: PathBuf,
    /// Agent state dir, passed as `RMM_AGENT_STATE_DIR`.
    pub state_dir: PathBuf,
    /// Arguments for the agent binary.
    pub agent_args: Vec<OsString>,
    /// Time a trial has to report healthy (at most [`MAX_HEALTH_TIMEOUT`]).
    pub health_timeout: Duration,
    /// Compiled-in root keys.
    pub roots: Vec<PublicKey>,
    /// Root signature threshold before a manifest is applied.
    pub threshold: u8,
    /// Release platform string, e.g. `linux-x86_64`.
    pub platform: String,
    /// Unix time source for release verification and `started_at`.
    pub clock: fn() -> u64,
}

#[derive(Debug, Deserialize)]
struct Health {
    version: String,
    pid: u32,
}

#[derive(Debug)]
struct Running {
    child: Child,
    started: Instant,
}

#[derive(Debug)]
struct TrialRun {
    deadline: Instant,
    crashes: u32,
}

/// Owns the agent child process and the watchdog state.
#[derive(Debug)]
pub struct Supervisor {
    cfg: Config,
    state: State,
    child: Option<Running>,
    trial: Option<TrialRun>,
    backoff: usize,
    next_start: Instant,
    next_poll: Instant,
}

impl Supervisor {
    /// Load the state and prepare to run. A trial left over from a previous
    /// run (power loss, watchdog restart) resumes with a fresh health window.
    pub fn new(mut cfg: Config) -> std::io::Result<Self> {
        cfg.health_timeout = cfg.health_timeout.min(MAX_HEALTH_TIMEOUT);
        fs::create_dir_all(&cfg.root)?;
        fs::create_dir_all(&cfg.state_dir)?;
        let state = State::load(&cfg.root)?;
        let now = Instant::now();
        let trial = state.trial.as_ref().map(|t| {
            log(
                "trial_resumed",
                json!({ "slot": t.slot.as_str(), "version": t.version }),
            );
            TrialRun {
                deadline: now + cfg.health_timeout,
                crashes: 0,
            }
        });
        Ok(Self {
            cfg,
            state,
            child: None,
            trial,
            backoff: 0,
            next_start: now,
            next_poll: now,
        })
    }

    /// Current state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Supervise until `stop` is set, then stop the agent and return.
    pub fn run(&mut self, stop: &AtomicBool) {
        log(
            "watchdog_started",
            json!({
                "active": self.state.active.as_str(),
                "active_version": self.state.active_version,
                "trial": self.state.trial.as_ref().map(|t| t.version.clone()),
            }),
        );
        while !stop.load(Ordering::SeqCst) {
            self.reap();
            self.evaluate_trial();
            let now = Instant::now();
            if self.trial.is_none() && now >= self.next_poll {
                self.next_poll = now + POLL_INTERVAL;
                self.poll_pending();
            }
            if self.child.is_none() && Instant::now() >= self.next_start {
                self.start();
            }
            thread::sleep(TICK);
        }
        self.stop_child();
        log("watchdog_stopped", json!({}));
    }

    fn start(&mut self) {
        let slot = self.state.running_slot();
        let bin = slot.binary(&self.cfg.root);
        let spawned = Command::new(&bin)
            .args(&self.cfg.agent_args)
            .env(STATE_DIR_ENV, &self.cfg.state_dir)
            .stdin(Stdio::null())
            .spawn();
        match spawned {
            Ok(child) => {
                log(
                    "agent_started",
                    json!({
                        "slot": slot.as_str(),
                        "version": self.state.running_version(),
                        "pid": child.id(),
                    }),
                );
                self.child = Some(Running {
                    child,
                    started: Instant::now(),
                });
            }
            Err(e) => {
                log(
                    "agent_spawn_failed",
                    json!({ "slot": slot.as_str(), "binary": bin.display().to_string(), "error": e.to_string() }),
                );
                self.on_exit(Duration::ZERO);
            }
        }
    }

    fn reap(&mut self) {
        let Some(run) = &mut self.child else { return };
        match run.child.try_wait() {
            Ok(Some(status)) => {
                let uptime = run.started.elapsed();
                log(
                    "agent_exited",
                    json!({
                        "pid": run.child.id(),
                        "code": status.code(),
                        "uptime_ms": u64::try_from(uptime.as_millis()).unwrap_or(u64::MAX),
                    }),
                );
                self.child = None;
                self.on_exit(uptime);
            }
            Ok(None) => {}
            Err(e) => log("agent_wait_failed", json!({ "error": e.to_string() })),
        }
    }

    /// Schedule the next start and count trial crashes.
    fn on_exit(&mut self, uptime: Duration) {
        if uptime >= BACKOFF_RESET {
            self.backoff = 0;
        }
        let delay = BACKOFF[self.backoff.min(BACKOFF.len() - 1)];
        self.backoff = (self.backoff + 1).min(BACKOFF.len() - 1);
        self.next_start = Instant::now() + delay;
        if let Some(t) = &mut self.trial {
            t.crashes += 1;
            if t.crashes >= TRIAL_MAX_CRASHES {
                self.rollback("crash_loop");
            }
        }
    }

    fn evaluate_trial(&mut self) {
        let (Some(run), Some(t)) = (&self.trial, &self.state.trial) else {
            return;
        };
        let healthy = self
            .child
            .as_ref()
            .is_some_and(|c| health_ok(&self.cfg.state_dir, &t.version, c.child.id()));
        if healthy {
            self.promote();
        } else if Instant::now() >= run.deadline {
            self.rollback("health_timeout");
        }
    }

    fn promote(&mut self) {
        let mut next = self.state.clone();
        let Some(t) = next.trial.take() else { return };
        next.previous = Some(next.active);
        next.active = t.slot;
        next.active_version = t.version.clone();
        next.release_seq_floor = next.release_seq_floor.max(t.release_seq);
        self.commit(next);
        self.trial = None;
        self.backoff = 0;
        log(
            "trial_promoted",
            json!({ "slot": t.slot.as_str(), "version": t.version }),
        );
    }

    fn rollback(&mut self, reason: &str) {
        self.stop_child();
        let mut next = self.state.clone();
        let Some(t) = next.trial.take() else { return };
        if !next.bad_hashes.contains(&t.sha256) {
            next.bad_hashes.push(t.sha256.clone());
        }
        next.release_seq_floor = next.release_seq_floor.max(t.release_seq);
        self.commit(next);
        self.trial = None;
        self.backoff = 0;
        self.next_start = Instant::now();
        log(
            "trial_rolled_back",
            json!({
                "reason": reason,
                "slot": t.slot.as_str(),
                "version": t.version,
                "sha256": t.sha256,
                "restoring": self.state.active.as_str(),
            }),
        );
    }

    /// Adopt `next` and persist it; a failed save is logged and the
    /// in-memory decision stands (it is re-saved on the next transition).
    fn commit(&mut self, next: State) {
        if let Err(e) = next.save(&self.cfg.root) {
            log("state_save_failed", json!({ "error": e.to_string() }));
        }
        self.state = next;
    }

    fn poll_pending(&mut self) {
        let now = (self.cfg.clock)();
        let staged = match apply::check_pending(
            &self.cfg.root,
            &self.cfg.roots,
            self.cfg.threshold,
            &self.cfg.platform,
            &self.state,
            now,
        ) {
            Ok(Some(s)) => s,
            Ok(None) | Err(_) => return,
        };
        self.install(&staged, now);
    }

    fn install(&mut self, staged: &Staged, now: u64) {
        log(
            "release_staged",
            json!({ "version": staged.version, "release_seq": staged.release_seq }),
        );
        self.stop_child();
        // A stale signal from an earlier run must not count for the trial.
        let _ = fs::remove_file(self.cfg.state_dir.join(HEALTH_FILE));
        match apply::install(&self.cfg.root, &mut self.state, staged, now) {
            Ok(slot) => {
                log(
                    "release_installed",
                    json!({ "slot": slot.as_str(), "version": staged.version }),
                );
                self.trial = Some(TrialRun {
                    deadline: Instant::now() + self.cfg.health_timeout,
                    crashes: 0,
                });
            }
            Err(e) => log("install_failed", json!({ "error": e.to_string() })),
        }
        self.backoff = 0;
        self.next_start = Instant::now();
    }

    /// Ask the agent to exit, kill it after [`STOP_GRACE`] and reap it.
    fn stop_child(&mut self) {
        let Some(mut run) = self.child.take() else {
            return;
        };
        let pid = run.child.id();
        let grace = if terminate(pid) {
            STOP_GRACE
        } else {
            Duration::ZERO
        };
        let deadline = Instant::now() + grace;
        loop {
            match run.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(TICK),
                _ => {
                    let _ = run.child.kill();
                    let _ = run.child.wait();
                    break;
                }
            }
        }
        log("agent_stopped", json!({ "pid": pid }));
    }
}

/// Whether `<state_dir>/health.json` reports `version` for process `pid`.
fn health_ok(state_dir: &Path, version: &str, pid: u32) -> bool {
    fs::read(state_dir.join(HEALTH_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Health>(&b).ok())
        .is_some_and(|h| h.version == version && h.pid == pid)
}

/// Polite stop request: SIGTERM on unix (through `kill`, std has no signal
/// API). Windows has no equivalent for a console-less child, so there the
/// caller kills at once. Returns whether a request was sent.
fn terminate(pid: u32) -> bool {
    cfg!(unix)
        && Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}
