//! `state.json`: which slot is active, the release sequence floor, known-bad
//! artifact hashes and the trial in progress. Written atomically.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::{AGENT_FILE, log};

/// File name of the state inside the root.
pub const STATE_FILE: &str = "state.json";
/// Version assumed when the bootstrap binary does not report one.
pub const UNKNOWN_VERSION: &str = "0.0.0";

/// An agent install location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    /// `slots/a/`.
    A,
    /// `slots/b/`.
    B,
    /// `bootstrap/`, owned by the installer; read-only for the watchdog.
    Bootstrap,
}

impl Slot {
    /// Directory of the slot under `root`.
    pub fn dir(self, root: &Path) -> PathBuf {
        match self {
            Slot::A => root.join("slots").join("a"),
            Slot::B => root.join("slots").join("b"),
            Slot::Bootstrap => root.join("bootstrap"),
        }
    }

    /// The agent binary of the slot.
    pub fn binary(self, root: &Path) -> PathBuf {
        self.dir(root).join(AGENT_FILE)
    }

    /// The slot a new release is installed into while `self` is active.
    /// Never [`Slot::Bootstrap`].
    pub fn inactive(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B | Slot::Bootstrap => Slot::A,
        }
    }

    /// Name as written in `state.json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
            Slot::Bootstrap => "bootstrap",
        }
    }
}

/// A release installed but not yet proven healthy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trial {
    /// Slot the release was installed into.
    pub slot: Slot,
    /// Release version.
    pub version: String,
    /// Install time (Unix seconds).
    pub started_at: u64,
    /// Hex SHA-256 of the installed artifact (added to `bad_hashes` on rollback).
    pub sha256: String,
    /// Sequence number of the release.
    pub release_seq: u64,
}

/// Persistent watchdog state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Slot whose agent runs when no trial is in progress.
    pub active: Slot,
    /// Version of the active slot's agent.
    pub active_version: String,
    /// Slot that was active before the last promotion.
    pub previous: Option<Slot>,
    /// Releases must have a sequence number above this.
    pub release_seq_floor: u64,
    /// Hex SHA-256 of artifacts that failed a trial; never installed again.
    pub bad_hashes: Vec<String>,
    /// Trial in progress, if any.
    pub trial: Option<Trial>,
}

impl State {
    /// Fresh state running the bootstrap agent of `version`.
    pub fn bootstrap(version: String) -> Self {
        Self {
            active: Slot::Bootstrap,
            active_version: version,
            previous: None,
            release_seq_floor: 0,
            bad_hashes: Vec::new(),
            trial: None,
        }
    }

    /// Load `<root>/state.json`. A missing or corrupt file falls back to the
    /// bootstrap slot, with the version reported by `bootstrap/rmm-agent
    /// --version`; only other I/O errors are returned.
    pub fn load(root: &Path) -> io::Result<Self> {
        let path = root.join(STATE_FILE);
        let why = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
                Ok(s) if s.is_consistent() => return Ok(s),
                Ok(_) => "inconsistent".to_owned(),
                Err(e) => e.to_string(),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let version = bootstrap_version(root);
                log(
                    "state_initialized",
                    serde_json::json!({ "active": "bootstrap", "active_version": version }),
                );
                return Ok(Self::bootstrap(version));
            }
            Err(e) => return Err(e),
        };
        let version = bootstrap_version(root);
        log(
            "state_corrupt",
            serde_json::json!({ "error": why, "fallback": "bootstrap", "active_version": version }),
        );
        Ok(Self::bootstrap(version))
    }

    /// Save to `<root>/state.json` (temp file, fsync, rename, fsync dir).
    pub fn save(&self, root: &Path) -> io::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        bytes.push(b'\n');
        fs::create_dir_all(root)?;
        write_atomic(&root.join(STATE_FILE), &bytes)
    }

    fn is_consistent(&self) -> bool {
        self.trial
            .as_ref()
            .is_none_or(|t| t.slot != Slot::Bootstrap)
    }

    /// Slot whose agent should run now: the trial's slot during a trial.
    pub fn running_slot(&self) -> Slot {
        self.trial.as_ref().map_or(self.active, |t| t.slot)
    }

    /// Version of the agent that should run now.
    pub fn running_version(&self) -> &str {
        self.trial
            .as_ref()
            .map_or(self.active_version.as_str(), |t| t.version.as_str())
    }
}

/// Version printed by `bootstrap/rmm-agent --version` (last word of the first
/// line, e.g. `rmm-agent 0.1.0`), or [`UNKNOWN_VERSION`].
pub fn bootstrap_version(root: &Path) -> String {
    let bin = Slot::Bootstrap.binary(root);
    let out = Command::new(&bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let version = match &out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().last())
            .filter(|v| rmm_trust::docs::is_semver(v))
            .map(str::to_owned),
        _ => None,
    };
    version.unwrap_or_else(|| {
        log(
            "bootstrap_version_unknown",
            serde_json::json!({
                "binary": bin.display().to_string(),
                "error": match out {
                    Ok(o) => format!("exit {:?}", o.status.code()),
                    Err(e) => e.to_string(),
                },
            }),
        );
        UNKNOWN_VERSION.to_owned()
    })
}

/// Make a completed rename in `dir` durable (no-op where directories cannot
/// be opened, i.e. Windows).
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    if cfg!(unix) {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Write `bytes` to `path` via `<path>.tmp`, fsync and rename.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(())
}

/// Semantic-version precedence (semver.org 2.0.0 section 11); build metadata
/// is ignored. `None` when either side is not a semantic version.
pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    fn split(v: &str) -> (&str, Option<&str>) {
        let core = v.split_once('+').map_or(v, |(c, _)| c);
        match core.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (core, None),
        }
    }
    // Digit strings without leading zeros: longer is larger.
    fn num(a: &str, b: &str) -> Ordering {
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }
    if !rmm_trust::docs::is_semver(a) || !rmm_trust::docs::is_semver(b) {
        return None;
    }
    let ((ca, pa), (cb, pb)) = (split(a), split(b));
    for (x, y) in ca.split('.').zip(cb.split('.')) {
        let o = num(x, y);
        if o != Ordering::Equal {
            return Some(o);
        }
    }
    Some(match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(pa), Some(pb)) => {
            let mut ia = pa.split('.');
            let mut ib = pb.split('.');
            loop {
                match (ia.next(), ib.next()) {
                    (None, None) => break Ordering::Equal,
                    (None, Some(_)) => break Ordering::Less,
                    (Some(_), None) => break Ordering::Greater,
                    (Some(x), Some(y)) => {
                        let dx = x.bytes().all(|c| c.is_ascii_digit());
                        let dy = y.bytes().all(|c| c.is_ascii_digit());
                        let o = match (dx, dy) {
                            (true, true) => num(x, y),
                            (true, false) => Ordering::Less,
                            (false, true) => Ordering::Greater,
                            (false, false) => x.cmp(y),
                        };
                        if o != Ordering::Equal {
                            break o;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::{Equal, Greater, Less};

    #[test]
    fn semver_precedence() {
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.2.0",
            "1.10.0",
            "2.0.0",
        ];
        for w in chain.windows(2) {
            assert_eq!(compare_versions(w[0], w[1]), Some(Less), "{w:?}");
            assert_eq!(compare_versions(w[1], w[0]), Some(Greater), "{w:?}");
        }
        assert_eq!(compare_versions("1.0.0+a", "1.0.0+b"), Some(Equal));
        assert_eq!(compare_versions("1.0", "1.0.0"), None);
    }

    #[test]
    fn inactive_is_never_bootstrap() {
        assert_eq!(Slot::Bootstrap.inactive(), Slot::A);
        assert_eq!(Slot::A.inactive(), Slot::B);
        assert_eq!(Slot::B.inactive(), Slot::A);
    }
}
