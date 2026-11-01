//! Health signal for the watchdog.
//!
//! After every heartbeat the agent publishes it rewrites
//! `<state_dir>/health.json` as `{"version", "pid", "ts"}`. During a trial the
//! watchdog promotes the new release when the file names the trial's version
//! and the pid of the process it started, and rolls back when that does not
//! happen in time.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// File name inside the state directory.
pub const HEALTH_FILE: &str = "health.json";

/// Content of `health.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// Version of the running agent.
    pub version: String,
    /// Process id of the running agent.
    pub pid: u32,
    /// Write time (Unix seconds).
    pub ts: u64,
}

/// Atomically write `health.json` (temp file, fsync, rename).
pub fn write(state_dir: &Path, version: &str) -> io::Result<()> {
    let health = Health {
        version: version.to_owned(),
        pid: std::process::id(),
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    };
    let bytes = serde_json::to_vec(&health).map_err(io::Error::other)?;
    fs::create_dir_all(state_dir)?;
    let path = state_dir.join(HEALTH_FILE);
    let tmp = state_dir.join(format!("{HEALTH_FILE}.tmp"));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_version_and_own_pid() {
        let dir = std::env::temp_dir().join(format!("rmm-health-{}", std::process::id()));
        write(&dir, "1.2.3").expect("write");
        let h: Health =
            serde_json::from_slice(&fs::read(dir.join(HEALTH_FILE)).expect("read")).expect("json");
        assert_eq!((h.version.as_str(), h.pid), ("1.2.3", std::process::id()));
        assert!(!dir.join("health.json.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
