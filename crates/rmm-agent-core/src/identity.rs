//! Persistent agent identity: `identity.json` plus the trust bundle files.
//!
//! Nothing here is secret (the device key lives in the `KeyStore`), but the
//! files are still written atomically and with mode 0600 on Unix.

use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use rmm_proto::enroll::TrustBundle;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// File name of the identity inside the state directory.
pub const IDENTITY_FILE: &str = "identity.json";
/// Sub-directory holding the trust envelopes.
pub const TRUST_DIR: &str = "trust";
/// Signed manifest envelope.
pub const MANIFEST_FILE: &str = "manifest.env";
/// Signed revocations envelope.
pub const REVOCATIONS_FILE: &str = "revocations.env";
/// Signed technician list envelope.
pub const TECHLIST_FILE: &str = "techlist.env";

/// What the server assigned to this agent at enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Agent id; also the NATS inbox suffix.
    pub agent_id: Uuid,
    /// Device id (stable across reattach).
    pub device_id: Uuid,
    /// Owning client id.
    pub client_id: Uuid,
    /// NATS URL to connect to.
    pub nats_url: String,
    /// Base URL of the enrollment server.
    pub server_url: String,
}

/// Write `data` to `path` via a temp file in the same directory and a rename.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    let tmp: PathBuf = dir.join(tmp_name);
    let _ = fs::remove_file(&tmp);
    let write = || -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    };
    write().inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Load the identity; `Ok(None)` when the agent has not enrolled.
pub fn load(state_dir: &Path) -> io::Result<Option<Identity>> {
    match fs::read(state_dir.join(IDENTITY_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("identity.json: {e}"))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomically save the identity.
pub fn save(state_dir: &Path, identity: &Identity) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(identity)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    write_atomic(&state_dir.join(IDENTITY_FILE), &json)
}

/// Atomically save the trust envelopes; absent ones remove stale files.
pub fn save_trust(state_dir: &Path, bundle: &TrustBundle) -> io::Result<()> {
    let dir = state_dir.join(TRUST_DIR);
    for (file, data) in [
        (MANIFEST_FILE, &bundle.manifest),
        (REVOCATIONS_FILE, &bundle.revocations),
        (TECHLIST_FILE, &bundle.techlist),
    ] {
        match data {
            Some(bytes) => write_atomic(&dir.join(file), bytes)?,
            None => match fs::remove_file(dir.join(file)) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            },
        }
    }
    Ok(())
}

/// Remove the identity and trust files (used to roll back a failed enrollment).
pub fn remove(state_dir: &Path) {
    let _ = fs::remove_file(state_dir.join(IDENTITY_FILE));
    for file in [MANIFEST_FILE, REVOCATIONS_FILE, TECHLIST_FILE] {
        let _ = fs::remove_file(state_dir.join(TRUST_DIR).join(file));
    }
}
