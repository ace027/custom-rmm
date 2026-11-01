//! Independent verification of a staged release and its install into the
//! inactive slot.
//!
//! The agent stages a release in `<root>/pending/`: `manifest.env` (the trust
//! manifest the release is signed under), `release.env` (the release
//! envelope), `artifact` (the agent binary) and finally an empty `READY`.
//! Until `READY` exists the directory is left alone. Once it exists the
//! release is either installed or rejected; in both cases `pending/` is
//! deleted.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use rmm_trust::docs::verify_release;
use rmm_trust::error::TrustError;
use rmm_trust::keys::PublicKey;
use rmm_trust::store::TrustStore;
use rmm_trust::verify::{FixedClock, MemorySeqStore};
use sha2::{Digest, Sha256};

use crate::state::{self, Slot, State, Trial, compare_versions};
use crate::{AGENT_FILE, hex, log};

/// Staging directory under the root.
pub const PENDING_DIR: &str = "pending";
/// Written last by the agent; marks `pending/` complete.
pub const READY_FILE: &str = "READY";
/// Trust manifest envelope.
pub const MANIFEST_FILE: &str = "manifest.env";
/// Release envelope.
pub const RELEASE_FILE: &str = "release.env";
/// The artifact for this platform.
pub const ARTIFACT_FILE: &str = "artifact";

const CHUNK: usize = 64 * 1024;

/// A verified release ready to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// Release version.
    pub version: String,
    /// Signed SHA-256 of this platform's artifact.
    pub sha256: [u8; 32],
    /// Signed size of this platform's artifact.
    pub size: u64,
    /// Release sequence number.
    pub release_seq: u64,
}

/// Why a staged release was rejected. [`ApplyReject::reason`] is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyReject {
    /// `READY` is present but `release.env` or `artifact` is missing.
    NoPending,
    /// The manifest is missing or does not chain to the compiled root keys.
    BadManifest,
    /// The release is not a valid envelope signed with the release role.
    BadRelease,
    /// The release is expired or not yet valid.
    Expired,
    /// The version is not newer than the active version.
    Downgrade,
    /// The sequence number is not above the floor.
    ReplayedSeq,
    /// The release has no artifact for this platform.
    NoArtifactForPlatform,
    /// The artifact size differs from the signed size.
    SizeMismatch,
    /// The artifact hash differs from the signed hash.
    HashMismatch,
    /// The artifact failed a previous trial.
    KnownBad,
}

impl ApplyReject {
    /// Stable machine-readable reason.
    pub fn reason(self) -> &'static str {
        match self {
            ApplyReject::NoPending => "no_pending",
            ApplyReject::BadManifest => "bad_manifest",
            ApplyReject::BadRelease => "bad_release",
            ApplyReject::Expired => "expired",
            ApplyReject::Downgrade => "downgrade",
            ApplyReject::ReplayedSeq => "replayed_seq",
            ApplyReject::NoArtifactForPlatform => "no_artifact_for_platform",
            ApplyReject::SizeMismatch => "size_mismatch",
            ApplyReject::HashMismatch => "hash_mismatch",
            ApplyReject::KnownBad => "known_bad",
        }
    }
}

impl std::fmt::Display for ApplyReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for ApplyReject {}

/// Delete `<root>/pending/` (absent is fine).
pub fn discard_pending(root: &Path) {
    match fs::remove_dir_all(root.join(PENDING_DIR)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => log(
            "pending_discard_failed",
            serde_json::json!({ "error": e.to_string() }),
        ),
    }
}

/// Verify the release staged in `<root>/pending/`. `Ok(None)` when nothing is
/// staged or `READY` is not written yet. On a reject `pending/` is deleted
/// and the reason logged.
pub fn check_pending(
    root: &Path,
    roots: &[PublicKey],
    threshold: u8,
    platform: &str,
    state: &State,
    now: u64,
) -> Result<Option<Staged>, ApplyReject> {
    let dir = root.join(PENDING_DIR);
    if !dir.join(READY_FILE).is_file() {
        return Ok(None);
    }
    match verify_pending(&dir, roots, threshold, platform, state, now) {
        Ok(staged) => Ok(Some(staged)),
        Err(reject) => {
            log(
                "release_rejected",
                serde_json::json!({ "reason": reject.reason() }),
            );
            discard_pending(root);
            Err(reject)
        }
    }
}

fn verify_pending(
    dir: &Path,
    roots: &[PublicKey],
    threshold: u8,
    platform: &str,
    state: &State,
    now: u64,
) -> Result<Staged, ApplyReject> {
    let release_bytes = fs::read(dir.join(RELEASE_FILE)).map_err(|_| ApplyReject::NoPending)?;
    let manifest_bytes = fs::read(dir.join(MANIFEST_FILE)).map_err(|_| ApplyReject::BadManifest)?;

    let mut store = TrustStore::new(roots.to_vec(), threshold);
    store
        .apply_manifest(
            &manifest_bytes,
            &FixedClock(now),
            &mut MemorySeqStore::new(),
        )
        .map_err(|_| ApplyReject::BadManifest)?;
    let (_, release) = verify_release(&store, &release_bytes, now).map_err(|e| match e {
        TrustError::Expired | TrustError::NotYetValid => ApplyReject::Expired,
        _ => ApplyReject::BadRelease,
    })?;

    if release.seq <= state.release_seq_floor {
        return Err(ApplyReject::ReplayedSeq);
    }
    let newer = compare_versions(&release.version, &state.active_version)
        .or_else(|| compare_versions(&release.version, state::UNKNOWN_VERSION))
        .is_some_and(|o| o.is_gt());
    if !newer {
        return Err(ApplyReject::Downgrade);
    }
    let artifact = release
        .artifact_for(platform)
        .ok_or(ApplyReject::NoArtifactForPlatform)?;
    let sha256: [u8; 32] = artifact
        .sha256
        .0
        .as_slice()
        .try_into()
        .map_err(|_| ApplyReject::BadRelease)?;
    let size = artifact.size;
    if state.bad_hashes.iter().any(|h| *h == hex(&sha256)) {
        return Err(ApplyReject::KnownBad);
    }

    let path = dir.join(ARTIFACT_FILE);
    let meta = fs::metadata(&path).map_err(|_| ApplyReject::NoPending)?;
    if !meta.is_file() {
        return Err(ApplyReject::NoPending);
    }
    if meta.len() != size {
        return Err(ApplyReject::SizeMismatch);
    }
    let mut file = File::open(&path).map_err(|_| ApplyReject::NoPending)?;
    let (got, read) =
        hash_copy(&mut file, &mut io::sink(), size).map_err(|_| ApplyReject::NoPending)?;
    if read != size {
        return Err(ApplyReject::SizeMismatch);
    }
    if got != sha256 {
        return Err(ApplyReject::HashMismatch);
    }
    Ok(Staged {
        version: release.version,
        sha256,
        size,
        release_seq: release.seq,
    })
}

/// Copy at most `limit + 1` bytes from `r` to `w`, returning their SHA-256
/// and count (a count above `limit` means the source grew).
fn hash_copy(r: &mut impl Read, w: &mut impl Write, limit: u64) -> io::Result<([u8; 32], u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    let mut src = r.take(limit.saturating_add(1));
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok((hasher.finalize().into(), total))
}

/// Install a verified release into the inactive slot and record it as the
/// trial (the release seq becomes the floor) before anything runs it. The
/// artifact is re-hashed while it is copied to `<slot>/rmm-agent.tmp`, which
/// is renamed over the slot binary only if it still matches. `pending/` is
/// deleted afterwards, whatever the outcome. Returns the slot written.
pub fn install(root: &Path, state: &mut State, staged: &Staged, now: u64) -> io::Result<Slot> {
    let result = install_inner(root, state, staged, now);
    discard_pending(root);
    result
}

fn install_inner(root: &Path, state: &mut State, staged: &Staged, now: u64) -> io::Result<Slot> {
    let slot = state.active.inactive();
    let dir = slot.dir(root);
    fs::create_dir_all(&dir)?;
    let target = dir.join(AGENT_FILE);
    let tmp = dir.join(format!("{AGENT_FILE}.tmp"));
    let copied = (|| {
        let mut src = File::open(root.join(PENDING_DIR).join(ARTIFACT_FILE))?;
        let mut dst = File::create(&tmp)?;
        let (got, size) = hash_copy(&mut src, &mut dst, staged.size)?;
        if size != staged.size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "size_mismatch"));
        }
        if got != staged.sha256 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "hash_mismatch"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            dst.set_permissions(fs::Permissions::from_mode(0o755))?;
        }
        dst.sync_all()
    })();
    if let Err(e) = copied {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, &target)?;
    state::sync_dir(&dir)?;

    // Only adopt the trial once it is durable, so nothing runs an unrecorded slot.
    let mut next = state.clone();
    next.trial = Some(Trial {
        slot,
        version: staged.version.clone(),
        started_at: now,
        sha256: hex(&staged.sha256),
        release_seq: staged.release_seq,
    });
    next.release_seq_floor = next.release_seq_floor.max(staged.release_seq);
    next.save(root)?;
    *state = next;
    Ok(slot)
}
