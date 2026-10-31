//! Device key storage: the agent's Ed25519 seed never leaves the device
//! unprotected. Windows uses DPAPI (see `windows.rs`); Unix uses a 0600 file.

use std::path::{Path, PathBuf};

use crate::PlatformError;

/// File name of the protected seed inside the state directory.
pub(crate) const KEY_FILE: &str = "agent.key";

/// Persistent, protected storage for the 32-byte agent key seed.
pub trait KeyStore: std::fmt::Debug + Send + Sync {
    /// Load the seed. `Ok(None)` only when no key has been stored; a damaged
    /// or unprotected key is an error, never a reason to make a new one.
    fn load(&self) -> Result<Option<[u8; 32]>, PlatformError>;
    /// Store the seed, replacing any existing one atomically.
    fn store(&self, seed: &[u8; 32]) -> Result<(), PlatformError>;
    /// Remove the stored seed; succeeds if there is none.
    fn delete(&self) -> Result<(), PlatformError>;
}

/// Key store rooted at `state_dir` for the current OS.
pub fn keystore(state_dir: &Path) -> Box<dyn KeyStore> {
    #[cfg(windows)]
    {
        Box::new(crate::windows::DpapiKeyStore::new(state_dir))
    }
    #[cfg(unix)]
    {
        Box::new(unix::FileKeyStore::new(state_dir))
    }
}

/// Default state directory: `%ProgramData%\RMM` on Windows, `/var/lib/rmm` on
/// Unix. `RMM_AGENT_STATE_DIR` overrides both.
pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("RMM_AGENT_STATE_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("RMM")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/rmm")
    }
}

#[cfg(unix)]
mod unix {
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    use zeroize::Zeroizing;

    use super::{KEY_FILE, KeyStore};
    use crate::PlatformError;

    fn os_err(what: &str, e: std::io::Error) -> PlatformError {
        PlatformError::Os(format!("{what}: {e}"))
    }

    #[derive(Debug)]
    pub(super) struct FileKeyStore {
        dir: PathBuf,
    }

    impl FileKeyStore {
        pub(super) fn new(dir: &Path) -> Self {
            Self {
                dir: dir.to_path_buf(),
            }
        }

        fn path(&self) -> PathBuf {
            self.dir.join(KEY_FILE)
        }
    }

    impl KeyStore for FileKeyStore {
        fn load(&self) -> Result<Option<[u8; 32]>, PlatformError> {
            let path = self.path();
            let mut file = match OpenOptions::new().read(true).open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(os_err("open key file", e)),
            };
            // Check the opened handle, not the path, so the mode cannot change
            // between the check and the read.
            let meta = file.metadata().map_err(|e| os_err("stat key file", e))?;
            if !meta.is_file() {
                return Err(PlatformError::Os("key path is not a regular file".into()));
            }
            if meta.mode() & 0o077 != 0 {
                return Err(PlatformError::Os(format!(
                    "refusing key file {} with mode {:o}: group/other access",
                    path.display(),
                    meta.mode() & 0o7777
                )));
            }
            let mut buf = Zeroizing::new(Vec::with_capacity(33));
            (&mut file)
                .take(33)
                .read_to_end(&mut buf)
                .map_err(|e| os_err("read key file", e))?;
            let seed: [u8; 32] = buf
                .as_slice()
                .try_into()
                .map_err(|_| PlatformError::Os("key file has wrong length".into()))?;
            Ok(Some(seed))
        }

        fn store(&self, seed: &[u8; 32]) -> Result<(), PlatformError> {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.dir)
                .map_err(|e| os_err("create state dir", e))?;
            let tmp = self
                .dir
                .join(format!("{KEY_FILE}.tmp{}", std::process::id()));
            match fs::remove_file(&tmp) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(os_err("remove stale temp key", e)),
            }
            let write = || -> std::io::Result<()> {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)?;
                f.write_all(seed)?;
                f.sync_all()?;
                fs::rename(&tmp, self.path())
            };
            write().map_err(|e| {
                let _ = fs::remove_file(&tmp);
                os_err("write key file", e)
            })
        }

        fn delete(&self) -> Result<(), PlatformError> {
            match fs::remove_file(self.path()) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(e) => Err(os_err("delete key file", e)),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn scratch(name: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!("rmm-ks-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&d);
            d
        }

        #[test]
        fn round_trip_and_modes() {
            let dir = scratch("rt").join("state");
            let ks = FileKeyStore::new(&dir);
            assert_eq!(ks.load().expect("load"), None);
            ks.store(&[9; 32]).expect("store");
            assert_eq!(ks.load().expect("load"), Some([9; 32]));
            let file_mode = fs::metadata(ks.path()).expect("stat").mode() & 0o777;
            let dir_mode = fs::metadata(&dir).expect("stat").mode() & 0o777;
            assert_eq!(file_mode, 0o600);
            assert_eq!(dir_mode, 0o700);
            ks.store(&[3; 32]).expect("replace");
            assert_eq!(ks.load().expect("load"), Some([3; 32]));
            ks.delete().expect("delete");
            ks.delete().expect("delete is idempotent");
            assert_eq!(ks.load().expect("load"), None);
            let _ = fs::remove_dir_all(dir.parent().expect("parent"));
        }

        #[test]
        fn refuses_group_or_other_access() {
            let dir = scratch("perm");
            let ks = FileKeyStore::new(&dir);
            ks.store(&[1; 32]).expect("store");
            for mode in [0o640, 0o604, 0o660, 0o666] {
                fs::set_permissions(ks.path(), fs::Permissions::from_mode(mode)).expect("chmod");
                assert!(ks.load().is_err(), "mode {mode:o} must be refused");
            }
            fs::set_permissions(ks.path(), fs::Permissions::from_mode(0o400)).expect("chmod");
            assert_eq!(ks.load().expect("0400 ok"), Some([1; 32]));
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn wrong_length_is_an_error() {
            let dir = scratch("len");
            let ks = FileKeyStore::new(&dir);
            ks.store(&[1; 32]).expect("store");
            fs::write(ks.path(), [1u8; 31]).expect("truncate");
            fs::set_permissions(ks.path(), fs::Permissions::from_mode(0o600)).expect("chmod");
            assert!(ks.load().is_err());
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
