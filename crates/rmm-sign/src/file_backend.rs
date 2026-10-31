//! Root key stored as an age (scrypt passphrase) encrypted Ed25519 seed.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use age::DecryptError;
use age::scrypt;
use age::secrecy::SecretString;
use rmm_trust::sign::Ed25519Signer;
use zeroize::Zeroizing;

/// Environment variable holding the key file passphrase.
pub const PASSPHRASE_ENV: &str = "RMM_SIGN_PASSPHRASE";

/// Errors of the file backend.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// The passphrase did not decrypt the key file.
    #[error("wrong passphrase (or corrupted key file)")]
    WrongPassphrase,
    /// Refusing to overwrite.
    #[error("{} already exists; refusing to overwrite", .0.display())]
    Exists(PathBuf),
    /// Filesystem failure.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file concerned.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The decrypted content is not a 32-byte seed.
    #[error("key file does not contain a 32-byte Ed25519 seed")]
    BadSeed,
    /// Any other age or prompt failure.
    #[error("{0}")]
    Other(String),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> FileError + '_ {
    move |source| FileError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Read the passphrase from the environment or prompt (twice when `confirm`).
/// The environment variable is intended for tests and CI only.
pub fn passphrase(confirm: bool) -> Result<SecretString, FileError> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV).map(Zeroizing::new) {
        if p.is_empty() {
            return Err(FileError::Other(format!("{PASSPHRASE_ENV} is empty")));
        }
        return Ok(SecretString::from(p.as_str().to_owned()));
    }
    let prompt = |msg: &str| {
        rpassword::prompt_password(msg)
            .map(Zeroizing::new)
            .map_err(|e| FileError::Other(format!("cannot read passphrase: {e}")))
    };
    let first = prompt("Passphrase: ")?;
    if first.is_empty() {
        return Err(FileError::Other("passphrase must not be empty".into()));
    }
    if confirm {
        let second = prompt("Repeat passphrase: ")?;
        if *first != *second {
            return Err(FileError::Other("passphrases do not match".into()));
        }
    }
    Ok(SecretString::from(first.as_str().to_owned()))
}

/// Create a new random root key encrypted with `pass` at `path`.
pub fn generate(path: &Path, pass: SecretString) -> Result<Ed25519Signer, FileError> {
    if path.exists() {
        return Err(FileError::Exists(path.to_owned()));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut seed[..])
        .map_err(|e| FileError::Other(format!("OS randomness unavailable: {e}")))?;
    let ct = age::encrypt(&scrypt::Recipient::new(pass), &seed[..])
        .map_err(|e| FileError::Other(format!("encryption failed: {e}")))?;

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == ErrorKind::AlreadyExists {
            FileError::Exists(path.to_owned())
        } else {
            io_err(path)(e)
        }
    })?;
    f.write_all(&ct)
        .and_then(|()| f.sync_all())
        .map_err(io_err(path))?;
    Ok(Ed25519Signer::from_seed(&seed))
}

/// Decrypt the key file at `path`.
pub fn load(path: &Path, pass: SecretString) -> Result<Ed25519Signer, FileError> {
    let ct = std::fs::read(path).map_err(io_err(path))?;
    let plain = age::decrypt(&scrypt::Identity::new(pass), &ct).map_err(|e| match e {
        DecryptError::DecryptionFailed
        | DecryptError::KeyDecryptionFailed
        | DecryptError::NoMatchingKeys => FileError::WrongPassphrase,
        other => FileError::Other(format!("cannot decrypt {}: {other}", path.display())),
    })?;
    let plain = Zeroizing::new(plain);
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        plain
            .as_slice()
            .try_into()
            .map_err(|_| FileError::BadSeed)?,
    );
    Ok(Ed25519Signer::from_seed(&seed))
}
