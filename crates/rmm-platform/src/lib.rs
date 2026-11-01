//! Platform abstraction with per-OS implementations.

pub mod collect;
#[cfg(debug_assertions)]
pub mod fake;
pub mod indicator;
mod keystore;
pub mod pty;
pub mod quarantine;
pub mod services;
pub mod smbios;

pub use keystore::{KeyStore, default_state_dir, keystore, keystore_named};
pub use rmm_proto::enroll::HwFacts;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux::Current;
#[cfg(target_os = "macos")]
use macos::Current;
#[cfg(target_os = "windows")]
use windows::Current;

/// Errors returned by platform operations.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// An operating-system call failed.
    #[error("os error: {0}")]
    Os(String),
    /// The operation is not implemented on this platform.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The operation did not finish in time.
    #[error("timed out: {0}")]
    Timeout(String),
    /// The request was refused before anything was changed (not allowlisted,
    /// would overwrite, invalid input).
    #[error("refused: {0}")]
    Refused(String),
}

/// Operating-system services needed by the agent.
pub trait Platform {
    /// DNS host name of this machine.
    fn hostname(&self) -> Result<String, PlatformError>;

    /// Hardware identifiers for the device fingerprint; fields that cannot be
    /// read (containers, missing firmware tables) are `None`.
    fn hw_facts(&self) -> HwFacts;

    /// `(os_family, os_version)`, e.g. `("windows", "Windows 11 Pro 24H2 (build 26100)")`.
    fn os_info(&self) -> (String, String);
}

/// The platform implementation for the current target OS.
pub fn current() -> impl Platform {
    Current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_not_empty() {
        let name = current().hostname().expect("hostname");
        assert!(!name.is_empty());
    }
}
