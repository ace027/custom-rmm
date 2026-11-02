//! Platform-agnostic agent core: enrollment, persistent identity, the NATS
//! transport, telemetry, signed command execution, co-signed shells and the
//! periodic trust and release refresh.

pub mod blocks;
pub mod commands;
pub mod enroll;
pub mod executor;
pub mod health;
pub mod identity;
pub mod refresh;
pub mod shell;
pub mod shell_verify;
pub mod store;
pub mod telemetry;
pub mod transport;
pub mod update;

use rmm_platform::Platform;

/// Human-readable identity line used in logs.
pub fn identity() -> String {
    let host = rmm_platform::current()
        .hostname()
        .unwrap_or_else(|_| "unknown".to_string());
    format!("host={host} protocol={}", rmm_recipe::protocol_version())
}

#[cfg(test)]
mod tests {
    #[test]
    fn identity_has_protocol() {
        assert!(super::identity().contains("protocol=1"));
    }
}
