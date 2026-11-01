//! Platform-agnostic agent core: enrollment, persistent identity, the NATS
//! transport, telemetry, signed command execution and co-signed shells.

pub mod blocks;
pub mod commands;
pub mod enroll;
pub mod executor;
pub mod identity;
pub mod shell;
pub mod shell_verify;
pub mod store;
pub mod telemetry;
pub mod transport;

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
