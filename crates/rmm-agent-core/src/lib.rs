//! Platform-agnostic agent core: enrollment, persistent identity and the NATS
//! transport.

pub mod enroll;
pub mod identity;
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
