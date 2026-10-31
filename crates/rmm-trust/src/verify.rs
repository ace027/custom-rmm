//! Verification side of the trust chain (skeleton).

/// Protocol version this verifier understands.
pub fn supported_protocol() -> u16 {
    rmm_proto::PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    #[test]
    fn protocol_matches() {
        assert_eq!(super::supported_protocol(), rmm_proto::PROTOCOL_VERSION);
    }
}
