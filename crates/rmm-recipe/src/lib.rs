//! Action-definition schema and static recipe validation (skeleton).

/// Protocol version recipes are validated against.
pub fn protocol_version() -> u16 {
    rmm_trust::verify::supported_protocol()
}

#[cfg(test)]
mod tests {
    #[test]
    fn protocol_version_is_one() {
        assert_eq!(super::protocol_version(), 1);
    }
}
