//! Database access layer (skeleton).

/// Name of the Postgres schema owned by the platform.
pub const SCHEMA: &str = "rmm";

#[cfg(test)]
mod tests {
    #[test]
    fn schema_name() {
        assert_eq!(super::SCHEMA, "rmm");
    }
}
