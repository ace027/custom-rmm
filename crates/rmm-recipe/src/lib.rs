//! Action-definition schema, result schema and static recipe validation.
//!
//! Agent and server run the same validator so a definition or parameter set
//! is accepted or rejected identically on both sides.

pub mod definition;
pub mod result;
pub mod validate;

/// Protocol version recipes are validated against.
pub fn protocol_version() -> u16 {
    rmm_trust::verify::supported_protocol()
}

/// Why a definition, its parameters or a document failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecipeError {
    /// Not canonical CBOR, unknown field or wrong shape.
    #[error("decode: {0}")]
    Decode(String),
    /// A definition-level field is out of bounds.
    #[error("invalid definition: {0}")]
    InvalidDefinition(String),
    /// A step names a block outside the registry.
    #[error("unknown block: {0}")]
    UnknownBlock(String),
    /// A step argument does not match its block's schema.
    #[error("invalid argument: {0}")]
    InvalidArg(String),
    /// A supplied parameter does not satisfy its declaration.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
    /// More than 32 steps in total.
    #[error("too many steps")]
    TooManySteps,
    /// A step asks for more than 3 retries.
    #[error("retries out of range")]
    InvalidRetries,
    /// A block's capability group is not allowed by the definition.
    #[error("capability mismatch: {0}")]
    CapabilityMismatch(String),
}

#[cfg(test)]
mod tests {
    #[test]
    fn protocol_version_is_one() {
        assert_eq!(super::protocol_version(), 1);
    }
}
