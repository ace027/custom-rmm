//! Errors produced by trust-chain operations.

use rmm_proto::canonical::CanonicalError;

/// Failure modes of envelope handling and verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    /// Canonical CBOR encoding or strict decoding failed.
    #[error("canonical encoding: {0}")]
    Canonical(#[from] CanonicalError),
    /// A signature did not verify.
    #[error("bad signature")]
    BadSignature,
    /// The supplied key does not match the signature entry.
    #[error("unknown key")]
    UnknownKey,
    /// The signature algorithm is not supported.
    #[error("unsupported signature algorithm")]
    UnsupportedAlg,
    /// The envelope version is not supported.
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    /// The payload type is not the expected one.
    #[error("wrong payload type")]
    WrongType,
    /// Key bytes are not a valid public key.
    #[error("invalid public key")]
    InvalidKey,
    /// A signing backend failed.
    #[error("signer: {0}")]
    Signer(String),
}
