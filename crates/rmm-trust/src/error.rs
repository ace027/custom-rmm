//! Errors produced by trust-chain operations.

use rmm_proto::canonical::CanonicalError;

use crate::docs::Role;

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
    /// Fewer distinct valid signers than the role threshold requires.
    #[error("below threshold for {role:?}: got {got}, need {need}")]
    BelowThreshold {
        /// The role being checked.
        role: Role,
        /// Distinct valid signers found.
        got: u8,
        /// Signers required.
        need: u8,
    },
    /// The signer does not hold the required role, or the role has no threshold.
    #[error("key does not hold the required role")]
    WrongRole,
    /// The signing key is revoked by the trust manifest.
    #[error("key revoked")]
    KeyRevoked,
    /// The signer's certificate is not valid at the current time.
    #[error("certificate not valid now")]
    CertNotValid,
    /// The document has expired.
    #[error("expired")]
    Expired,
    /// The document is issued in the future beyond the skew tolerance.
    #[error("not yet valid")]
    NotYetValid,
    /// The document's sequence number is lower than the stored one.
    #[error("rollback: stored seq {stored}, got {got}")]
    Rollback {
        /// Highest accepted sequence number.
        stored: u64,
        /// Sequence number of the rejected document.
        got: u64,
    },
    /// Same sequence number as the stored document but different content.
    #[error("equivocation: same seq, different content")]
    Equivocation,
    /// Revocation data is missing or expired.
    #[error("trust data is stale")]
    Stale,
    /// The command targets a different agent.
    #[error("command is for another agent")]
    WrongAgent,
    /// The command targets a different client.
    #[error("command is for another client")]
    WrongClient,
    /// The command id was already seen.
    #[error("replayed command")]
    Replay,
    /// No trust manifest has been applied.
    #[error("no trust manifest")]
    NoManifest,
    /// The referenced artifact is revoked.
    #[error("artifact revoked")]
    ArtifactRevoked,
    /// The document is structurally invalid.
    #[error("invalid document: {0}")]
    InvalidDocument(String),
}
