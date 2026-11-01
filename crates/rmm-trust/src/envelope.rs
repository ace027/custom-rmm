//! DSSE-style signed envelope over canonical CBOR.

use rmm_proto::canonical::{from_canonical_slice, to_canonical_vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::TrustError;
use crate::keys::{Bytes, KeyId, PublicKey, Sig64};

/// Payload type of a trust manifest.
pub const TYPE_MANIFEST: &str = "rmm.manifest/1";
/// Payload type of an artifact revocation list.
pub const TYPE_REVOCATIONS: &str = "rmm.revocations/1";
/// Payload type of a command.
pub const TYPE_COMMAND: &str = "rmm.command/1";
/// Payload type of a technician list.
pub const TYPE_TECHLIST: &str = "rmm.techlist/1";

/// The only signature algorithm identifier.
pub const ALG_ED25519: &str = "ed25519";
/// The only envelope version.
pub const ENVELOPE_VERSION: u8 = 1;

const SIG_PREFIX: &[u8; 7] = b"RMMSIG1";

/// One signature over the envelope's signing message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigEntry {
    /// SHA-256 of the signer's public key.
    pub key_id: KeyId,
    /// Algorithm identifier; must be `ed25519`.
    pub alg: String,
    /// The signature.
    pub sig: Sig64,
}

/// A typed payload with signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Envelope version; must be 1.
    pub v: u8,
    /// Payload type string, bound into every signature.
    #[serde(rename = "type")]
    pub r#type: String,
    /// Payload bytes (canonical CBOR of the document).
    pub payload: Bytes,
    /// Signatures over [`signing_message`].
    pub sigs: Vec<SigEntry>,
}

/// DSSE pre-authentication encoding:
/// `"DSSEv1 " len(type) " " type " " len(payload) " " payload`.
pub fn pae(type_: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + type_.len() + payload.len());
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(type_.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(type_.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// The 39-byte message that is signed: `"RMMSIG1" || SHA-256(PAE)`.
pub fn signing_message(type_: &str, payload: &[u8]) -> [u8; 39] {
    let mut m = [0u8; 39];
    m[..7].copy_from_slice(SIG_PREFIX);
    m[7..].copy_from_slice(&Sha256::digest(pae(type_, payload)));
    m
}

impl Envelope {
    /// Canonical CBOR encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TrustError> {
        Ok(to_canonical_vec(self)?)
    }

    /// Strict canonical decoding; also rejects unsupported versions.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let env: Self = from_canonical_slice(bytes)?;
        if env.v != ENVELOPE_VERSION {
            return Err(TrustError::UnsupportedVersion);
        }
        Ok(env)
    }

    /// SHA-256 of the payload.
    pub fn content_id(&self) -> [u8; 32] {
        Sha256::digest(&self.payload.0).into()
    }

    /// The message signers sign for this envelope.
    pub fn signing_message(&self) -> [u8; 39] {
        signing_message(&self.r#type, &self.payload.0)
    }

    /// Verify a single signature entry against `key`.
    pub fn verify_sig(&self, entry: &SigEntry, key: &PublicKey) -> Result<(), TrustError> {
        if self.v != ENVELOPE_VERSION {
            return Err(TrustError::UnsupportedVersion);
        }
        if entry.alg != ALG_ED25519 {
            return Err(TrustError::UnsupportedAlg);
        }
        if entry.key_id != key.key_id() {
            return Err(TrustError::UnknownKey);
        }
        key.verify(&self.signing_message(), &entry.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_known_bytes() {
        assert_eq!(
            pae("rmm.command/1", b"hi"),
            b"DSSEv1 13 rmm.command/1 2 hi".to_vec()
        );
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
    }

    #[test]
    fn signing_message_shape() {
        let m = signing_message("t", b"p");
        assert_eq!(m.len(), 39);
        assert_eq!(&m[..7], b"RMMSIG1");
        assert_eq!(&m[7..], &Sha256::digest(pae("t", b"p"))[..]);
    }

    #[test]
    fn empty_envelope_is_canonical() {
        let env = Envelope {
            v: 1,
            r#type: TYPE_COMMAND.into(),
            payload: Bytes(vec![]),
            sigs: vec![],
        };
        let bytes = env.to_bytes().expect("encode");
        assert_eq!(Envelope::from_bytes(&bytes).expect("decode"), env);
    }

    #[test]
    fn rejects_unsupported_version() {
        let env = Envelope {
            v: 2,
            r#type: "t".into(),
            payload: Bytes(vec![]),
            sigs: vec![],
        };
        let bytes = env.to_bytes().expect("encode");
        assert_eq!(
            Envelope::from_bytes(&bytes),
            Err(TrustError::UnsupportedVersion)
        );
    }

    #[test]
    fn content_id_is_payload_hash() {
        let env = Envelope {
            v: 1,
            r#type: "t".into(),
            payload: Bytes(b"abc".to_vec()),
            sigs: vec![],
        };
        assert_eq!(env.content_id(), <[u8; 32]>::from(Sha256::digest(b"abc")));
    }
}
