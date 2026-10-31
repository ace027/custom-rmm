//! Signing side of the trust chain. Only built with feature `sign`.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey};

use crate::envelope::{ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, signing_message};
use crate::error::TrustError;
use crate::keys::{Bytes, KeyId, PublicKey, Sig64};

/// Marker proving the signing module is compiled into a binary. Release
/// checks search agent binaries for this string.
#[used]
pub static SIGN_MODULE_MARKER: [u8; 30] = *b"RMM_TRUST_SIGN_MODULE_PRESENT!";

/// A source of Ed25519 signatures (file key, hardware token, ...).
pub trait Signer {
    /// Identifier of the signing key.
    fn key_id(&self) -> KeyId;
    /// The public key matching this signer.
    fn public_key(&self) -> PublicKey;
    /// Sign the 39-byte signing message.
    fn sign_message(&self, msg: &[u8; 39]) -> Result<Sig64, TrustError>;
}

/// Software signer built from a 32-byte Ed25519 seed.
pub struct Ed25519Signer {
    key: SigningKey,
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signer({:?})", self.key_id())
    }
}

impl Ed25519Signer {
    /// Derive the signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> KeyId {
        self.public_key().key_id()
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(&self.key.verifying_key().to_bytes())
            .expect("a derived verifying key is always valid")
    }

    fn sign_message(&self, msg: &[u8; 39]) -> Result<Sig64, TrustError> {
        Ok(Sig64(self.key.sign(msg).to_bytes()))
    }
}

/// Build an envelope signed by every signer. Signatures are sorted by key id;
/// each is verified before returning so a faulty backend cannot emit garbage.
pub fn sign_envelope(
    type_: &str,
    payload: Vec<u8>,
    signers: &[&dyn Signer],
) -> Result<Envelope, TrustError> {
    let msg = signing_message(type_, &payload);
    let mut env = Envelope {
        v: ENVELOPE_VERSION,
        r#type: type_.to_owned(),
        payload: Bytes(payload),
        sigs: Vec::with_capacity(signers.len()),
    };
    for s in signers {
        env.sigs.push(SigEntry {
            key_id: s.key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: s.sign_message(&msg)?,
        });
    }
    env.sigs.sort_by_key(|e| e.key_id);
    if env.sigs.windows(2).any(|w| w[0].key_id == w[1].key_id) {
        return Err(TrustError::Signer("duplicate signer".into()));
    }
    for (entry, s) in sorted_pairs(&env, signers) {
        env.verify_sig(entry, &s.public_key())?;
    }
    Ok(env)
}

fn sorted_pairs<'a>(
    env: &'a Envelope,
    signers: &'a [&'a dyn Signer],
) -> impl Iterator<Item = (&'a SigEntry, &'a dyn Signer)> {
    env.sigs.iter().filter_map(move |e| {
        signers
            .iter()
            .find(|s| s.key_id() == e.key_id)
            .map(|s| (e, *s))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(b: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed(&[b; 32])
    }

    #[test]
    fn sign_then_verify() {
        let s = signer(1);
        let env = sign_envelope("rmm.command/1", b"payload".to_vec(), &[&s]).expect("sign");
        assert_eq!(env.sigs.len(), 1);
        env.verify_sig(&env.sigs[0], &s.public_key())
            .expect("verify");
        let bytes = env.to_bytes().expect("enc");
        assert_eq!(Envelope::from_bytes(&bytes).expect("dec"), env);
    }

    #[test]
    fn tampering_fails() {
        let s = signer(1);
        let env = sign_envelope("rmm.command/1", b"payload".to_vec(), &[&s]).expect("sign");
        let pk = s.public_key();

        let mut e = env.clone();
        e.payload.0[0] ^= 1;
        assert_eq!(e.verify_sig(&e.sigs[0], &pk), Err(TrustError::BadSignature));

        // type binding: same payload, different type string
        let mut e = env.clone();
        e.r#type = "rmm.manifest/1".into();
        assert_eq!(e.verify_sig(&e.sigs[0], &pk), Err(TrustError::BadSignature));

        let mut e = env.clone();
        e.sigs[0].sig.0[10] ^= 1;
        assert_eq!(e.verify_sig(&e.sigs[0], &pk), Err(TrustError::BadSignature));
    }

    #[test]
    fn wrong_key_fails() {
        let (a, b) = (signer(1), signer(2));
        let env = sign_envelope("t", vec![], &[&a]).expect("sign");
        assert_eq!(
            env.verify_sig(&env.sigs[0], &b.public_key()),
            Err(TrustError::UnknownKey)
        );
        // same key id claimed but signature from another key
        let mut e = env.clone();
        e.sigs[0].key_id = b.key_id();
        assert_eq!(
            e.verify_sig(&e.sigs[0], &b.public_key()),
            Err(TrustError::BadSignature)
        );
    }

    #[test]
    fn rejects_alg_and_version() {
        let s = signer(1);
        let env = sign_envelope("t", vec![], &[&s]).expect("sign");
        let mut e = env.clone();
        e.sigs[0].alg = "ed448".into();
        assert_eq!(
            e.verify_sig(&e.sigs[0], &s.public_key()),
            Err(TrustError::UnsupportedAlg)
        );
        let mut e = env;
        e.v = 2;
        assert_eq!(
            e.verify_sig(&e.sigs[0], &s.public_key()),
            Err(TrustError::UnsupportedVersion)
        );
    }

    #[test]
    fn two_signers_sorted_and_duplicates_rejected() {
        let (a, b) = (signer(1), signer(2));
        let env = sign_envelope("t", vec![9], &[&a, &b]).expect("sign");
        assert!(env.sigs[0].key_id < env.sigs[1].key_id);
        assert!(matches!(
            sign_envelope("t", vec![], &[&a, &a]),
            Err(TrustError::Signer(_))
        ));
    }

    #[test]
    fn marker_present() {
        assert_eq!(&SIGN_MODULE_MARKER[..3], b"RMM");
    }
}
