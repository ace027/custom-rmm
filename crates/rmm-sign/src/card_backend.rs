//! OpenPGP-card (YubiKey) Ed25519 signing backend.
//!
//! The selection, algorithm and key id logic is written against the small
//! [`CardOps`] trait so it can be unit-tested with a fake card. Only
//! `PcscCard` (feature `card`) talks to real hardware.

// Without the `card` feature only the stub `open` is reachable.
#![cfg_attr(not(feature = "card"), allow(dead_code))]

use std::cell::RefCell;
use std::fmt;

use rmm_trust::error::TrustError;
use rmm_trust::keys::{KeyId, PublicKey, Sig64};
use rmm_trust::sign::Signer;
use zeroize::Zeroizing;

/// Environment variable holding the card user PIN.
pub const PIN_ENV: &str = "RMM_CARD_PIN";

/// Errors of the card backend.
#[derive(Debug, thiserror::Error)]
pub enum CardError {
    /// No OpenPGP card found.
    #[error("no OpenPGP card found (is it inserted and is pcscd running?)")]
    NoCard,
    /// The requested ident is not present.
    #[error("card {wanted} not found; available cards: {}", .available.join(", "))]
    NotFound {
        /// Requested ident.
        wanted: String,
        /// Idents present.
        available: Vec<String>,
    },
    /// Several cards and no ident given.
    #[error("several cards present, select one with card:<ident>; available cards: {}", .available.join(", "))]
    Ambiguous {
        /// Idents present.
        available: Vec<String>,
    },
    /// The signature slot does not hold an Ed25519 key.
    #[error("card signing key is not Ed25519 (found {0})")]
    NotEd25519(String),
    /// The public key from the card is unusable.
    #[error("card returned an invalid public key: {0}")]
    BadPublicKey(String),
    /// The key on the card is not the expected one.
    #[error("card key id {found} does not match expected {expected}")]
    KeyIdMismatch {
        /// Expected key id (hex).
        expected: String,
        /// Key id found (hex).
        found: String,
    },
    /// A PIN is needed to sign.
    #[error("a card PIN is required to sign")]
    PinRequired,
    /// Card communication or command failure.
    #[error("card error: {0}")]
    Card(String),
    /// Built without the `card` feature.
    #[error("this rmm-sign build has no card support (rebuild with the `card` feature)")]
    #[cfg_attr(feature = "card", allow(dead_code))]
    Disabled,
}

/// Algorithm of the signature slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigAlgo {
    /// EdDSA over Ed25519.
    Ed25519,
    /// Anything else, described for the error message.
    Other(String),
}

/// The card operations needed for signing.
pub trait CardOps {
    /// Card identifier (`MMMM:SSSSSSSS`).
    fn ident(&mut self) -> Result<String, CardError>;
    /// Algorithm of the signature key slot.
    fn sig_algorithm(&mut self) -> Result<SigAlgo, CardError>;
    /// Raw public key bytes of the signature slot.
    fn public_key(&mut self) -> Result<Vec<u8>, CardError>;
    /// Verify the user PIN for signing, then PSO:COMPUTE DIGITAL SIGNATURE.
    fn sign(&mut self, pin: &str, msg: &[u8]) -> Result<Vec<u8>, CardError>;
}

/// Pick one card: by ident when given, otherwise the only card present.
pub fn select<C: CardOps>(mut cards: Vec<C>, ident: Option<&str>) -> Result<C, CardError> {
    if cards.is_empty() {
        return Err(CardError::NoCard);
    }
    let mut idents = Vec::with_capacity(cards.len());
    for c in &mut cards {
        idents.push(c.ident()?);
    }
    let index = match ident {
        Some(want) => idents
            .iter()
            .position(|i| i.eq_ignore_ascii_case(want))
            .ok_or_else(|| CardError::NotFound {
                wanted: want.to_owned(),
                available: idents.clone(),
            })?,
        None if cards.len() == 1 => 0,
        None => return Err(CardError::Ambiguous { available: idents }),
    };
    Ok(cards.swap_remove(index))
}

/// A signer backed by a card.
pub struct CardSigner<C: CardOps> {
    card: RefCell<C>,
    pin: Option<Zeroizing<String>>,
    public: PublicKey,
}

impl<C: CardOps> fmt::Debug for CardSigner<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CardSigner({:?})", self.public.key_id())
    }
}

impl<C: CardOps> CardSigner<C> {
    /// Check the card holds an Ed25519 signing key and read it. `expect`
    /// pins the key id. `pin` may be `None` for read-only use.
    pub fn new(
        mut card: C,
        pin: Option<Zeroizing<String>>,
        expect: Option<&KeyId>,
    ) -> Result<Self, CardError> {
        match card.sig_algorithm()? {
            SigAlgo::Ed25519 => {}
            SigAlgo::Other(found) => return Err(CardError::NotEd25519(found)),
        }
        let raw = card.public_key()?;
        // Some cards prefix the native 32-byte key with 0x40.
        let raw = match raw.as_slice() {
            [0x40, rest @ ..] if rest.len() == 32 => rest,
            all => all,
        };
        let arr: [u8; 32] = raw.try_into().map_err(|_| {
            CardError::BadPublicKey(format!("expected 32 bytes, got {}", raw.len()))
        })?;
        let public =
            PublicKey::from_bytes(&arr).map_err(|e| CardError::BadPublicKey(e.to_string()))?;
        if let Some(want) = expect
            && *want != public.key_id()
        {
            return Err(CardError::KeyIdMismatch {
                expected: hex::encode(want.0),
                found: hex::encode(public.key_id().0),
            });
        }
        Ok(Self {
            card: RefCell::new(card),
            pin,
            public,
        })
    }
}

impl<C: CardOps> Signer for CardSigner<C> {
    fn key_id(&self) -> KeyId {
        self.public.key_id()
    }

    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign_message(&self, msg: &[u8; 39]) -> Result<Sig64, TrustError> {
        let signer_err = |e: CardError| TrustError::Signer(e.to_string());
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| signer_err(CardError::PinRequired))?;
        eprintln!("Touch your security key to sign...");
        let sig = self.card.borrow_mut().sign(pin, msg).map_err(signer_err)?;
        let sig: [u8; 64] = sig.as_slice().try_into().map_err(|_| {
            signer_err(CardError::Card(format!(
                "expected a 64-byte signature, got {} bytes",
                sig.len()
            )))
        })?;
        Ok(Sig64(sig))
    }
}

/// Read the card PIN from the environment or prompt.
pub fn read_pin() -> Result<Zeroizing<String>, CardError> {
    if let Ok(p) = std::env::var(PIN_ENV) {
        return Ok(Zeroizing::new(p));
    }
    rpassword::prompt_password("Card user PIN: ")
        .map(Zeroizing::new)
        .map_err(|e| CardError::Card(format!("cannot read PIN: {e}")))
}

/// Open the card for read-only use (public key) or signing (`with_pin`).
#[cfg(feature = "card")]
pub fn open(
    ident: Option<&str>,
    with_pin: bool,
    expect: Option<&KeyId>,
) -> Result<Box<dyn Signer>, CardError> {
    let card = select(pcsc::enumerate()?, ident)?;
    let pin = if with_pin { Some(read_pin()?) } else { None };
    Ok(Box::new(CardSigner::new(card, pin, expect)?))
}

/// Stub for builds without card support.
#[cfg(not(feature = "card"))]
pub fn open(
    _ident: Option<&str>,
    _with_pin: bool,
    _expect: Option<&KeyId>,
) -> Result<Box<dyn Signer>, CardError> {
    Err(CardError::Disabled)
}

#[cfg(feature = "card")]
mod pcsc {
    use card_backend_pcsc::PcscBackend;
    use openpgp_card::Card;
    use openpgp_card::ocard::KeyType;
    use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve};
    use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
    use openpgp_card::state::Open;

    use super::{CardError, CardOps, SigAlgo};

    fn err(e: impl std::fmt::Display) -> CardError {
        CardError::Card(e.to_string())
    }

    /// A real card reached over PC/SC.
    pub struct PcscCard {
        card: Card<Open>,
    }

    /// All OpenPGP cards currently reachable; readers without an OpenPGP
    /// application are skipped.
    pub fn enumerate() -> Result<Vec<PcscCard>, CardError> {
        let backends = PcscBackend::card_backends(None).map_err(err)?;
        Ok(backends
            .filter_map(Result::ok)
            .filter_map(|b| Card::new(b).ok())
            .map(|card| PcscCard { card })
            .collect())
    }

    impl CardOps for PcscCard {
        fn ident(&mut self) -> Result<String, CardError> {
            let tx = self.card.transaction().map_err(err)?;
            Ok(tx.application_identifier().map_err(err)?.ident())
        }

        fn sig_algorithm(&mut self) -> Result<SigAlgo, CardError> {
            let mut tx = self.card.transaction().map_err(err)?;
            let attrs = tx.algorithm_attributes(KeyType::Signing).map_err(err)?;
            Ok(match &attrs {
                AlgorithmAttributes::Ecc(e)
                    if e.ecc_type() == EccType::EdDSA && *e.curve() == Curve::Ed25519 =>
                {
                    SigAlgo::Ed25519
                }
                other => SigAlgo::Other(format!("{other:?}")),
            })
        }

        fn public_key(&mut self) -> Result<Vec<u8>, CardError> {
            let mut tx = self.card.transaction().map_err(err)?;
            match tx.public_key_material(KeyType::Signing).map_err(err)? {
                PublicKeyMaterial::E(e) => Ok(e.data().to_vec()),
                PublicKeyMaterial::R(_) => Err(CardError::NotEd25519("RSA".into())),
            }
        }

        fn sign(&mut self, pin: &str, msg: &[u8]) -> Result<Vec<u8>, CardError> {
            let mut tx = self.card.transaction().map_err(err)?;
            tx.verify_user_signing_pin(pin.to_owned().into())
                .map_err(err)?;
            tx.card()
                .pso_compute_digital_signature(msg.to_vec())
                .map_err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rmm_trust::sign::{Ed25519Signer, sign_envelope};

    use super::*;

    #[derive(Debug)]
    struct FakeCard {
        ident: String,
        algo: SigAlgo,
        key: Ed25519Signer,
        pin: &'static str,
    }

    fn fake(ident: &str, seed: u8) -> FakeCard {
        FakeCard {
            ident: ident.into(),
            algo: SigAlgo::Ed25519,
            key: Ed25519Signer::from_seed(&[seed; 32]),
            pin: "123456",
        }
    }

    impl CardOps for FakeCard {
        fn ident(&mut self) -> Result<String, CardError> {
            Ok(self.ident.clone())
        }
        fn sig_algorithm(&mut self) -> Result<SigAlgo, CardError> {
            Ok(self.algo.clone())
        }
        fn public_key(&mut self) -> Result<Vec<u8>, CardError> {
            Ok(self.key.public_key().to_bytes().to_vec())
        }
        fn sign(&mut self, pin: &str, msg: &[u8]) -> Result<Vec<u8>, CardError> {
            if pin != self.pin {
                return Err(CardError::Card("wrong PIN".into()));
            }
            let msg: &[u8; 39] = msg.try_into().unwrap();
            Ok(self.key.sign_message(msg).unwrap().0.to_vec())
        }
    }

    fn pin(s: &str) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(s.to_owned()))
    }

    #[test]
    fn card_select_none_present() {
        assert!(matches!(
            select::<FakeCard>(vec![], None),
            Err(CardError::NoCard)
        ));
    }

    #[test]
    fn card_select_single_without_ident() {
        let c = select(vec![fake("0006:00000001", 1)], None).unwrap();
        assert_eq!(c.ident, "0006:00000001");
    }

    #[test]
    fn card_select_multiple_requires_ident_and_lists_them() {
        let cards = vec![fake("0006:00000001", 1), fake("0006:00000002", 2)];
        let err = select(cards, None).unwrap_err();
        assert!(matches!(err, CardError::Ambiguous { .. }));
        let msg = err.to_string();
        assert!(msg.contains("0006:00000001") && msg.contains("0006:00000002"));
    }

    #[test]
    fn card_select_by_ident_case_insensitive() {
        let cards = vec![fake("0006:0000ABCD", 1), fake("0006:00000002", 2)];
        let c = select(cards, Some("0006:0000abcd")).unwrap();
        assert_eq!(c.ident, "0006:0000ABCD");
    }

    #[test]
    fn card_select_unknown_ident_lists_available() {
        let err = select(vec![fake("0006:00000001", 1)], Some("0006:99999999")).unwrap_err();
        assert!(matches!(err, CardError::NotFound { .. }));
        assert!(err.to_string().contains("0006:00000001"));
    }

    #[test]
    fn card_refuses_non_ed25519() {
        let mut c = fake("0006:00000001", 1);
        c.algo = SigAlgo::Other("Ecc(NistP256r1)".into());
        let err = CardSigner::new(c, pin("123456"), None).unwrap_err();
        assert!(matches!(err, CardError::NotEd25519(ref a) if a.contains("NistP256r1")));
    }

    #[test]
    fn card_key_id_expectation_checked() {
        let good = fake("a", 1).key.key_id();
        let bad = fake("b", 2).key.key_id();
        assert!(CardSigner::new(fake("a", 1), None, Some(&good)).is_ok());
        assert!(matches!(
            CardSigner::new(fake("a", 1), None, Some(&bad)),
            Err(CardError::KeyIdMismatch { .. })
        ));
    }

    #[test]
    fn card_signs_envelope_that_verifies() {
        let signer = CardSigner::new(fake("a", 3), pin("123456"), None).unwrap();
        let env = sign_envelope("rmm.techlist/1", b"payload".to_vec(), &[&signer]).unwrap();
        assert_eq!(env.sigs.len(), 1);
        env.verify_sig(&env.sigs[0], &signer.public_key()).unwrap();
    }

    #[test]
    fn card_wrong_or_missing_pin_fails() {
        let wrong = CardSigner::new(fake("a", 3), pin("000000"), None).unwrap();
        assert!(sign_envelope("t", vec![], &[&wrong]).is_err());
        let none = CardSigner::new(fake("a", 3), None, None).unwrap();
        assert!(sign_envelope("t", vec![], &[&none]).is_err());
    }

    #[test]
    fn card_prefixed_public_key_accepted() {
        struct Prefixed(FakeCard);
        impl CardOps for Prefixed {
            fn ident(&mut self) -> Result<String, CardError> {
                self.0.ident()
            }
            fn sig_algorithm(&mut self) -> Result<SigAlgo, CardError> {
                self.0.sig_algorithm()
            }
            fn public_key(&mut self) -> Result<Vec<u8>, CardError> {
                let mut v = vec![0x40];
                v.extend(self.0.public_key()?);
                Ok(v)
            }
            fn sign(&mut self, pin: &str, msg: &[u8]) -> Result<Vec<u8>, CardError> {
                self.0.sign(pin, msg)
            }
        }
        let s = CardSigner::new(Prefixed(fake("a", 4)), None, None).unwrap();
        assert_eq!(s.key_id(), fake("a", 4).key.key_id());
    }
}
