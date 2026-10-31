//! Trust-chain primitives. Verification is always available; signing is gated
//! behind the `sign` feature so that no signing code ships on endpoints.

pub mod docs;
pub mod envelope;
pub mod error;
pub mod keys;
pub mod store;
pub mod verify;
pub mod webauthn;

#[cfg(feature = "sign")]
pub mod sign;
