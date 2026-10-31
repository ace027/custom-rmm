//! Trust-chain primitives. Verification is always available; signing is gated
//! behind the `sign` feature so that no signing code ships on endpoints.

pub mod verify;

#[cfg(feature = "sign")]
pub mod sign;
