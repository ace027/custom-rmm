//! Co-signed remote shell wire messages (canonical CBOR).
//!
//! `ShellOut` flows agent to operator on `shell.<a>.<sid>.out`, `ShellIn`
//! operator to agent on `.in`, and `ShellCtl` flow control on `.ctl`.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::canonical::{self, CanonicalError};

/// Largest payload of one data chunk.
pub const MAX_CHUNK: usize = 16384;
/// Minimum interval between output chunks, in milliseconds.
pub const CHUNK_INTERVAL_MS: u64 = 20;
/// Most unacknowledged output bytes in flight.
pub const MAX_IN_FLIGHT: u32 = 262_144;
/// Interval between pings, in seconds.
pub const PING_INTERVAL_SECS: u64 = 15;
/// Silence after which the peer is considered gone, in seconds.
pub const LIVENESS_SECS: u64 = 45;
/// Hard cap on a session's duration, in seconds.
pub const MAX_DURATION_SECS: u64 = 14400;

/// A byte string that encodes as a CBOR byte string.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Bytes(pub Vec<u8>);

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes({} bytes)", self.0.len())
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

struct BytesVisitor;

impl Visitor<'_> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a byte string")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
        Ok(Bytes(v.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
        Ok(Bytes(v))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_byte_buf(BytesVisitor)
    }
}

fn check_chunk(data: &Bytes) -> Result<(), CanonicalError> {
    if data.0.len() > MAX_CHUNK {
        return Err(CanonicalError::Serde(format!(
            "data chunk of {} bytes exceeds {MAX_CHUNK}",
            data.0.len()
        )));
    }
    Ok(())
}

/// Agent to operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ShellOut {
    /// Terminal output with a running sequence number.
    Data { seq: u64, data: Bytes },
    /// The shell exited.
    Exit { code: i32 },
    /// The session was closed by the agent.
    Closed { reason: String },
}

/// Operator to agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ShellIn {
    /// Keystrokes.
    Data { data: Bytes },
    /// Terminal size change.
    Resize { cols: u16, rows: u16 },
}

/// Flow control and liveness, either direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ShellCtl {
    /// Output up to and including `seq` was received.
    Ack { seq: u64 },
    /// Receive window in bytes.
    Window { bytes: u32 },
    /// Liveness probe.
    Ping,
    /// End the session.
    Close,
}

impl ShellOut {
    /// Canonical CBOR encoding.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CanonicalError> {
        if let Self::Data { data, .. } = self {
            check_chunk(data)?;
        }
        canonical::to_canonical_vec(self)
    }

    /// Strict decoding; oversized data chunks are rejected.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CanonicalError> {
        let v: Self = canonical::from_canonical_slice(bytes)?;
        if let Self::Data { data, .. } = &v {
            check_chunk(data)?;
        }
        Ok(v)
    }
}

impl ShellIn {
    /// Canonical CBOR encoding.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CanonicalError> {
        if let Self::Data { data } = self {
            check_chunk(data)?;
        }
        canonical::to_canonical_vec(self)
    }

    /// Strict decoding; oversized data chunks are rejected.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CanonicalError> {
        let v: Self = canonical::from_canonical_slice(bytes)?;
        if let Self::Data { data } = &v {
            check_chunk(data)?;
        }
        Ok(v)
    }
}

impl ShellCtl {
    /// Canonical CBOR encoding.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical::to_canonical_vec(self)
    }

    /// Strict decoding.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CanonicalError> {
        canonical::from_canonical_slice(bytes)
    }
}
