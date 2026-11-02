//! Wire types, IDs and NATS subject builders shared by agent and server.

pub mod canonical;
pub mod enroll;
pub mod shell;
pub mod subjects;
pub mod telemetry;

/// Version of the agent/server wire protocol.
pub const PROTOCOL_VERSION: u16 = 1;
