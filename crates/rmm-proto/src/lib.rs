//! Wire types, IDs and NATS subject builders shared by agent and server.

pub mod canonical;
pub mod enroll;
pub mod telemetry;

/// Version of the agent/server wire protocol.
pub const PROTOCOL_VERSION: u16 = 1;

/// NATS subject builders.
pub mod subjects {
    /// Subject on which an agent receives commands: `agent.<id>.cmd`.
    pub fn agent_cmd(agent_id: &str) -> String {
        format!("agent.{agent_id}.cmd")
    }

    /// Telemetry subject: `telemetry.<client>.<agent>.<kind>`.
    pub fn telemetry(client_id: &str, agent_id: &str, kind: &str) -> String {
        format!("telemetry.{client_id}.{agent_id}.{kind}")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn builds_subjects() {
            assert_eq!(agent_cmd("a1"), "agent.a1.cmd");
            assert_eq!(telemetry("c1", "a1", "cpu"), "telemetry.c1.a1.cpu");
        }
    }
}
