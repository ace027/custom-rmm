//! NATS subject builders.

/// Subject on which an agent receives commands: `agent.<id>.cmd`.
pub fn agent_cmd(agent_id: &str) -> String {
    format!("agent.{agent_id}.cmd")
}

/// Telemetry subject: `telemetry.<client>.<agent>.<kind>`.
pub fn telemetry(client_id: &str, agent_id: &str, kind: &str) -> String {
    format!("telemetry.{client_id}.{agent_id}.{kind}")
}

/// Operator keystrokes to the agent shell: `shell.<agent>.<sid>.in`.
pub fn shell_in(agent_id: &str, sid: &str) -> String {
    format!("shell.{agent_id}.{sid}.in")
}

/// Shell output from the agent: `shell.<agent>.<sid>.out`.
pub fn shell_out(agent_id: &str, sid: &str) -> String {
    format!("shell.{agent_id}.{sid}.out")
}

/// Flow control and liveness for a shell session: `shell.<agent>.<sid>.ctl`.
pub fn shell_ctl(agent_id: &str, sid: &str) -> String {
    format!("shell.{agent_id}.{sid}.ctl")
}

/// Session id for a grant: the grant id as lowercase hex.
pub fn sid_from_grant_id(grant_id: &[u8]) -> String {
    use std::fmt::Write;
    grant_id.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
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
