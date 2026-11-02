//! The action result document (`rmm.result/1`), signed by the agent's key.

use rmm_proto::canonical::{from_canonical_slice, to_canonical_vec};
use rmm_trust::keys::{Bytes, KeyId};
use serde::{Deserialize, Serialize};

use crate::RecipeError;
use crate::definition::Stage;

/// Envelope payload type of a result.
pub const TYPE_RESULT: &str = "rmm.result/1";
/// Longest `detail` of a stage outcome in bytes.
pub const MAX_DETAIL: usize = 4096;
/// Most stage outcomes a result may carry.
pub const MAX_STAGES: usize = 16;

/// Overall outcome of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// All stages passed.
    Succeeded,
    /// The action failed and rollback was not (fully) applied.
    Failed,
    /// The action failed and rollback ran.
    RolledBack,
    /// The command was refused before execution.
    Rejected,
}

/// Why a command was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Outside its validity window.
    Expired,
    /// Command id already seen.
    Replay,
    /// Signature or role check failed.
    BadSignature,
    /// Addressed to another agent or client.
    WrongAgent,
    /// Definition is on the revocation list.
    Revoked,
    /// Definition not signed by a catalog key.
    UnsignedDefinition,
    /// Static recipe or parameter validation failed.
    Validation,
    /// Capability not within the signed ceiling.
    Capability,
    /// Trust documents are stale.
    StaleTrust,
    /// Agent older than the definition requires.
    AgentVersion,
}

/// Result of one stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageOutcome {
    /// Which stage.
    pub stage: Stage,
    /// Whether it passed.
    pub ok: bool,
    /// Start time (Unix seconds).
    pub started_at: u64,
    /// End time (Unix seconds).
    pub finished_at: u64,
    /// Free text, at most [`MAX_DETAIL`] bytes.
    pub detail: String,
}

/// The agent's report on one command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResult {
    /// Command id (16 bytes).
    pub cmd_id: Bytes,
    /// Reporting agent.
    pub agent_id: String,
    /// Content id of the definition that was (to be) run.
    pub definition_content_id: KeyId,
    /// Overall outcome.
    pub outcome: Outcome,
    /// Set exactly when the outcome is `Rejected`.
    pub reason: Option<RejectReason>,
    /// Per-stage outcomes in order.
    pub stages: Vec<StageOutcome>,
    /// Completion time (Unix seconds).
    pub finished_at: u64,
}

impl ActionResult {
    /// Structural validation.
    pub fn validate(&self) -> Result<(), RecipeError> {
        let bad = |m: &str| Err(RecipeError::InvalidDefinition(m.to_owned()));
        if self.cmd_id.0.len() != 16 {
            return bad("cmd_id must be 16 bytes");
        }
        if (self.outcome == Outcome::Rejected) != self.reason.is_some() {
            return bad("reason must be set exactly when rejected");
        }
        if self.stages.len() > MAX_STAGES {
            return bad("too many stages");
        }
        if self.stages.iter().any(|s| s.detail.len() > MAX_DETAIL) {
            return bad("stage detail too long");
        }
        Ok(())
    }

    /// Canonical CBOR encoding (the envelope payload).
    pub fn to_canonical(&self) -> Result<Vec<u8>, RecipeError> {
        to_canonical_vec(self).map_err(|e| RecipeError::Decode(e.to_string()))
    }

    /// Strictly decode an envelope payload (canonical, no unknown fields).
    pub fn from_envelope_payload(bytes: &[u8]) -> Result<Self, RecipeError> {
        let r: Self =
            from_canonical_slice(bytes).map_err(|e| RecipeError::Decode(e.to_string()))?;
        if r.to_canonical()? != bytes {
            return Err(RecipeError::Decode(
                "payload is not the canonical encoding of the result".into(),
            ));
        }
        Ok(r)
    }
}
