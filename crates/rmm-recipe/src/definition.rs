//! The signed action definition document (`rmm.definition/1`).
//!
//! A definition is canonical CBOR carried as the payload of a catalog-signed
//! envelope. It is pure data: a bounded list of steps over a fixed block
//! registry, with no loops, branching or arbitrary execution.

use std::collections::BTreeMap;

use rmm_proto::canonical::{from_canonical_slice, to_canonical_vec};
use serde::{Deserialize, Serialize};

use crate::RecipeError;

/// Envelope payload type of a definition.
pub const TYPE_DEFINITION: &str = "rmm.definition/1";

/// Kind of a declared parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamKind {
    /// UTF-8 text bounded by `max_len`.
    String,
    /// Signed integer bounded by `min..=max`.
    Int,
    /// Boolean.
    Bool,
    /// Text that must equal one of `enum_values`.
    Enum,
}

/// Declaration of one caller-supplied parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    /// Parameter name.
    pub name: String,
    /// Parameter kind.
    pub kind: ParamKind,
    /// Whether the caller must supply it.
    pub required: bool,
    /// Allowed values (enum kind only).
    #[serde(default)]
    pub enum_values: Vec<String>,
    /// Longest allowed string in bytes (string kind only).
    #[serde(default)]
    pub max_len: Option<u32>,
    /// Smallest allowed value (int kind only).
    #[serde(default)]
    pub min: Option<i64>,
    /// Largest allowed value (int kind only).
    #[serde(default)]
    pub max: Option<i64>,
}

/// A step argument: a literal, a caller parameter or a snapshot value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arg {
    /// Literal text, integer or boolean.
    Lit(ciborium::Value),
    /// The value of a declared parameter.
    Param(String),
    /// A value captured by an earlier snapshot step (keyed by block name).
    Snapshot(String),
}

/// What happens when a step fails after its retries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnFail {
    /// Stop the stage (and trigger rollback where defined).
    #[default]
    Abort,
    /// Record the failure and go on.
    Continue,
}

/// One building-block invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Block name from the agent's registry.
    pub block: String,
    /// Block arguments by name.
    #[serde(default)]
    pub args: BTreeMap<String, Arg>,
    /// Extra attempts after the first failure (at most 3).
    #[serde(default)]
    pub retries: u8,
    /// Failure policy.
    #[serde(default)]
    pub on_fail: OnFail,
}

/// Execution stage; shared by definitions' step lists and results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Preconditions.
    Precheck,
    /// State capture (snapshot-producing precheck steps).
    Snapshot,
    /// The action proper.
    Steps,
    /// Post-condition checks.
    Verify,
    /// Undo after a failure.
    Rollback,
}

/// A catalog action definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    /// Dotted action name, e.g. `printing.spooler-restart`.
    pub id: String,
    /// Definition version.
    pub version: u32,
    /// Human-readable title.
    pub title: String,
    /// Capability group the action needs.
    pub capability: String,
    /// Whether rollback fully undoes the action.
    pub reversible: bool,
    /// Highest autonomy level (stored; not enforced yet).
    pub max_autonomy: u8,
    /// Oldest agent version able to run it (semver).
    pub min_agent_version: String,
    /// Overall time budget in seconds (at most 900).
    pub timeout_s: u32,
    /// Declared parameters.
    #[serde(default)]
    pub params: Vec<ParamSpec>,
    /// Precondition steps.
    #[serde(default)]
    pub precheck: Vec<Step>,
    /// Action steps.
    pub steps: Vec<Step>,
    /// Verification steps.
    #[serde(default)]
    pub verify: Vec<Step>,
    /// Rollback steps.
    #[serde(default)]
    pub rollback: Vec<Step>,
}

impl Definition {
    /// Strictly decode an envelope payload: canonical CBOR, no unknown fields,
    /// byte-identical to the canonical re-encoding. Does not validate.
    pub fn from_envelope_payload(bytes: &[u8]) -> Result<Self, RecipeError> {
        let def: Self =
            from_canonical_slice(bytes).map_err(|e| RecipeError::Decode(e.to_string()))?;
        let again = def.to_canonical()?;
        if again != bytes {
            return Err(RecipeError::Decode(
                "payload is not the canonical encoding of the definition".into(),
            ));
        }
        Ok(def)
    }

    /// Canonical CBOR encoding (the envelope payload).
    pub fn to_canonical(&self) -> Result<Vec<u8>, RecipeError> {
        to_canonical_vec(self).map_err(|e| RecipeError::Decode(e.to_string()))
    }

    /// All steps with their stage in execution order.
    pub fn all_steps(&self) -> impl Iterator<Item = (Stage, &Step)> {
        let pre = self.precheck.iter().map(|st| (Stage::Precheck, st));
        let run = self.steps.iter().map(|st| (Stage::Steps, st));
        let ver = self.verify.iter().map(|st| (Stage::Verify, st));
        let rol = self.rollback.iter().map(|st| (Stage::Rollback, st));
        pre.chain(run).chain(ver).chain(rol)
    }
}
