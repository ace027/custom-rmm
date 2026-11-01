//! Runs a verified definition: precheck, snapshot, steps, verify and, when
//! steps or verify fail on a reversible definition, rollback. Every run ends
//! in an [`ActionResult`]; [`sign_result`] signs it with the agent key.
//!
//! Stage rules:
//! - precheck failure: outcome `failed`, nothing else runs;
//! - snapshot: values captured by snapshot-producing blocks (`service.query`)
//!   so far, keyed by block name;
//! - a step or verify failure (after retries, `on_fail: abort`) runs the
//!   rollback steps if the definition is reversible and has any; all
//!   rollback steps are attempted, and the outcome is `rolled_back` only if
//!   they all succeed, `failed` otherwise;
//! - `on_fail: continue` records the failure in the stage detail and goes on.
//!
//! The definition's `timeout_s` bounds precheck, steps and verify together;
//! rollback gets a fresh budget of the same length.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rmm_recipe::RecipeError;
use rmm_recipe::definition::{OnFail, Stage, Step};
use rmm_recipe::result::{
    ActionResult, MAX_DETAIL, Outcome, RejectReason, StageOutcome, TYPE_RESULT,
};
use rmm_recipe::validate::BLOCKS;
use rmm_trust::docs::CommandBody;
use rmm_trust::envelope::{ALG_ED25519, ENVELOPE_VERSION, Envelope, SigEntry, signing_message};
use rmm_trust::keys::{Bytes, KeyId, PublicKey, Sig64};

use crate::blocks::{BlockOutput, BlockRunner, StepCtx, resolve_args};
use crate::commands::Verified;

/// Pause between attempts of a retried step.
pub const RETRY_PAUSE: Duration = Duration::from_millis(500);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Cut `s` to at most [`MAX_DETAIL`] bytes on a character boundary.
fn clip(mut s: String) -> String {
    if s.len() > MAX_DETAIL {
        let mut end = MAX_DETAIL;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

struct Run<'a> {
    verified: &'a Verified,
    blocks: &'a dyn BlockRunner,
    params: BTreeMap<String, ciborium::Value>,
    snapshots: BTreeMap<String, String>,
    stages: Vec<StageOutcome>,
}

impl Run<'_> {
    fn step(&mut self, step: &Step, deadline: Instant) -> Result<BlockOutput, String> {
        let args = resolve_args(step, &self.params, &self.snapshots)?;
        let ctx = StepCtx {
            cmd_id: &self.verified.command.cmd_id.0,
        };
        let attempts = 1 + u32::from(step.retries.min(rmm_recipe::validate::MAX_RETRIES));
        let mut last = String::new();
        for attempt in 0..attempts {
            if Instant::now() >= deadline {
                return Err(format!("time budget exceeded ({last})"));
            }
            match self.blocks.run(&step.block, &args, &ctx) {
                Ok(out) => {
                    let produces = BLOCKS
                        .iter()
                        .any(|b| b.name == step.block && b.produces_snapshot);
                    if produces && let Some(v) = &out.snapshot {
                        self.snapshots.insert(step.block.clone(), v.clone());
                    }
                    return Ok(out);
                }
                Err(e) => last = e,
            }
            if attempt + 1 < attempts {
                std::thread::sleep(RETRY_PAUSE);
            }
        }
        Err(last)
    }

    /// Run `steps` as `stage`; returns whether the stage passed. With
    /// `keep_going` every step runs regardless of failures (rollback).
    fn stage(&mut self, stage: Stage, steps: &[Step], deadline: Instant, keep_going: bool) -> bool {
        let started_at = now_secs();
        let mut ok = true;
        let mut lines = Vec::new();
        for step in steps {
            match self.step(step, deadline) {
                Ok(out) => lines.push(format!("{}: ok {}", step.block, out.detail)),
                Err(e) => {
                    lines.push(format!("{}: FAILED {e}", step.block));
                    if step.on_fail == OnFail::Abort || keep_going {
                        ok = false;
                        if !keep_going {
                            break;
                        }
                    }
                }
            }
        }
        if steps.is_empty() {
            lines.push("no steps".into());
        }
        self.stages.push(StageOutcome {
            stage,
            ok,
            started_at,
            finished_at: now_secs(),
            detail: clip(lines.join("\n")),
        });
        ok
    }

    fn snapshot_stage(&mut self) {
        let at = now_secs();
        let detail = if self.snapshots.is_empty() {
            "nothing captured".to_owned()
        } else {
            self.snapshots
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        self.stages.push(StageOutcome {
            stage: Stage::Snapshot,
            ok: true,
            started_at: at,
            finished_at: at,
            detail: clip(detail),
        });
    }
}

/// Run a verified command through the stages and report the outcome.
pub fn run(verified: &Verified, blocks: &dyn BlockRunner) -> ActionResult {
    let def = &verified.definition;
    let params = match &verified.command.body {
        CommandBody::Invoke { params, .. } => params.clone(),
        _ => BTreeMap::new(),
    };
    let mut r = Run {
        verified,
        blocks,
        params,
        snapshots: BTreeMap::new(),
        stages: Vec::new(),
    };
    let budget = Duration::from_secs(u64::from(def.timeout_s));
    let deadline = Instant::now() + budget;

    let outcome = if !r.stage(Stage::Precheck, &def.precheck, deadline, false) {
        Outcome::Failed
    } else {
        r.snapshot_stage();
        let action_ok = r.stage(Stage::Steps, &def.steps, deadline, false)
            && r.stage(Stage::Verify, &def.verify, deadline, false);
        if action_ok {
            Outcome::Succeeded
        } else if def.reversible && !def.rollback.is_empty() {
            let rb_deadline = Instant::now() + budget;
            if r.stage(Stage::Rollback, &def.rollback, rb_deadline, true) {
                Outcome::RolledBack
            } else {
                Outcome::Failed
            }
        } else {
            Outcome::Failed
        }
    };
    ActionResult {
        cmd_id: verified.command.cmd_id.clone(),
        agent_id: verified.command.agent_id.clone(),
        definition_content_id: KeyId(verified.content_id),
        outcome,
        reason: None,
        stages: r.stages,
        finished_at: now_secs(),
    }
}

/// The result of a command refused before execution.
pub fn rejected(
    cmd_id: Vec<u8>,
    agent_id: &str,
    definition_content_id: [u8; 32],
    reason: RejectReason,
) -> ActionResult {
    ActionResult {
        cmd_id: Bytes(cmd_id),
        agent_id: agent_id.to_owned(),
        definition_content_id: KeyId(definition_content_id),
        outcome: Outcome::Rejected,
        reason: Some(reason),
        stages: Vec::new(),
        finished_at: now_secs(),
    }
}

/// Sign `result` with the agent seed: an `rmm.result/1` envelope over the
/// canonical payload, one ed25519 signature over
/// [`rmm_trust::envelope::signing_message`].
pub fn sign_result(result: &ActionResult, seed: &[u8; 32]) -> Result<Envelope, RecipeError> {
    result.validate()?;
    let payload = result.to_canonical()?;
    let key = SigningKey::from_bytes(seed);
    let sig = key.sign(&signing_message(TYPE_RESULT, &payload));
    let public = PublicKey::from_bytes(&key.verifying_key().to_bytes())
        .map_err(|e| RecipeError::Decode(e.to_string()))?;
    Ok(Envelope {
        v: ENVELOPE_VERSION,
        r#type: TYPE_RESULT.to_owned(),
        payload: Bytes(payload),
        sigs: vec![SigEntry {
            key_id: public.key_id(),
            alg: ALG_ED25519.to_owned(),
            sig: Sig64(sig.to_bytes()),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_respects_char_boundaries() {
        let s = "é".repeat(MAX_DETAIL);
        let c = clip(s);
        assert!(c.len() <= MAX_DETAIL);
        assert!(c.chars().all(|ch| ch == 'é'));
    }
}
