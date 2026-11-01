//! Building blocks: the six [`rmm_recipe::validate::BLOCKS`] mapped onto
//! `rmm-platform` calls, plus argument resolution (`lit`, `param`,
//! `snapshot`).
//!
//! `files.quarantine` takes a root *name* (`spool`), never a path; the name is
//! mapped to a directory here and the directory must also be in the
//! platform allowlist. Each command quarantines into
//! `<state_dir>/quarantine/<cmd_id hex>/`, which `files.restore` restores.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rmm_platform::quarantine;
use rmm_platform::services::{ServiceState, Services};
use rmm_recipe::definition::{Arg, Step};
use rmm_recipe::validate::MAX_TIMEOUT_S;

/// Environment variable that enables the test platform (debug builds only).
pub const TEST_PLATFORM_ENV: &str = "RMM_AGENT_TEST_PLATFORM";
/// Root name of the print spool directory.
pub const SPOOL_ROOT: &str = "spool";
/// Directory under the state dir holding per-command quarantines.
pub const QUARANTINE_DIR: &str = "quarantine";
/// Test platform spool directory under the state dir.
pub const TEST_SPOOL_DIR: &str = "test-spool";

/// A resolved block argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    /// Text.
    Str(String),
    /// Integer.
    Int(i64),
    /// Boolean.
    Bool(bool),
}

/// Resolved arguments by name.
pub type Args = BTreeMap<String, ArgValue>;

/// Per-step context handed to a block.
#[derive(Debug, Clone, Copy)]
pub struct StepCtx<'a> {
    /// The command being run (keys the quarantine directory).
    pub cmd_id: &'a [u8],
}

/// What a block reports on success.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockOutput {
    /// Snapshot value (for blocks that produce one), keyed by block name.
    pub snapshot: Option<String>,
    /// Short human-readable note.
    pub detail: String,
}

/// Runs building blocks. Calls block the thread.
pub trait BlockRunner: fmt::Debug + Send + Sync {
    /// Run `block` with `args`; `Err` carries the failure detail.
    fn run(&self, block: &str, args: &Args, ctx: &StepCtx<'_>) -> Result<BlockOutput, String>;
}

fn cbor_to_arg(v: &ciborium::Value) -> Result<ArgValue, String> {
    match v {
        ciborium::Value::Text(s) => Ok(ArgValue::Str(s.clone())),
        ciborium::Value::Bool(b) => Ok(ArgValue::Bool(*b)),
        ciborium::Value::Integer(i) => i64::try_from(*i)
            .map(ArgValue::Int)
            .map_err(|_| "integer out of range".to_owned()),
        _ => Err("unsupported value type".to_owned()),
    }
}

/// Resolve a step's arguments. An optional parameter that was not supplied
/// leaves its argument out.
pub fn resolve_args(
    step: &Step,
    params: &BTreeMap<String, ciborium::Value>,
    snapshots: &BTreeMap<String, String>,
) -> Result<Args, String> {
    let mut out = Args::new();
    for (name, arg) in &step.args {
        let value = match arg {
            Arg::Lit(v) => cbor_to_arg(v).map_err(|e| format!("{name}: {e}"))?,
            Arg::Param(p) => match params.get(p) {
                Some(v) => cbor_to_arg(v).map_err(|e| format!("{name}: {e}"))?,
                None => continue,
            },
            Arg::Snapshot(key) => ArgValue::Str(
                snapshots
                    .get(key)
                    .cloned()
                    .ok_or_else(|| format!("{name}: no snapshot value for {key}"))?,
            ),
        };
        out.insert(name.clone(), value);
    }
    Ok(out)
}

fn str_arg<'a>(args: &'a Args, name: &str) -> Result<&'a str, String> {
    match args.get(name) {
        Some(ArgValue::Str(s)) => Ok(s),
        Some(_) => Err(format!("argument {name} must be text")),
        None => Err(format!("argument {name} missing")),
    }
}

fn timeout_arg(args: &Args) -> Result<Duration, String> {
    match args.get("timeout_s") {
        Some(ArgValue::Int(n)) => {
            let secs = u64::try_from(*n)
                .unwrap_or(0)
                .clamp(1, u64::from(MAX_TIMEOUT_S));
            Ok(Duration::from_secs(secs))
        }
        Some(_) => Err("argument timeout_s must be an integer".into()),
        None => Err("argument timeout_s missing".into()),
    }
}

/// Hex of a command id (quarantine directory name).
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Building blocks backed by `rmm-platform`.
#[derive(Debug)]
pub struct PlatformBlocks {
    services: Box<dyn Services>,
    roots: BTreeMap<String, PathBuf>,
    allowed: Vec<PathBuf>,
    quarantine_base: PathBuf,
}

impl PlatformBlocks {
    /// Blocks over `services`, with named quarantine `roots` that must also be
    /// in `allowed`; quarantines live under `state_dir/quarantine`.
    pub fn new(
        services: Box<dyn Services>,
        roots: BTreeMap<String, PathBuf>,
        allowed: Vec<PathBuf>,
        state_dir: &Path,
    ) -> Self {
        Self {
            services,
            roots,
            allowed,
            quarantine_base: state_dir.join(QUARANTINE_DIR),
        }
    }

    /// The real platform: the OS service controller and the platform's
    /// allowlisted roots.
    pub fn native(state_dir: &Path) -> Self {
        let roots = quarantine::spool_root()
            .map(|p| (SPOOL_ROOT.to_owned(), p))
            .into_iter()
            .collect();
        Self::new(
            rmm_platform::services::services(),
            roots,
            quarantine::allowed_roots(),
            state_dir,
        )
    }

    /// The CI test platform: `services` instead of the OS, and `spool` mapped
    /// to (and allowlisted as) `state_dir/test-spool`, which is created.
    #[cfg(debug_assertions)]
    pub fn test_platform(services: Box<dyn Services>, state_dir: &Path) -> std::io::Result<Self> {
        let spool = state_dir.join(TEST_SPOOL_DIR);
        std::fs::create_dir_all(&spool)?;
        let mut allowed = quarantine::allowed_roots();
        allowed.push(spool.clone());
        let roots = BTreeMap::from([(SPOOL_ROOT.to_owned(), spool)]);
        Ok(Self::new(services, roots, allowed, state_dir))
    }

    /// What `rmm-agent run` uses: the test platform (fake services honouring
    /// `RMM_AGENT_FAKE_FAIL_START`) when this is a debug build and
    /// `RMM_AGENT_TEST_PLATFORM=1`, the native platform otherwise.
    pub fn for_agent(state_dir: &Path) -> Self {
        #[cfg(debug_assertions)]
        if std::env::var_os(TEST_PLATFORM_ENV).is_some_and(|v| v == "1") {
            let fake = Box::new(rmm_platform::fake::FakeServices::from_env());
            match Self::test_platform(fake, state_dir) {
                Ok(b) => {
                    tracing::warn!("test platform enabled: services are simulated");
                    return b;
                }
                Err(e) => tracing::error!("test platform unavailable: {e}"),
            }
        }
        Self::native(state_dir)
    }

    /// Quarantine directory of a command.
    pub fn quarantine_dir(&self, cmd_id: &[u8]) -> PathBuf {
        self.quarantine_base.join(hex(cmd_id))
    }

    fn service_state(&self, name: &str) -> Result<ServiceState, String> {
        self.services
            .query(name)
            .map_err(|e| format!("query {name}: {e}"))
    }
}

impl BlockRunner for PlatformBlocks {
    fn run(&self, block: &str, args: &Args, ctx: &StepCtx<'_>) -> Result<BlockOutput, String> {
        match block {
            "service.query" => {
                let name = str_arg(args, "name")?;
                match self.service_state(name)? {
                    ServiceState::Missing => Err(format!("service {name} does not exist")),
                    st => Ok(BlockOutput {
                        snapshot: Some(st.as_str().to_owned()),
                        detail: format!("{name} is {st}"),
                    }),
                }
            }
            "service.stop" => {
                let name = str_arg(args, "name")?;
                self.services
                    .stop(name, timeout_arg(args)?)
                    .map_err(|e| format!("stop {name}: {e}"))?;
                Ok(BlockOutput {
                    snapshot: None,
                    detail: format!("{name} stopped"),
                })
            }
            "service.start" => {
                let name = str_arg(args, "name")?;
                self.services
                    .start(name, timeout_arg(args)?)
                    .map_err(|e| format!("start {name}: {e}"))?;
                Ok(BlockOutput {
                    snapshot: None,
                    detail: format!("{name} started"),
                })
            }
            "service.wait" => {
                let name = str_arg(args, "name")?;
                let want = str_arg(args, "state")?;
                let want = ServiceState::parse(want)
                    .ok_or_else(|| format!("unknown service state {want}"))?;
                self.services
                    .wait(name, want, timeout_arg(args)?)
                    .map_err(|e| format!("wait {name}: {e}"))?;
                Ok(BlockOutput {
                    snapshot: None,
                    detail: format!("{name} is {want}"),
                })
            }
            "files.quarantine" => {
                let root_name = str_arg(args, "root")?;
                let pattern = str_arg(args, "pattern")?;
                let root = self
                    .roots
                    .get(root_name)
                    .ok_or_else(|| format!("root {root_name} is not available on this platform"))?;
                let moved = quarantine::quarantine_in(
                    &self.allowed,
                    root,
                    pattern,
                    &self.quarantine_dir(ctx.cmd_id),
                )
                .map_err(|e| format!("quarantine {root_name}: {e}"))?;
                let bytes: u64 = moved.iter().map(|m| m.size).sum();
                Ok(BlockOutput {
                    snapshot: None,
                    detail: format!(
                        "{} file(s), {bytes} byte(s) quarantined from {root_name}",
                        moved.len()
                    ),
                })
            }
            "files.restore" => {
                let n = quarantine::restore(&self.quarantine_dir(ctx.cmd_id))
                    .map_err(|e| format!("restore: {e}"))?;
                Ok(BlockOutput {
                    snapshot: None,
                    detail: format!("{n} file(s) restored"),
                })
            }
            other => Err(format!("unknown block {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_recipe::definition::OnFail;

    fn step(args: &[(&str, Arg)]) -> Step {
        Step {
            block: "service.wait".into(),
            args: args
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
            retries: 0,
            on_fail: OnFail::Abort,
        }
    }

    #[test]
    fn resolves_lit_param_and_snapshot() {
        let s = step(&[
            ("name", Arg::Lit(ciborium::Value::Text("Spooler".into()))),
            ("timeout_s", Arg::Param("wait_s".into())),
            ("state", Arg::Snapshot("service.query".into())),
            ("opt", Arg::Param("absent".into())),
        ]);
        let params = BTreeMap::from([("wait_s".to_owned(), ciborium::Value::Integer(30.into()))]);
        let snaps = BTreeMap::from([("service.query".to_owned(), "running".to_owned())]);
        let args = resolve_args(&s, &params, &snaps).expect("resolve");
        assert_eq!(args["name"], ArgValue::Str("Spooler".into()));
        assert_eq!(args["timeout_s"], ArgValue::Int(30));
        assert_eq!(args["state"], ArgValue::Str("running".into()));
        assert!(!args.contains_key("opt"));
        assert!(resolve_args(&s, &params, &BTreeMap::new()).is_err());
    }

    #[test]
    fn timeouts_are_clamped() {
        let a = |n| Args::from([("timeout_s".to_owned(), ArgValue::Int(n))]);
        assert_eq!(timeout_arg(&a(-5)).expect("t"), Duration::from_secs(1));
        assert_eq!(timeout_arg(&a(30)).expect("t"), Duration::from_secs(30));
        assert_eq!(
            timeout_arg(&a(99_999)).expect("t"),
            Duration::from_secs(900)
        );
    }
}
