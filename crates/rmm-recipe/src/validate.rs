//! Static definition validation and caller-parameter validation.

use std::collections::{BTreeMap, BTreeSet};

use crate::RecipeError;
use crate::definition::{Arg, Definition, ParamKind, ParamSpec};

/// Most steps (all stages together) a definition may contain.
pub const MAX_STEPS: usize = 32;
/// Most retries a step may request.
pub const MAX_RETRIES: u8 = 3;
/// Longest overall timeout in seconds.
pub const MAX_TIMEOUT_S: u32 = 900;
/// Most declared parameters.
pub const MAX_PARAMS: usize = 16;
/// Default and upper bound of `max_len` for string parameters.
pub const DEFAULT_MAX_LEN: u32 = 256;
/// Hard ceiling for a declared string `max_len`.
pub const MAX_STRING_LEN: u32 = 4096;

/// Value type of a block argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// Text.
    Str,
    /// Signed integer.
    Int,
    /// Boolean.
    Bool,
}

/// Schema of one building block.
#[derive(Debug, Clone, Copy)]
pub struct BlockSpec {
    /// Block name.
    pub name: &'static str,
    /// Capability group the block belongs to.
    pub capability: &'static str,
    /// `(arg name, kind, required)`.
    pub args: &'static [(&'static str, ArgKind, bool)],
    /// Whether running it captures a snapshot keyed by the block name.
    pub produces_snapshot: bool,
}

/// The six phase-6 building blocks.
pub const BLOCKS: &[BlockSpec] = &[
    BlockSpec {
        name: "service.query",
        capability: "service",
        args: &[("name", ArgKind::Str, true)],
        produces_snapshot: true,
    },
    BlockSpec {
        name: "service.stop",
        capability: "service",
        args: &[
            ("name", ArgKind::Str, true),
            ("timeout_s", ArgKind::Int, true),
        ],
        produces_snapshot: false,
    },
    BlockSpec {
        name: "service.start",
        capability: "service",
        args: &[
            ("name", ArgKind::Str, true),
            ("timeout_s", ArgKind::Int, true),
        ],
        produces_snapshot: false,
    },
    BlockSpec {
        name: "service.wait",
        capability: "service",
        args: &[
            ("name", ArgKind::Str, true),
            ("state", ArgKind::Str, true),
            ("timeout_s", ArgKind::Int, true),
        ],
        produces_snapshot: false,
    },
    BlockSpec {
        name: "files.quarantine",
        capability: "files.write",
        args: &[
            ("root", ArgKind::Str, true),
            ("pattern", ArgKind::Str, true),
        ],
        produces_snapshot: false,
    },
    BlockSpec {
        name: "files.restore",
        capability: "files.write",
        args: &[],
        produces_snapshot: false,
    },
];

/// Extra block capability groups a definition capability may use.
/// A service recovery action may move files (quarantine its spool).
const ALLOWED_EXTRA: &[(&str, &str)] = &[("service", "files.write")];

fn capability_allowed(def_cap: &str, block_cap: &str) -> bool {
    def_cap == block_cap
        || ALLOWED_EXTRA
            .iter()
            .any(|(d, b)| *d == def_cap && *b == block_cap)
}

fn invalid_def<T>(m: &str) -> Result<T, RecipeError> {
    Err(RecipeError::InvalidDefinition(m.to_owned()))
}

fn ident_ok(s: &str, first_alpha_only: bool, extra: &[char]) -> bool {
    let mut chars = s.chars();
    let Some(c) = chars.next() else { return false };
    let first_ok = c.is_ascii_lowercase() || (!first_alpha_only && c.is_ascii_digit());
    first_ok && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(&c))
}

fn validate_id(id: &str) -> Result<(), RecipeError> {
    let segs: Vec<&str> = id.split('.').collect();
    if id.len() > 64 || segs.len() < 2 || !segs.iter().all(|s| ident_ok(s, false, &['-'])) {
        return invalid_def("id must be a dotted lowercase name of at least two segments");
    }
    Ok(())
}

fn validate_param_specs(params: &[ParamSpec]) -> Result<(), RecipeError> {
    if params.len() > MAX_PARAMS {
        return invalid_def("too many parameters");
    }
    let mut names = BTreeSet::new();
    for p in params {
        if p.name.len() > 32 || !ident_ok(&p.name, true, &['_']) {
            return invalid_def("parameter names are lowercase identifiers up to 32 bytes");
        }
        if !names.insert(p.name.as_str()) {
            return invalid_def("duplicate parameter name");
        }
        let numeric = p.min.is_some() || p.max.is_some();
        match p.kind {
            ParamKind::Enum => {
                let uniq: BTreeSet<&String> = p.enum_values.iter().collect();
                if p.enum_values.is_empty()
                    || p.enum_values.len() > 32
                    || uniq.len() != p.enum_values.len()
                    || p.enum_values.iter().any(|v| v.is_empty() || v.len() > 64)
                {
                    return invalid_def(
                        "enum parameter needs 1..=32 unique values of 1..=64 bytes",
                    );
                }
                if numeric || p.max_len.is_some() {
                    return invalid_def("enum parameter takes only enum_values");
                }
            }
            ParamKind::String => {
                if !p.enum_values.is_empty() || numeric {
                    return invalid_def("string parameter takes only max_len");
                }
                if p.max_len.is_some_and(|m| m == 0 || m > MAX_STRING_LEN) {
                    return invalid_def("max_len out of range");
                }
            }
            ParamKind::Int => {
                if !p.enum_values.is_empty() || p.max_len.is_some() {
                    return invalid_def("int parameter takes only min and max");
                }
                if let (Some(lo), Some(hi)) = (p.min, p.max)
                    && lo > hi
                {
                    return invalid_def("min exceeds max");
                }
            }
            ParamKind::Bool => {
                if !p.enum_values.is_empty() || numeric || p.max_len.is_some() {
                    return invalid_def("bool parameter takes no bounds");
                }
            }
        }
    }
    Ok(())
}

fn param_arg_kind(k: ParamKind) -> ArgKind {
    match k {
        ParamKind::String | ParamKind::Enum => ArgKind::Str,
        ParamKind::Int => ArgKind::Int,
        ParamKind::Bool => ArgKind::Bool,
    }
}

fn check_arg(
    def: &Definition,
    block: &str,
    name: &str,
    arg: &Arg,
    want: ArgKind,
    snapshots: &BTreeSet<&str>,
) -> Result<(), RecipeError> {
    let err = |m: &str| Err(RecipeError::InvalidArg(format!("{block}.{name}: {m}")));
    match arg {
        Arg::Lit(v) => {
            let ok = match (want, v) {
                (ArgKind::Str, ciborium::Value::Text(_)) => true,
                (ArgKind::Bool, ciborium::Value::Bool(_)) => true,
                (ArgKind::Int, ciborium::Value::Integer(i)) => i64::try_from(*i).is_ok(),
                _ => false,
            };
            if ok {
                Ok(())
            } else {
                err("literal has the wrong type")
            }
        }
        Arg::Param(p) => match def.params.iter().find(|s| &s.name == p) {
            None => err("parameter is not declared"),
            Some(s) if param_arg_kind(s.kind) == want => Ok(()),
            Some(_) => err("parameter kind does not fit the argument"),
        },
        Arg::Snapshot(key) => {
            if want != ArgKind::Str {
                err("snapshot values are text")
            } else if snapshots.contains(key.as_str()) {
                Ok(())
            } else {
                err("snapshot key not produced by an earlier step")
            }
        }
    }
}

/// Statically validate `def` against the block `registry`.
pub fn validate_definition(def: &Definition, registry: &[BlockSpec]) -> Result<(), RecipeError> {
    validate_id(&def.id)?;
    if def.version == 0 {
        return invalid_def("version must be at least 1");
    }
    if def.title.is_empty() || def.title.len() > 128 {
        return invalid_def("title must be 1..=128 bytes");
    }
    if def.capability.is_empty() || def.capability.len() > 64 {
        return invalid_def("capability must be 1..=64 bytes");
    }
    if semver::Version::parse(&def.min_agent_version).is_err() {
        return invalid_def("min_agent_version is not a semantic version");
    }
    if def.timeout_s == 0 || def.timeout_s > MAX_TIMEOUT_S {
        return invalid_def("timeout_s must be 1..=900");
    }
    validate_param_specs(&def.params)?;

    let total = def.precheck.len() + def.steps.len() + def.verify.len() + def.rollback.len();
    if total > MAX_STEPS {
        return Err(RecipeError::TooManySteps);
    }
    if def.steps.is_empty() {
        return invalid_def("steps must not be empty");
    }

    let mut snapshots: BTreeSet<&str> = BTreeSet::new();
    for (_, step) in def.all_steps() {
        let spec = registry
            .iter()
            .find(|b| b.name == step.block)
            .ok_or_else(|| RecipeError::UnknownBlock(step.block.clone()))?;
        if step.retries > MAX_RETRIES {
            return Err(RecipeError::InvalidRetries);
        }
        if !capability_allowed(&def.capability, spec.capability) {
            return Err(RecipeError::CapabilityMismatch(step.block.clone()));
        }
        for name in step.args.keys() {
            if !spec.args.iter().any(|(n, _, _)| n == name) {
                return Err(RecipeError::InvalidArg(format!(
                    "{}: unknown argument {name}",
                    step.block
                )));
            }
        }
        for (name, kind, required) in spec.args {
            match step.args.get(*name) {
                Some(arg) => check_arg(def, &step.block, name, arg, *kind, &snapshots)?,
                None if *required => {
                    return Err(RecipeError::InvalidArg(format!(
                        "{}: missing argument {name}",
                        step.block
                    )));
                }
                None => {}
            }
        }
        if spec.produces_snapshot {
            snapshots.insert(spec.name);
        }
    }
    Ok(())
}

fn bad_param<T>(name: &str, m: &str) -> Result<T, RecipeError> {
    Err(RecipeError::InvalidParam(format!("{name}: {m}")))
}

/// Validate caller `params` against the definition's declarations.
pub fn validate_params(
    def: &Definition,
    params: &BTreeMap<String, ciborium::Value>,
) -> Result<(), RecipeError> {
    use ciborium::Value;
    if let Some(unknown) = params
        .keys()
        .find(|k| !def.params.iter().any(|s| &s.name == *k))
    {
        return bad_param(unknown, "not declared");
    }
    for spec in &def.params {
        let Some(value) = params.get(&spec.name) else {
            if spec.required {
                return bad_param(&spec.name, "required but missing");
            }
            continue;
        };
        match (spec.kind, value) {
            (ParamKind::String, Value::Text(s)) => {
                let max = spec.max_len.unwrap_or(DEFAULT_MAX_LEN);
                if s.len() > usize::try_from(max).unwrap_or(usize::MAX) {
                    return bad_param(&spec.name, "string too long");
                }
            }
            (ParamKind::Enum, Value::Text(s)) => {
                if !spec.enum_values.iter().any(|v| v == s) {
                    return bad_param(&spec.name, "value not in enum_values");
                }
            }
            (ParamKind::Int, Value::Integer(i)) => {
                let Ok(n) = i64::try_from(*i) else {
                    return bad_param(&spec.name, "integer out of range");
                };
                if spec.min.is_some_and(|m| n < m) || spec.max.is_some_and(|m| n > m) {
                    return bad_param(&spec.name, "integer outside min..max");
                }
            }
            (ParamKind::Bool, Value::Bool(_)) => {}
            _ => return bad_param(&spec.name, "wrong type"),
        }
    }
    Ok(())
}
