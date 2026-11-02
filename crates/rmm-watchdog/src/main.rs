//! `rmm-watchdog`: supervises the agent and applies verified releases.
//!
//! ```text
//! rmm-watchdog run --root DIR --state-dir DIR [--health-timeout SECS] [-- AGENT_ARGS...]
//! rmm-watchdog service [--root DIR] [--state-dir DIR] [--health-timeout SECS] [-- AGENT_ARGS...]
//! rmm-watchdog status --root DIR
//! rmm-watchdog --version
//! ```
//!
//! `service` is the Windows SCM entry point; root and state dir default to
//! `%ProgramData%\RMM` there.

#[cfg(windows)]
#[allow(unsafe_code)]
mod service_windows;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rmm_watchdog::supervisor::{Config, DEFAULT_HEALTH_TIMEOUT, MAX_HEALTH_TIMEOUT, Supervisor};

/// Root public keys (comma-separated hex), compiled in like the agent's.
const ROOT_PUBKEYS: Option<&str> = option_env!("RMM_ROOT_PUBKEYS");
/// Root signature threshold used before a manifest is applied.
const ROOT_THRESHOLD: Option<&str> = option_env!("RMM_ROOT_THRESHOLD");

// Release builds must carry the root keys; only debug builds may go without.
#[cfg(not(debug_assertions))]
const _: () = assert!(
    ROOT_PUBKEYS.is_some(),
    "RMM_ROOT_PUBKEYS must be set when building a release watchdog"
);

const USAGE: &str = "usage:
  rmm-watchdog run --root DIR --state-dir DIR [--health-timeout SECS] [-- AGENT_ARGS...]
  rmm-watchdog service [--root DIR] [--state-dir DIR] [--health-timeout SECS] [-- AGENT_ARGS...]
  rmm-watchdog status --root DIR
  rmm-watchdog --version";

/// Options shared by `run` and `service`.
#[derive(Debug, Clone)]
struct RunOpts {
    root: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    health_timeout: Duration,
    agent_args: Vec<OsString>,
}

fn value(it: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<OsString, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_run(args: Vec<OsString>) -> Result<RunOpts, String> {
    let mut opts = RunOpts {
        root: None,
        state_dir: None,
        health_timeout: DEFAULT_HEALTH_TIMEOUT,
        agent_args: Vec::new(),
    };
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--") => {
                opts.agent_args = it.collect();
                break;
            }
            Some("--root") => opts.root = Some(value(&mut it, "--root")?.into()),
            Some("--state-dir") => opts.state_dir = Some(value(&mut it, "--state-dir")?.into()),
            Some("--health-timeout") => {
                let v = value(&mut it, "--health-timeout")?;
                let secs: u64 = v
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or("--health-timeout must be a number of seconds")?;
                if secs == 0 || secs > MAX_HEALTH_TIMEOUT.as_secs() {
                    return Err(format!(
                        "--health-timeout must be 1..={}",
                        MAX_HEALTH_TIMEOUT.as_secs()
                    ));
                }
                opts.health_timeout = Duration::from_secs(secs);
            }
            _ => return Err(format!("unexpected argument {}", arg.to_string_lossy())),
        }
    }
    Ok(opts)
}

/// Supervisor config for `root` and `state_dir`, with the compiled-in roots.
fn build_config(opts: &RunOpts, root: PathBuf, state_dir: PathBuf) -> Result<Config, String> {
    let (roots, threshold) = rmm_watchdog::parse_roots(ROOT_PUBKEYS.unwrap_or(""), ROOT_THRESHOLD)?;
    if roots.is_empty() {
        rmm_watchdog::log(
            "no_root_keys",
            serde_json::json!({ "note": "built without RMM_ROOT_PUBKEYS; every release is rejected" }),
        );
    }
    Ok(Config {
        root,
        state_dir,
        agent_args: opts.agent_args.clone(),
        health_timeout: opts.health_timeout,
        roots,
        threshold,
        platform: rmm_watchdog::platform(),
        clock: rmm_watchdog::now_secs,
    })
}

/// Foreground supervisor (unix dev/e2e). std has no signal API, so it runs
/// until killed; the agent child is left to the session's process group.
fn run(opts: RunOpts) -> Result<(), String> {
    let root = opts.root.clone().ok_or("run needs --root DIR")?;
    let state_dir = opts.state_dir.clone().ok_or("run needs --state-dir DIR")?;
    let cfg = build_config(&opts, root, state_dir)?;
    let mut sup = Supervisor::new(cfg).map_err(|e| format!("start: {e}"))?;
    sup.run(&AtomicBool::new(false));
    Ok(())
}

fn status(args: Vec<OsString>) -> Result<(), String> {
    let mut it = args.into_iter();
    let mut root = None;
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--root") => root = Some(PathBuf::from(value(&mut it, "--root")?)),
            _ => return Err(format!("unexpected argument {}", arg.to_string_lossy())),
        }
    }
    let path = root
        .ok_or("status needs --root DIR")?
        .join(rmm_watchdog::state::STATE_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    print!("{text}");
    Ok(())
}

#[cfg(windows)]
fn service(opts: RunOpts) -> Result<(), String> {
    service_windows::run(opts)
}

#[cfg(not(windows))]
fn service(_opts: RunOpts) -> Result<(), String> {
    Err("service is only available on Windows; use run".into())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let cmd = args.next();
    let rest: Vec<OsString> = args.collect();
    let result = match cmd.as_ref().and_then(|c| c.to_str()) {
        Some("--version" | "-V") => {
            println!("rmm-watchdog {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("run") => parse_run(rest).and_then(run),
        Some("service") => parse_run(rest).and_then(service),
        Some("status") => status(rest),
        Some("--help" | "-h") => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("rmm-watchdog: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn run_flags_parse() {
        let o = parse_run(os(&[
            "--root",
            "/r",
            "--state-dir",
            "/s",
            "--health-timeout",
            "30",
            "--",
            "run",
            "--state-dir",
            "/x",
        ]))
        .expect("parse");
        assert_eq!(o.root, Some(PathBuf::from("/r")));
        assert_eq!(o.state_dir, Some(PathBuf::from("/s")));
        assert_eq!(o.health_timeout, Duration::from_secs(30));
        assert_eq!(o.agent_args, os(&["run", "--state-dir", "/x"]));
        assert_eq!(
            parse_run(vec![]).expect("defaults").health_timeout,
            DEFAULT_HEALTH_TIMEOUT
        );
    }

    #[test]
    fn health_timeout_is_bounded() {
        for bad in ["0", "301", "x"] {
            assert!(parse_run(os(&["--health-timeout", bad])).is_err(), "{bad}");
        }
        assert!(parse_run(os(&["--health-timeout", "300"])).is_ok());
        assert!(parse_run(os(&["--bogus"])).is_err());
        assert!(parse_run(os(&["--root"])).is_err());
    }
}
