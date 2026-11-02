//! Developer automation: `cargo run -p xtask -- openapi [--check]` and
//! `cargo run -p xtask -- action-fixtures [--out DIR]` and
//! `cargo run -p xtask -- msi [--out DIR] [--no-build] [--dry-run]` and
//! `cargo run -p xtask -- fake-authn ca|register|assert` (dev and CI only).

mod action_fixtures;
mod fake_authn;
mod msi;

use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn openapi(check: bool) -> Result<(), String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(["run", "-q", "-p", "rmm-server", "--", "openapi"])
        .current_dir(root())
        .output()
        .map_err(|e| format!("failed to run cargo: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "rmm-server openapi failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let mut spec = out.stdout;
    if spec.last() != Some(&b'\n') {
        spec.push(b'\n');
    }
    let path = root().join("docs/openapi.json");
    if check {
        let current = std::fs::read(&path).unwrap_or_default();
        if current != spec {
            return Err(
                "docs/openapi.json is stale; run cargo run -p xtask -- openapi".to_string(),
            );
        }
        Ok(())
    } else {
        std::fs::write(&path, spec).map_err(|e| format!("write {}: {e}", path.display()))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("openapi") => openapi(args.iter().any(|a| a == "--check")),
        Some("action-fixtures") => {
            let out = match args.iter().position(|a| a == "--out") {
                Some(i) => args.get(i + 1).map(PathBuf::from),
                None => Some(action_fixtures::default_out(&root())),
            };
            match out {
                Some(dir) => action_fixtures::run(&dir),
                None => Err("--out needs a directory".to_string()),
            }
        }
        Some("msi") => msi::run_msi(&root(), &args[1..]),
        Some("fake-authn") => fake_authn::run(&args[1..]),
        _ => Err(
            "usage: xtask openapi [--check] | action-fixtures [--out DIR] | msi [--out DIR] [--no-build] [--dry-run] | fake-authn ca|register|assert"
                .to_string(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}
