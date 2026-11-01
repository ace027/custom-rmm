//! `xtask msi [--out DIR] [--no-build] [--dry-run]`: build the Windows installer.

use std::path::{Path, PathBuf};
use std::process::Command;

const BINARIES: [(&str, &str); 3] = [
    ("rmm-agent", "rmm-agent.exe"),
    ("rmm-watchdog", "rmm-watchdog.exe"),
    ("rmm-session", "rmm-session.exe"),
];

struct Plan {
    out_dir: PathBuf,
    staging: PathBuf,
    msi: PathBuf,
    build: Vec<String>,
    wix: Vec<String>,
}

fn plan(root: &Path, out: Option<PathBuf>) -> Plan {
    let version = env!("CARGO_PKG_VERSION");
    let out_dir = out.unwrap_or_else(|| root.join("target/msi"));
    let staging = out_dir.join("staging");
    let msi = out_dir.join(format!("rmm-agent-{version}-x64.msi"));
    let mut build: Vec<String> = ["cargo", "build", "--release"]
        .iter()
        .map(ToString::to_string)
        .collect();
    for (pkg, _) in BINARIES {
        build.push("-p".into());
        build.push(pkg.into());
    }
    let wix = vec![
        "wix".into(),
        "build".into(),
        root.join("installer/wix/Package.wxs").display().to_string(),
        "-arch".into(),
        "x64".into(),
        "-ext".into(),
        "WixToolset.Util.wixext".into(),
        "-d".into(),
        format!("Version={version}"),
        "-d".into(),
        format!("BinDir={}", staging.display()),
        "-o".into(),
        msi.display().to_string(),
    ];
    Plan {
        out_dir,
        staging,
        msi,
        build,
        wix,
    }
}

fn run(cmd: &[String], root: &Path) -> Result<(), String> {
    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(root)
        .status()
        .map_err(|e| format!("failed to run {}: {e}", cmd[0]))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} failed ({status})", cmd[0]))
    }
}

pub fn run_msi(root: &Path, args: &[String]) -> Result<(), String> {
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let no_build = args.iter().any(|a| a == "--no-build");
    let out = match args.iter().position(|a| a == "--out") {
        Some(i) => Some(
            args.get(i + 1)
                .map(PathBuf::from)
                .ok_or("--out needs a directory")?,
        ),
        None => None,
    };
    let p = plan(root, out);
    if !cfg!(windows) {
        if dry_run {
            if !no_build {
                println!("{}", p.build.join(" "));
            }
            println!("stage target/release/*.exe -> {}", p.staging.display());
            println!("{}", p.wix.join(" "));
            return Ok(());
        }
        return Err(
            "xtask msi builds Windows installers and must run on Windows \
             (use --dry-run to print the commands)"
                .to_string(),
        );
    }
    if !no_build {
        if std::env::var_os("RMM_ROOT_PUBKEYS").is_none_or(|v| v.is_empty()) {
            return Err("RMM_ROOT_PUBKEYS must be set to build release binaries".to_string());
        }
        if dry_run {
            println!("{}", p.build.join(" "));
        } else {
            run(&p.build, root)?;
        }
    }
    if dry_run {
        println!("stage target/release/*.exe -> {}", p.staging.display());
        println!("{}", p.wix.join(" "));
        return Ok(());
    }
    std::fs::create_dir_all(&p.staging)
        .map_err(|e| format!("create {}: {e}", p.staging.display()))?;
    for (_, exe) in BINARIES {
        let src = root.join("target/release").join(exe);
        std::fs::copy(&src, p.staging.join(exe))
            .map_err(|e| format!("stage {}: {e}", src.display()))?;
    }
    run(&p.wix, root)?;
    println!("built {} (in {})", p.msi.display(), p.out_dir.display());
    Ok(())
}
