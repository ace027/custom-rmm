//! CLI behaviour of `rmm-agent enroll` that needs no server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

const IDENTITY: &str = r#"{
  "agent_id": "00000000-0000-0000-0000-000000000001",
  "device_id": "00000000-0000-0000-0000-000000000002",
  "client_id": "00000000-0000-0000-0000-000000000003",
  "nats_url": "nats://127.0.0.1:1",
  "server_url": "http://127.0.0.1:1"
}"#;

fn enrolled_dir() -> tempdir::Dir {
    let dir = tempdir::Dir::new();
    std::fs::write(dir.path().join("identity.json"), IDENTITY).unwrap();
    dir
}

fn agent(state: &Path, extra: &[&str], token_env: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rmm-agent"));
    cmd.args(["enroll", "--server", "http://127.0.0.1:1", "--state-dir"])
        .arg(state)
        .args(extra)
        .env_remove("RMM_ENROLL_TOKEN");
    if let Some(t) = token_env {
        cmd.env("RMM_ENROLL_TOKEN", t);
    }
    cmd.output().unwrap()
}

mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "rmm-agent-cli-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn if_not_enrolled_exits_zero_when_enrolled() {
    let dir = enrolled_dir();
    let out = agent(
        dir.path(),
        &["--token", "rmmenr_x", "--if-not-enrolled"],
        None,
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("already enrolled"));
}

#[test]
fn if_not_enrolled_accepts_env_token() {
    let dir = enrolled_dir();
    let out = agent(dir.path(), &["--if-not-enrolled"], Some("rmmenr_secret"));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("rmmenr_secret"));
}

#[test]
fn enrolled_without_flag_exits_two() {
    let dir = enrolled_dir();
    let out = agent(dir.path(), &["--token", "rmmenr_x"], None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

#[test]
fn unreachable_server_fails_with_agent_error_and_no_identity() {
    let dir = tempdir::Dir::new();
    let out = agent(dir.path(), &["--token", "rmmenr_secret"], None);
    assert_eq!(out.status.code(), Some(4), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("server unreachable"), "{stderr}");
    assert!(!stderr.contains("rmmenr_secret"));
    assert!(!dir.path().join("identity.json").exists());
}

#[test]
fn missing_token_is_a_usage_error() {
    let dir = tempdir::Dir::new();
    let out = agent(dir.path(), &[], None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("RMM_ENROLL_TOKEN"));
}
