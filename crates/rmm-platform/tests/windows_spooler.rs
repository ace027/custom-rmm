//! Drives the real Print Spooler through the SCM building blocks. Needs an
//! elevated Windows session (the CI runner is an administrator); otherwise
//! the test prints `skipping: not elevated` and passes.
#![cfg(windows)]

use std::time::Duration;

use rmm_platform::services::{ServiceState, services};

const TIMEOUT: Duration = Duration::from_secs(60);

/// `net session` succeeds only in an elevated session.
fn elevated() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn spooler_stop_and_start() {
    if !elevated() {
        println!("skipping: not elevated");
        return;
    }
    let scm = services();
    assert_eq!(
        scm.query("NoSuchService_rmm_test").expect("query missing"),
        ServiceState::Missing
    );
    let before = scm.query("Spooler").expect("query Spooler");
    assert_ne!(before, ServiceState::Missing, "Spooler must exist");

    scm.stop("Spooler", TIMEOUT).expect("stop Spooler");
    assert_eq!(scm.query("Spooler").expect("query"), ServiceState::Stopped);
    scm.stop("Spooler", TIMEOUT)
        .expect("stopping a stopped service succeeds");

    scm.start("Spooler", TIMEOUT).expect("start Spooler");
    assert_eq!(scm.query("Spooler").expect("query"), ServiceState::Running);
    scm.wait("Spooler", ServiceState::Running, Duration::from_secs(5))
        .expect("wait running");
}
