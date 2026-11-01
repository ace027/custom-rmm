//! The update client against a tiny std `TcpListener` HTTP responder: a newer
//! release is staged with `READY` written last, tampered bytes are rejected
//! without a `READY`, and older, equal, known-bad and busy cases are skipped.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use rmm_agent_core::update::{UpdateCtx, UpdateOutcome, on_release};
use rmm_trust::docs::{ReleaseArtifact, ReleaseManifest};
use rmm_trust::keys::Bytes;
use sha2::{Digest, Sha256};

const PLATFORM: &str = "linux-x86_64";
const BODY: &[u8] = b"#!/bin/sh\necho new agent\n";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "rmm-update-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(p.join("bootstrap")).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Serve `body` to every request on a loopback port; returns the base URL and
/// the path requested by the first connection.
fn serve(body: Vec<u8>) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut req = Vec::new();
        let mut buf = [0u8; 1024];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = conn.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
        }
        let line = String::from_utf8_lossy(&req)
            .lines()
            .next()
            .unwrap()
            .to_owned();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        conn.write_all(head.as_bytes()).unwrap();
        conn.write_all(&body).unwrap();
        line
    });
    (url, handle)
}

fn release(version: &str, body: &[u8]) -> ReleaseManifest {
    ReleaseManifest {
        seq: 2,
        version: version.into(),
        issued_at: 1,
        expires_at: 2,
        artifacts: vec![ReleaseArtifact {
            platform: PLATFORM.into(),
            sha256: Bytes(sha(body).to_vec()),
            size: body.len() as u64,
            name: "rmm-agent".into(),
        }],
    }
}

fn ctx(url: &str, root: &Path) -> UpdateCtx {
    UpdateCtx {
        api_base: url.into(),
        root: root.to_path_buf(),
        platform: PLATFORM.into(),
        current_version: "0.1.0".into(),
        http: reqwest::Client::new(),
    }
}

async fn run(rel: &ReleaseManifest, ctx: &UpdateCtx) -> UpdateOutcome {
    on_release(rel, b"release-env", b"manifest-env", ctx).await
}

#[tokio::test]
async fn newer_release_is_staged_with_ready_last() {
    let dir = TempDir::new();
    let (url, server) = serve(BODY.to_vec());
    let outcome = run(&release("0.1.1", BODY), &ctx(&url, &dir.0)).await;
    assert_eq!(outcome, UpdateOutcome::Staged);
    assert_eq!(
        server.join().unwrap(),
        format!("GET /v1/artifacts/{} HTTP/1.1", hex(&sha(BODY)))
    );
    let pending = dir.0.join("pending");
    assert_eq!(fs::read(pending.join("artifact")).unwrap(), BODY);
    assert_eq!(
        fs::read(pending.join("release.env")).unwrap(),
        b"release-env"
    );
    assert_eq!(
        fs::read(pending.join("manifest.env")).unwrap(),
        b"manifest-env"
    );
    assert_eq!(fs::read(pending.join("READY")).unwrap(), b"");
    let mut names: Vec<_> = fs::read_dir(&pending)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["READY", "artifact", "manifest.env", "release.env"]);
}

#[tokio::test]
async fn tampered_bytes_are_rejected_without_ready() {
    let dir = TempDir::new();
    let mut evil = BODY.to_vec();
    *evil.last_mut().unwrap() ^= 1;
    let (url, server) = serve(evil);
    let outcome = run(&release("0.1.1", BODY), &ctx(&url, &dir.0)).await;
    assert_eq!(outcome, UpdateOutcome::Failed("hash_mismatch".into()));
    server.join().unwrap();
    assert!(!dir.0.join("pending/READY").exists());
    assert!(!dir.0.join("pending/artifact").exists());
    assert!(!dir.0.join("pending/rmm-agent.part").exists());
}

#[tokio::test]
async fn oversized_body_is_aborted() {
    let dir = TempDir::new();
    let mut long = BODY.to_vec();
    long.extend_from_slice(b"more");
    let (url, server) = serve(long);
    let outcome = run(&release("0.1.1", BODY), &ctx(&url, &dir.0)).await;
    assert_eq!(outcome, UpdateOutcome::Failed("size_mismatch".into()));
    server.join().unwrap();
    assert!(!dir.0.join("pending/READY").exists());
}

#[tokio::test]
async fn older_and_equal_versions_are_skipped_without_a_request() {
    let dir = TempDir::new();
    // Nothing listens on this URL: a request would fail with download_failed.
    let c = ctx("http://127.0.0.1:1", &dir.0);
    assert_eq!(
        run(&release("0.0.9", BODY), &c).await,
        UpdateOutcome::Downgrade
    );
    assert_eq!(
        run(&release("0.1.0", BODY), &c).await,
        UpdateOutcome::UpToDate
    );
    assert!(!dir.0.join("pending").exists());
}

#[tokio::test]
async fn known_bad_hash_is_skipped() {
    let dir = TempDir::new();
    let state = format!(r#"{{"bad_hashes":["{}"],"extra":1}}"#, hex(&sha(BODY)));
    fs::write(dir.0.join("state.json"), state).unwrap();
    let c = ctx("http://127.0.0.1:1", &dir.0);
    assert_eq!(
        run(&release("0.1.1", BODY), &c).await,
        UpdateOutcome::KnownBad
    );
    assert!(!dir.0.join("pending").exists());
}

#[tokio::test]
async fn existing_ready_is_left_alone() {
    let dir = TempDir::new();
    let pending = dir.0.join("pending");
    fs::create_dir_all(&pending).unwrap();
    fs::write(pending.join("READY"), b"").unwrap();
    fs::write(pending.join("release.env"), b"first").unwrap();
    let c = ctx("http://127.0.0.1:1", &dir.0);
    assert_eq!(
        run(&release("0.1.1", BODY), &c).await,
        UpdateOutcome::Failed("pending_exists".into())
    );
    assert_eq!(fs::read(pending.join("release.env")).unwrap(), b"first");
}

#[tokio::test]
async fn leftovers_of_an_interrupted_download_are_cleared() {
    let dir = TempDir::new();
    let pending = dir.0.join("pending");
    fs::create_dir_all(&pending).unwrap();
    fs::write(pending.join("rmm-agent.part"), b"half").unwrap();
    let (url, server) = serve(BODY.to_vec());
    assert_eq!(
        run(&release("0.1.1", BODY), &ctx(&url, &dir.0)).await,
        UpdateOutcome::Staged
    );
    server.join().unwrap();
    assert!(!pending.join("rmm-agent.part").exists());
    assert!(pending.join("READY").exists());
}

#[tokio::test]
async fn release_without_an_artifact_for_this_platform_fails() {
    let dir = TempDir::new();
    let mut rel = release("0.1.1", BODY);
    rel.artifacts[0].platform = "windows-x86_64".into();
    let c = ctx("http://127.0.0.1:1", &dir.0);
    assert_eq!(
        run(&rel, &c).await,
        UpdateOutcome::Failed("no_artifact_for_platform".into())
    );
}
