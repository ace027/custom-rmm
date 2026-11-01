//! Enrollment client against a minimal local HTTP server.
//!
//! The server is hand-rolled on tokio because the crate has no HTTP server
//! dependency; it speaks just enough HTTP/1.1 for one JSON POST per
//! connection.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use rmm_agent_core::enroll::{EnrollError, EnrollOptions, Enrolled, Retry, enroll, http_client};
use rmm_agent_core::identity;
use rmm_platform::{HwFacts, Platform, PlatformError};
use rmm_proto::enroll::{EnrollRequest, EnrollResponse, TrustBundle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

const TOKEN: &str = "rmmenr_SECRETTOKENVALUE";

#[derive(Debug)]
struct FakePlatform;

impl Platform for FakePlatform {
    fn hostname(&self) -> Result<String, PlatformError> {
        Ok("test-host".into())
    }
    fn hw_facts(&self) -> HwFacts {
        HwFacts {
            smbios_uuid: Some("4C4C4544-0042-3510-8051-B7C04F4C4C32".into()),
            system_serial: Some("ABC123".into()),
            board_serial: Some("BRD9".into()),
            manufacturer: Some("Test".into()),
            model: Some("Model".into()),
        }
    }
    fn os_info(&self) -> (String, String) {
        ("linux".into(), "Test OS 1".into())
    }
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<EnrollRequest>>>,
}

/// Serve `/v1/enroll`: 200 returns a canned response, anything else 401.
async fn serve(status: u16) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Some(body) = read_request(&mut sock).await else {
                    return;
                };
                if let Ok(req) = serde_json::from_slice::<EnrollRequest>(&body) {
                    seen.lock().expect("lock").push(req);
                }
                let (code, payload) = if status == 200 {
                    let resp = EnrollResponse {
                        agent_id: Uuid::from_u128(1),
                        device_id: Uuid::from_u128(2),
                        client_id: Uuid::from_u128(3),
                        nats_url: "wss://rmm.test/nats".into(),
                        trust: TrustBundle::default(),
                        status: "active".into(),
                    };
                    ("200 OK", serde_json::to_vec(&resp).expect("json"))
                } else {
                    ("401 Unauthorized", b"{}".to_vec())
                };
                let head = format!(
                    "HTTP/1.1 {code}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&payload).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Server { url, requests }
}

async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())?;
        while buf.len() < end + 4 + len {
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        return Some(buf[end + 4..end + 4 + len].to_vec());
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmm-enroll-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn opts(dir: &Path, force: bool) -> EnrollOptions {
    let mut o = EnrollOptions::new(dir);
    o.force = force;
    o.retry = Retry {
        attempts: 3,
        base_delay: Duration::from_millis(10),
    };
    o
}

async fn run(url: &str, dir: &Path, force: bool) -> Result<Enrolled, EnrollError> {
    let ks = rmm_platform::keystore(dir);
    enroll(
        url,
        TOKEN,
        ks.as_ref(),
        &FakePlatform,
        http_client(None).expect("client"),
        &opts(dir, force),
    )
    .await
}

fn key_of(dir: &Path) -> Option<[u8; 32]> {
    rmm_platform::keystore(dir).load().expect("key load")
}

fn verify(req: &EnrollRequest) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&req.agent_pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&req.proof) else {
        return false;
    };
    vk.verify_strict(&req.signing_bytes(), &sig).is_ok()
}

#[tokio::test]
async fn happy_path_writes_identity_and_key() {
    let dir = scratch("happy");
    let srv = serve(200).await;
    let done = run(&srv.url, &dir, false).await.expect("enroll");
    assert_eq!(done.status, "active");
    assert_eq!(done.identity.agent_id, Uuid::from_u128(1));

    let loaded = identity::load(&dir).expect("load").expect("present");
    assert_eq!(loaded, done.identity);
    assert_eq!(loaded.server_url, srv.url);
    assert_eq!(loaded.nats_url, "wss://rmm.test/nats");

    let seed = key_of(&dir).expect("key stored");
    let sent = srv.requests.lock().expect("lock");
    assert_eq!(sent.len(), 1);
    let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    assert_eq!(sent[0].agent_pubkey, vk.to_bytes());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn proof_verifies_on_server_side() {
    let dir = scratch("proof");
    let srv = serve(200).await;
    run(&srv.url, &dir, false).await.expect("enroll");
    let sent = srv.requests.lock().expect("lock");
    assert!(verify(&sent[0]), "proof must verify");
    assert_eq!(sent[0].hostname, "test-host");
    let mut tampered = sent[0].clone();
    tampered.ts += 1;
    assert!(!verify(&tampered), "tampered request must not verify");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn rejected_token_deletes_key_and_writes_nothing() {
    let dir = scratch("reject");
    let srv = serve(401).await;
    let err = run(&srv.url, &dir, false).await.expect_err("must fail");
    assert!(matches!(err, EnrollError::TokenRejected), "{err}");
    assert_eq!(err.to_string(), "enrollment token rejected");
    assert!(key_of(&dir).is_none());
    assert!(identity::load(&dir).expect("load").is_none());
    assert!(!dir.join("trust").join("manifest.env").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn token_never_persisted_or_reported() {
    let dir = scratch("token");
    let srv = serve(200).await;
    run(&srv.url, &dir, false).await.expect("enroll");
    let mut stack = vec![dir.clone()];
    while let Some(p) = stack.pop() {
        for entry in std::fs::read_dir(&p).expect("read_dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let data = std::fs::read(&path).expect("read");
            assert!(
                !String::from_utf8_lossy(&data).contains("SECRETTOKENVALUE"),
                "{} leaks the token",
                path.display()
            );
        }
    }
    // Error text must not echo the token either.
    let dir2 = scratch("token2");
    let rejected = serve(401).await;
    let err = run(&rejected.url, &dir2, false).await.expect_err("fails");
    assert!(!format!("{err} {err:?}").contains("SECRETTOKENVALUE"));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[tokio::test]
async fn already_enrolled_is_refused_without_force() {
    let dir = scratch("again");
    let srv = serve(200).await;
    run(&srv.url, &dir, false).await.expect("first");
    let key_before = key_of(&dir);
    let err = run(&srv.url, &dir, false).await.expect_err("second");
    assert!(matches!(err, EnrollError::AlreadyEnrolled), "{err}");
    assert_eq!(
        srv.requests.lock().expect("lock").len(),
        1,
        "no second request"
    );
    assert_eq!(key_of(&dir), key_before);

    // --force replaces the key.
    run(&srv.url, &dir, true).await.expect("forced");
    assert_eq!(srv.requests.lock().expect("lock").len(), 2);
    assert_ne!(key_of(&dir), key_before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn failed_force_restores_previous_key() {
    let dir = scratch("restore");
    let ok = serve(200).await;
    run(&ok.url, &dir, false).await.expect("first");
    let key_before = key_of(&dir);
    let bad = serve(401).await;
    let err = run(&bad.url, &dir, true).await.expect_err("rejected");
    assert!(matches!(err, EnrollError::TokenRejected));
    assert_eq!(key_of(&dir), key_before);
    assert!(identity::load(&dir).expect("load").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn unreachable_server_fails_after_retries_and_removes_key() {
    let dir = scratch("down");
    // Bind then drop to get a port nobody listens on.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        l.local_addr().expect("addr").port()
    };
    let err = run(&format!("http://127.0.0.1:{port}"), &dir, false)
        .await
        .expect_err("unreachable");
    assert!(matches!(err, EnrollError::Unreachable(_)), "{err}");
    assert!(key_of(&dir).is_none());
    assert!(identity::load(&dir).expect("load").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn plain_http_to_remote_host_is_refused() {
    let dir = scratch("http");
    let err = run("http://rmm.example.com", &dir, false)
        .await
        .expect_err("refused");
    assert!(matches!(err, EnrollError::BadUrl(_)), "{err}");
    assert!(key_of(&dir).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
