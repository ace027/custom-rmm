#![cfg(unix)]

use rmm_platform::indicator::{IndicatorServer, IndicatorState};
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

async fn line(r: &mut BufReader<UnixStream>) -> String {
    let mut s = String::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), r.read_line(&mut s))
        .await
        .expect("timeout")
        .expect("read");
    s
}

fn temp_sock(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rmm-ind-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).expect("dir");
    d.join("i.sock")
}

#[tokio::test]
async fn broadcasts_latest_state() {
    let path = temp_sock("a");
    let server = IndicatorServer::start(Some(path.clone())).expect("start");
    assert_eq!(
        std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
        0o644
    );

    let mut c1 = BufReader::new(UnixStream::connect(&path).await.expect("c1"));
    assert_eq!(line(&mut c1).await, "{\"state\":\"idle\",\"tech\":null}\n");

    server.set(IndicatorState {
        connected: true,
        tech: Some("alice".into()),
    });
    let connected = "{\"state\":\"connected\",\"tech\":\"alice\"}\n";
    assert_eq!(line(&mut c1).await, connected);

    let mut c2 = BufReader::new(UnixStream::connect(&path).await.expect("c2"));
    assert_eq!(line(&mut c2).await, connected);

    server.set(IndicatorState::default());
    let idle = "{\"state\":\"idle\",\"tech\":null}\n";
    assert_eq!(line(&mut c1).await, idle);
    assert_eq!(line(&mut c2).await, idle);
}

#[tokio::test]
async fn stale_socket_and_dropped_client() {
    let path = temp_sock("b");
    std::fs::write(&path, b"stale").expect("stale file");
    let server = IndicatorServer::start(Some(path.clone())).expect("start over stale");

    let dead = UnixStream::connect(&path).await.expect("dead");
    drop(dead);
    let mut live = BufReader::new(UnixStream::connect(&path).await.expect("live"));
    let _ = line(&mut live).await;
    for i in 0..5 {
        server.set(IndicatorState {
            connected: true,
            tech: Some(format!("t{i}")),
        });
    }
    server.set(IndicatorState {
        connected: true,
        tech: Some("last".into()),
    });
    let mut got = line(&mut live).await;
    while !got.contains("last") {
        got = line(&mut live).await;
    }
}
