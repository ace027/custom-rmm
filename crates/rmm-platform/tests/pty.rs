use rmm_platform::fake::FakePty;
use rmm_platform::pty::{Pty, ShellKind};
use std::io::{Read, Write};

#[test]
fn fake_pty_replays_and_records() {
    let mut p = FakePty::new(vec![b"ab".to_vec(), b"cd".to_vec()].into_iter());
    let mut out = Vec::new();
    p.reader().read_to_end(&mut out).expect("read");
    assert_eq!(out, b"abcd");
    p.writer().write_all(b"ls\n").expect("write");
    assert_eq!(p.input(), b"ls\n");
    p.resize(100, 30).expect("resize");
    assert_eq!(p.size(), (100, 30));
    assert_eq!(p.try_wait().expect("wait"), None);
    p.kill().expect("kill");
    assert!(p.try_wait().expect("wait").is_some());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rmm_platform::pty::spawn_shell;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn sh_runs_and_exits_with_code() {
        let mut pty = spawn_shell(ShellKind::Sh, 80, 24).expect("spawn");
        let mut reader = pty.reader();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut w = pty.writer();
        w.write_all(b"echo rmm-pty-$((40+2)); exit 3\n")
            .expect("write");
        w.flush().expect("flush");

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(100)) {
                seen.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&seen).contains("rmm-pty-42") {
                    break;
                }
            }
        }
        assert!(
            String::from_utf8_lossy(&seen).contains("rmm-pty-42"),
            "output: {:?}",
            String::from_utf8_lossy(&seen)
        );
        let mut code = None;
        while Instant::now() < deadline && code.is_none() {
            code = pty.try_wait().expect("try_wait");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(code, Some(3));
    }

    #[test]
    fn parse_rejects_non_allowlisted() {
        assert_eq!(ShellKind::parse("sh"), Some(ShellKind::Sh));
        assert_eq!(ShellKind::parse("bash"), None);
        assert_eq!(ShellKind::parse("../sh"), None);
        assert_eq!(ShellKind::parse("cmd"), None);
        assert_eq!(ShellKind::parse("powershell"), None);
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use rmm_platform::pty::spawn_shell;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn cmd_runs_and_exits_with_code() {
        assert_eq!(ShellKind::parse("sh"), None);
        let mut pty = spawn_shell(ShellKind::Cmd, 80, 24).expect("spawn");
        let mut reader = pty.reader();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut w = pty.writer();
        w.write_all(b"echo rmm-pty-ok & exit 3\r\n").expect("write");
        w.flush().expect("flush");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(100)) {
                seen.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&seen).contains("rmm-pty-ok") {
                    break;
                }
            }
        }
        assert!(String::from_utf8_lossy(&seen).contains("rmm-pty-ok"));
        let mut code = None;
        while Instant::now() < deadline && code.is_none() {
            code = pty.try_wait().expect("try_wait");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(code, Some(3));
    }
}
