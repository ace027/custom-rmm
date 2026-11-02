//! Session helper: shows the "IT is connected" indicator to the logged-in user.
//!
//! It connects read-only to the agent's indicator endpoint (unix socket or
//! Windows named pipe) and reads one JSON line per state change.

use std::time::Duration;

/// Seconds between connection attempts.
const RETRY: Duration = Duration::from_secs(5);

/// Indicator state parsed from one JSON line.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    connected: bool,
    tech: Option<String>,
}

#[cfg(any(windows, test))]
fn parse_line(line: &str) -> Option<State> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let connected = match v.get("state")?.as_str()? {
        "connected" => true,
        "idle" => false,
        _ => return None,
    };
    let tech = v.get("tech").and_then(|t| t.as_str()).map(str::to_owned);
    Some(State { connected, tech })
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("rmm-session {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    run();
}

#[cfg(unix)]
fn run() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let path = std::env::var_os("RMM_INDICATOR_SOCKET")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/run/rmm/indicator.sock".into());
    loop {
        if let Ok(stream) = UnixStream::connect(&path) {
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else { break };
                println!("indicator: {line}");
            }
        }
        std::thread::sleep(RETRY);
    }
}

#[cfg(windows)]
fn run() {
    tray::run();
}

#[cfg(windows)]
mod tray {
    use super::{RETRY, State, parse_line};
    use std::io::{BufRead, BufReader};
    use std::sync::Mutex;
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::UI::Shell::{
        NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
        Shell_NotifyIconW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, GetMessageW, IDI_APPLICATION, LoadIconW, MSG,
        PostMessageW, TranslateMessage, WINDOW_EX_STYLE, WM_APP, WS_OVERLAPPED,
    };
    use windows::core::{PCWSTR, w};

    const PIPE: &str = r"\\.\pipe\rmm-session-indicator";
    const WM_STATE: u32 = WM_APP + 1;
    const ICON_ID: u32 = 1;

    static LATEST: Mutex<Option<State>> = Mutex::new(None);

    fn tooltip(tech: Option<&str>) -> [u16; 128] {
        let text = format!("IT is connected: {}", tech.unwrap_or("technician"));
        let mut buf = [0u16; 128];
        for (slot, unit) in buf.iter_mut().take(127).zip(text.encode_utf16()) {
            *slot = unit;
        }
        buf
    }

    fn data(hwnd: HWND) -> NOTIFYICONDATAW {
        NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ICON_ID,
            ..Default::default()
        }
    }

    fn apply(hwnd: HWND, shown: &mut bool) {
        let state = LATEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match state {
            Some(State {
                connected: true,
                tech,
            }) => {
                let mut nid = data(hwnd);
                nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
                nid.uCallbackMessage = WM_APP;
                nid.szTip = tooltip(tech.as_deref());
                // SAFETY: plain system icon; `nid` is fully initialised and
                // outlives the calls.
                unsafe {
                    if let Ok(icon) = LoadIconW(None, IDI_APPLICATION) {
                        nid.hIcon = icon;
                    }
                    let op = if *shown { NIM_MODIFY } else { NIM_ADD };
                    if Shell_NotifyIconW(op, &nid).as_bool() {
                        *shown = true;
                    }
                }
            }
            _ => {
                if *shown {
                    let nid = data(hwnd);
                    // SAFETY: `nid` identifies the icon added above.
                    unsafe {
                        let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
                    }
                    *shown = false;
                }
            }
        }
    }

    fn reader(hwnd_raw: isize) {
        loop {
            if let Ok(pipe) = std::fs::File::open(PIPE) {
                for line in BufReader::new(pipe).lines() {
                    let Ok(line) = line else { break };
                    if let Some(state) = parse_line(&line) {
                        *LATEST
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(state);
                        // SAFETY: posting to a window owned by the main thread.
                        unsafe {
                            let _ = PostMessageW(
                                Some(HWND(hwnd_raw as *mut _)),
                                WM_STATE,
                                WPARAM(0),
                                LPARAM(0),
                            );
                        }
                    }
                }
            }
            std::thread::sleep(RETRY);
        }
    }

    pub fn run() {
        // SAFETY: the predefined STATIC class needs no registration; the
        // hidden window only owns the notification icon.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                PCWSTR::null(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                None,
                None,
                None,
                None,
            )
        };
        let Ok(hwnd) = hwnd else {
            eprintln!("rmm-session: cannot create window");
            return;
        };
        let raw = hwnd.0 as isize;
        std::thread::spawn(move || reader(raw));
        let mut shown = false;
        let mut msg = MSG::default();
        // SAFETY: standard message loop on the thread that created the window.
        unsafe {
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                if msg.message == WM_STATE {
                    apply(hwnd, &mut shown);
                    continue;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_state_lines() {
        assert_eq!(
            parse_line("{\"state\":\"connected\",\"tech\":\"alice\"}\n"),
            Some(State {
                connected: true,
                tech: Some("alice".into())
            })
        );
        assert_eq!(
            parse_line("{\"state\":\"idle\",\"tech\":null}"),
            Some(State {
                connected: false,
                tech: None
            })
        );
        assert_eq!(parse_line("junk"), None);
        assert_eq!(parse_line("{\"state\":\"x\"}"), None);
    }
}
