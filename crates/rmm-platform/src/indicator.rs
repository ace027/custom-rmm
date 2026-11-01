//! Local "IT is connected" indicator.
//!
//! The agent runs an [`IndicatorServer`]; the user-session helper
//! (`rmm-session`) connects read-only and shows the state. Each state change
//! is one JSON line: `{"state":"connected"|"idle","tech":<string|null>}`.

use std::path::PathBuf;

use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::PlatformError;

/// Environment variable overriding the unix socket path.
pub const SOCKET_ENV: &str = "RMM_INDICATOR_SOCKET";
/// Default unix socket path.
pub const DEFAULT_SOCKET: &str = "/run/rmm/indicator.sock";
/// Windows named pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\rmm-session-indicator";

/// What the indicator shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndicatorState {
    /// A technician is connected.
    pub connected: bool,
    /// The technician's name, while connected.
    pub tech: Option<String>,
}

impl IndicatorState {
    /// The JSON line (with trailing newline) sent to clients.
    pub fn to_line(&self) -> String {
        let v = serde_json::json!({
            "state": if self.connected { "connected" } else { "idle" },
            "tech": self.tech,
        });
        format!("{v}\n")
    }
}

/// Broadcasts [`IndicatorState`] to local clients.
#[derive(Debug)]
pub struct IndicatorServer {
    tx: watch::Sender<IndicatorState>,
    task: tokio::task::JoinHandle<()>,
    path: Option<PathBuf>,
}

impl IndicatorServer {
    /// Start listening. `path` is the unix socket path (ignored on Windows);
    /// `None` uses [`SOCKET_ENV`] then [`DEFAULT_SOCKET`]. Must be called
    /// inside a tokio runtime.
    pub fn start(path: Option<PathBuf>) -> Result<Self, PlatformError> {
        let (tx, rx) = watch::channel(IndicatorState::default());
        let (task, path) = imp::listen(path, rx)?;
        Ok(Self { tx, task, path })
    }

    /// Record the latest state and send it to every client.
    pub fn set(&self, state: IndicatorState) {
        self.tx.send_replace(state);
    }

    /// The socket path in use (unix only).
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
}

impl Drop for IndicatorServer {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Send the current state, then every change, until the client goes away.
async fn serve_client<W>(mut w: W, mut rx: watch::Receiver<IndicatorState>)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        let line = rx.borrow_and_update().to_line();
        if w.write_all(line.as_bytes()).await.is_err() || w.flush().await.is_err() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    pub(super) fn listen(
        path: Option<PathBuf>,
        rx: watch::Receiver<IndicatorState>,
    ) -> Result<(tokio::task::JoinHandle<()>, Option<PathBuf>), PlatformError> {
        let path = path.unwrap_or_else(|| {
            std::env::var_os(SOCKET_ENV)
                .filter(|v| !v.is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
        });
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| PlatformError::Os(format!("create {}: {e}", dir.display())))?;
        }
        // A socket left over from a previous run would make bind fail.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(PlatformError::Os(format!(
                    "remove stale {}: {e}",
                    path.display()
                )));
            }
        }
        let listener = UnixListener::bind(&path)
            .map_err(|e| PlatformError::Os(format!("bind {}: {e}", path.display())))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| PlatformError::Os(format!("chmod {}: {e}", path.display())))?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                };
                let rx = rx.clone();
                tokio::spawn(async move {
                    let (mut r, w) = stream.into_split();
                    // Client input is ignored; reading only detects hang-up.
                    let hangup = async {
                        let mut buf = [0u8; 64];
                        while matches!(r.read(&mut buf).await, Ok(n) if n > 0) {}
                    };
                    tokio::select! {
                        () = serve_client(w, rx) => {}
                        () = hangup => {}
                    }
                });
            }
        });
        Ok((task, Some(path)))
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use ::windows::Win32::Foundation::{HLOCAL, LocalFree};
    use ::windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use ::windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use ::windows::core::w;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    /// SYSTEM full control, interactive users read.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is an immutable heap block owned by this value.
    unsafe impl Send for Descriptor {}

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptor...; freed once.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }

    fn descriptor() -> Result<Descriptor, PlatformError> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the SDDL literal is NUL-terminated and `sd` is a valid out pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w!("D:P(A;;GA;;;SY)(A;;GR;;;IU)"),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(|e| PlatformError::Os(format!("pipe security descriptor: {e}")))?;
        Ok(Descriptor(sd))
    }

    fn create(first: bool, sd: &Descriptor) -> std::io::Result<NamedPipeServer> {
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0.0,
            bInheritHandle: false.into(),
        };
        let mut opts = ServerOptions::new();
        opts.access_inbound(false)
            .access_outbound(true)
            .first_pipe_instance(first)
            .reject_remote_clients(true);
        // SAFETY: `attrs` points at a live descriptor kept alive by `sd`.
        unsafe {
            opts.create_with_security_attributes_raw(
                PIPE_NAME,
                std::ptr::addr_of_mut!(attrs).cast(),
            )
        }
    }

    pub(super) fn listen(
        _path: Option<PathBuf>,
        rx: watch::Receiver<IndicatorState>,
    ) -> Result<(tokio::task::JoinHandle<()>, Option<PathBuf>), PlatformError> {
        let sd = descriptor()?;
        let mut next = create(true, &sd).map_err(|e| PlatformError::Os(format!("pipe: {e}")))?;
        let task = tokio::spawn(async move {
            loop {
                if next.connect().await.is_err() {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    match create(false, &sd) {
                        Ok(n) => next = n,
                        Err(_) => return,
                    }
                    continue;
                }
                let Ok(fresh) = create(false, &sd) else {
                    return;
                };
                let client = std::mem::replace(&mut next, fresh);
                tokio::spawn(serve_client(client, rx.clone()));
            }
        });
        Ok((task, None))
    }
}
