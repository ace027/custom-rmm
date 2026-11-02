//! Pseudo-terminal shells (ConPTY on Windows, `openpty` on unix).
//!
//! Only allowlisted shells are spawned and never with caller-supplied
//! arguments.

use std::io::{Read, Write};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

use crate::PlatformError;

/// A running shell attached to a pseudo-terminal.
pub trait Pty: Send {
    /// A reader of the terminal output; each call returns a fresh clone.
    fn reader(&mut self) -> Box<dyn Read + Send>;
    /// The writer of terminal input. The same underlying writer is returned
    /// by every call.
    fn writer(&mut self) -> Box<dyn Write + Send>;
    /// Resize the terminal.
    fn resize(&self, cols: u16, rows: u16) -> Result<(), PlatformError>;
    /// Kill the shell.
    fn kill(&mut self) -> Result<(), PlatformError>;
    /// The exit code if the shell has exited.
    fn try_wait(&mut self) -> Result<Option<i32>, PlatformError>;
}

/// Shells that may be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    /// `cmd.exe` (Windows).
    Cmd,
    /// Windows PowerShell (Windows).
    PowerShell,
    /// `/bin/sh` (unix).
    Sh,
}

impl ShellKind {
    /// Parse a shell name; only names valid on this platform are accepted.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "cmd" if cfg!(windows) => Some(Self::Cmd),
            "powershell" if cfg!(windows) => Some(Self::PowerShell),
            "sh" if cfg!(unix) => Some(Self::Sh),
            _ => None,
        }
    }
}

fn os(what: &str, e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Os(format!("{what}: {e}"))
}

fn system_root() -> String {
    std::env::var("SystemRoot")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| r"C:\Windows".to_string())
}

fn command(kind: ShellKind) -> Result<CommandBuilder, PlatformError> {
    match kind {
        ShellKind::Cmd if cfg!(windows) => Ok(CommandBuilder::new(format!(
            r"{}\System32\cmd.exe",
            system_root()
        ))),
        ShellKind::PowerShell if cfg!(windows) => {
            let mut c = CommandBuilder::new(format!(
                r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
                system_root()
            ));
            c.arg("-NoLogo");
            Ok(c)
        }
        ShellKind::Sh if cfg!(unix) => Ok(CommandBuilder::new("/bin/sh")),
        _ => Err(PlatformError::Unsupported(format!(
            "shell {kind:?} is not available on this platform"
        ))),
    }
}

struct NativePty {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    writer: Option<std::sync::Arc<std::sync::Mutex<Box<dyn Write + Send>>>>,
}

impl std::fmt::Debug for NativePty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativePty")
    }
}

struct SharedWriter(std::sync::Arc<std::sync::Mutex<Box<dyn Write + Send>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .flush()
    }
}

impl Pty for NativePty {
    fn reader(&mut self) -> Box<dyn Read + Send> {
        match self.master.try_clone_reader() {
            Ok(r) => r,
            Err(_) => Box::new(std::io::empty()),
        }
    }

    fn writer(&mut self) -> Box<dyn Write + Send> {
        if self.writer.is_none() {
            let w: Box<dyn Write + Send> = match self.master.take_writer() {
                Ok(w) => w,
                Err(_) => Box::new(std::io::sink()),
            };
            self.writer = Some(std::sync::Arc::new(std::sync::Mutex::new(w)));
        }
        match &self.writer {
            Some(w) => Box::new(SharedWriter(w.clone())),
            None => Box::new(std::io::sink()),
        }
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<(), PlatformError> {
        self.master
            .resize(size(cols, rows))
            .map_err(|e| os("resize pty", e))
    }

    fn kill(&mut self) -> Result<(), PlatformError> {
        self.child.kill().map_err(|e| os("kill shell", e))
    }

    fn try_wait(&mut self) -> Result<Option<i32>, PlatformError> {
        let status = self.child.try_wait().map_err(|e| os("wait for shell", e))?;
        Ok(status.map(|s| i32::try_from(s.exit_code()).unwrap_or(i32::MAX)))
    }
}

fn size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// Start an allowlisted shell in a new pseudo-terminal.
pub fn spawn_shell(kind: ShellKind, cols: u16, rows: u16) -> Result<Box<dyn Pty>, PlatformError> {
    let cmd = command(kind)?;
    let pair = native_pty_system()
        .openpty(size(cols, rows))
        .map_err(|e| os("open pty", e))?;
    let child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| os("spawn shell", e))?;
    drop(pair.slave);
    Ok(Box::new(NativePty {
        master: pair.master,
        child,
        writer: None,
    }))
}
