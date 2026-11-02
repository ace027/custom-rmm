//! In-memory test platform (debug builds only).
//!
//! [`FakeServices`] stands in for the Windows SCM in CI: it starts with
//! `Spooler` running and changes state only when told to, so waits never
//! block. Service names are case-insensitive, as on Windows.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::PlatformError;
use crate::pty::Pty;
use crate::services::{Result, ServiceState, Services};

/// Environment variable naming a service whose start leaves it stopped.
pub const FAIL_START_ENV: &str = "RMM_AGENT_FAKE_FAIL_START";

/// In-memory service table.
#[derive(Debug)]
pub struct FakeServices {
    states: Mutex<BTreeMap<String, ServiceState>>,
    fail_start: Option<String>,
    calls: Mutex<Vec<String>>,
}

fn key(name: &str) -> String {
    name.to_ascii_lowercase()
}

impl Default for FakeServices {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeServices {
    /// A table holding only `Spooler`, running.
    pub fn new() -> Self {
        Self::with_services(&[("Spooler", ServiceState::Running)])
    }

    /// A table holding exactly `services`.
    pub fn with_services(services: &[(&str, ServiceState)]) -> Self {
        Self {
            states: Mutex::new(services.iter().map(|(n, s)| (key(n), *s)).collect()),
            fail_start: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// [`FakeServices::new`] honouring [`FAIL_START_ENV`].
    pub fn from_env() -> Self {
        let mut f = Self::new();
        f.fail_start = std::env::var(FAIL_START_ENV)
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| key(&v));
        f
    }

    /// Make `start` of `name` report success but leave the service stopped,
    /// like a service that exits right after starting.
    #[must_use]
    pub fn fail_start(mut self, name: &str) -> Self {
        self.fail_start = Some(key(name));
        self
    }

    /// Set a service's state (creating it).
    pub fn set(&self, name: &str, state: ServiceState) {
        lock(&self.states).insert(key(name), state);
    }

    /// Every mutating call so far, e.g. `stop spooler`.
    pub fn calls(&self) -> Vec<String> {
        lock(&self.calls).clone()
    }

    fn record(&self, what: &str, name: &str) {
        lock(&self.calls).push(format!("{what} {}", key(name)));
    }

    fn existing(&self, name: &str) -> Result<()> {
        if lock(&self.states).contains_key(&key(name)) {
            Ok(())
        } else {
            Err(PlatformError::Os(format!("service {name} does not exist")))
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Services for FakeServices {
    fn query(&self, name: &str) -> Result<ServiceState> {
        Ok(lock(&self.states)
            .get(&key(name))
            .copied()
            .unwrap_or(ServiceState::Missing))
    }

    fn stop(&self, name: &str, _timeout: Duration) -> Result<()> {
        self.existing(name)?;
        self.record("stop", name);
        self.set(name, ServiceState::Stopped);
        Ok(())
    }

    fn start(&self, name: &str, _timeout: Duration) -> Result<()> {
        self.existing(name)?;
        self.record("start", name);
        if self.fail_start.as_deref() == Some(key(name).as_str()) {
            self.set(name, ServiceState::Stopped);
        } else {
            self.set(name, ServiceState::Running);
        }
        Ok(())
    }

    /// Nothing changes on its own, so a wrong state is a timeout at once.
    fn wait(&self, name: &str, want: ServiceState, timeout: Duration) -> Result<()> {
        let state = self.query(name)?;
        if state == want {
            Ok(())
        } else {
            Err(PlatformError::Timeout(format!(
                "service {name} is {state}, wanted {want} within {}s",
                timeout.as_secs()
            )))
        }
    }
}

/// In-memory [`Pty`]: replays scripted output and records written input.
#[derive(Debug, Clone)]
pub struct FakePty {
    output: Arc<Mutex<VecDeque<Vec<u8>>>>,
    input: Arc<Mutex<Vec<u8>>>,
    exit: Arc<Mutex<Option<i32>>>,
    size: Arc<Mutex<(u16, u16)>>,
    killed: Arc<Mutex<bool>>,
}

impl FakePty {
    /// A pty whose reader yields each item of `output` in turn, then EOF.
    pub fn new(output: impl Iterator<Item = Vec<u8>>) -> Self {
        Self {
            output: Arc::new(Mutex::new(output.collect())),
            input: Arc::new(Mutex::new(Vec::new())),
            exit: Arc::new(Mutex::new(None)),
            size: Arc::new(Mutex::new((80, 24))),
            killed: Arc::new(Mutex::new(false)),
        }
    }

    /// Make `try_wait` report this exit code.
    pub fn set_exit(&self, code: i32) {
        *lock(&self.exit) = Some(code);
    }

    /// Everything written to the pty so far.
    pub fn input(&self) -> Vec<u8> {
        lock(&self.input).clone()
    }

    /// The last size set by `resize` (`cols`, `rows`).
    pub fn size(&self) -> (u16, u16) {
        *lock(&self.size)
    }

    /// Whether `kill` was called.
    pub fn killed(&self) -> bool {
        *lock(&self.killed)
    }
}

struct FakeReader {
    output: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pending: Vec<u8>,
}

impl Read for FakeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pending.is_empty() {
            match lock(&self.output).pop_front() {
                Some(chunk) => self.pending = chunk,
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

struct FakeWriter(Arc<Mutex<Vec<u8>>>);

impl Write for FakeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Pty for FakePty {
    fn reader(&mut self) -> Box<dyn Read + Send> {
        Box::new(FakeReader {
            output: self.output.clone(),
            pending: Vec::new(),
        })
    }

    fn writer(&mut self) -> Box<dyn Write + Send> {
        Box::new(FakeWriter(self.input.clone()))
    }

    fn resize(&self, cols: u16, rows: u16) -> std::result::Result<(), PlatformError> {
        *lock(&self.size) = (cols, rows);
        Ok(())
    }

    fn kill(&mut self) -> std::result::Result<(), PlatformError> {
        *lock(&self.killed) = true;
        let mut exit = lock(&self.exit);
        if exit.is_none() {
            *exit = Some(137);
        }
        Ok(())
    }

    fn try_wait(&mut self) -> std::result::Result<Option<i32>, PlatformError> {
        Ok(*lock(&self.exit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(1);

    #[test]
    fn spooler_starts_running_and_stops() {
        let f = FakeServices::new();
        assert_eq!(f.query("spooler").expect("q"), ServiceState::Running);
        f.stop("Spooler", T).expect("stop");
        assert_eq!(f.query("Spooler").expect("q"), ServiceState::Stopped);
        f.stop("Spooler", T)
            .expect("stopping a stopped service is fine");
        f.start("Spooler", T).expect("start");
        assert_eq!(f.query("Spooler").expect("q"), ServiceState::Running);
        f.wait("Spooler", ServiceState::Running, T).expect("wait");
        assert_eq!(f.calls(), ["stop spooler", "stop spooler", "start spooler"]);
    }

    #[test]
    fn missing_service() {
        let f = FakeServices::new();
        assert_eq!(f.query("Nope").expect("q"), ServiceState::Missing);
        assert!(f.stop("Nope", T).is_err());
        assert!(f.start("Nope", T).is_err());
    }

    #[test]
    fn fail_start_leaves_it_stopped() {
        let f = FakeServices::new().fail_start("SPOOLER");
        f.stop("Spooler", T).expect("stop");
        f.start("Spooler", T).expect("start reports success");
        assert_eq!(f.query("Spooler").expect("q"), ServiceState::Stopped);
        assert!(matches!(
            f.wait("Spooler", ServiceState::Running, T),
            Err(PlatformError::Timeout(_))
        ));
    }
}
