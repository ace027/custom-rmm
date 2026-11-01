//! Operating-system service control used by the `service.*` building blocks.
//!
//! Windows drives the Service Control Manager (see `windows.rs`). Linux and
//! macOS return [`PlatformError::Unsupported`] this phase. Debug builds also
//! have an in-memory implementation in [`crate::fake`].

use std::fmt;
use std::time::{Duration, Instant};

use crate::PlatformError;

/// Result alias of this module.
pub type Result<T> = std::result::Result<T, PlatformError>;

/// How often the default [`Services::wait`] polls.
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Coarse service state.
///
/// Paused services report [`ServiceState::Stopped`], pause-pending
/// [`ServiceState::StopPending`] and continue-pending
/// [`ServiceState::StartPending`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// The service is running.
    Running,
    /// The service is stopped.
    Stopped,
    /// The service is starting.
    StartPending,
    /// The service is stopping.
    StopPending,
    /// No service of that name exists.
    Missing,
}

impl ServiceState {
    /// Lowercase name used in recipes and results (`running`, `stopped`,
    /// `start_pending`, `stop_pending`, `missing`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::StartPending => "start_pending",
            Self::StopPending => "stop_pending",
            Self::Missing => "missing",
        }
    }

    /// Inverse of [`ServiceState::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Running,
            Self::Stopped,
            Self::StartPending,
            Self::StopPending,
            Self::Missing,
        ]
        .into_iter()
        .find(|st| st.as_str() == s)
    }
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Service control. All calls block the calling thread.
pub trait Services: fmt::Debug + Send + Sync {
    /// Current state; [`ServiceState::Missing`] when the service does not exist.
    fn query(&self, name: &str) -> Result<ServiceState>;

    /// Stop the service and wait until it is stopped. Stopping a stopped
    /// service succeeds. Not stopped within `timeout` is
    /// [`PlatformError::Timeout`].
    fn stop(&self, name: &str, timeout: Duration) -> Result<()>;

    /// Start the service and wait until it is running. Starting a running
    /// service succeeds. Not running within `timeout` is
    /// [`PlatformError::Timeout`].
    fn start(&self, name: &str, timeout: Duration) -> Result<()>;

    /// Wait until the service is in `want`, polling every [`POLL_INTERVAL`].
    fn wait(&self, name: &str, want: ServiceState, timeout: Duration) -> Result<()> {
        wait_until(self, name, want, timeout)
    }
}

/// Poll `svc.query(name)` until it reports `want` or `timeout` passes.
pub(crate) fn wait_until<S: Services + ?Sized>(
    svc: &S,
    name: &str,
    want: ServiceState,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = svc.query(name)?;
        if state == want {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(PlatformError::Timeout(format!(
                "service {name} is {state}, wanted {want} within {}s",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
}

/// Service control for platforms without an implementation yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unsupported;

fn unsupported<T>() -> Result<T> {
    Err(PlatformError::Unsupported(
        "service control is not implemented on this platform".into(),
    ))
}

impl Services for Unsupported {
    fn query(&self, _name: &str) -> Result<ServiceState> {
        unsupported()
    }

    fn stop(&self, _name: &str, _timeout: Duration) -> Result<()> {
        unsupported()
    }

    fn start(&self, _name: &str, _timeout: Duration) -> Result<()> {
        unsupported()
    }

    fn wait(&self, _name: &str, _want: ServiceState, _timeout: Duration) -> Result<()> {
        unsupported()
    }
}

/// The service controller of the current OS: the SCM on Windows,
/// [`Unsupported`] elsewhere.
pub fn services() -> Box<dyn Services> {
    #[cfg(windows)]
    {
        Box::new(crate::windows::ScmServices)
    }
    #[cfg(not(windows))]
    {
        Box::new(Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_names_round_trip() {
        for st in [
            ServiceState::Running,
            ServiceState::Stopped,
            ServiceState::StartPending,
            ServiceState::StopPending,
            ServiceState::Missing,
        ] {
            assert_eq!(ServiceState::parse(st.as_str()), Some(st));
        }
        assert_eq!(ServiceState::parse("Running"), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_off_windows() {
        let svc = services();
        assert!(matches!(
            svc.query("Spooler"),
            Err(PlatformError::Unsupported(_))
        ));
        assert!(svc.stop("Spooler", Duration::from_secs(1)).is_err());
        assert!(svc.start("Spooler", Duration::from_secs(1)).is_err());
    }
}
