//! Co-signed shell sessions: the PTY pump with credit backpressure,
//! liveness, `max_duration`, the local indicator and technician lockout.
//!
//! Per session a blocking reader thread reads the PTY into a buffer of at
//! most `max_chunk` bytes and hands each read to the async pump over a
//! channel of capacity 1. The pump coalesces reads into chunks of at most
//! `max_chunk` bytes (or whatever arrived within `chunk_interval`), numbers
//! them and publishes `ShellOut::Data` only while the unacknowledged bytes
//! plus the next chunk fit in the window (at most `max_in_flight`). Out of
//! credit, it stops taking reads, so the reader thread blocks, the PTY buffer
//! fills and the OS blocks the child: memory stays bounded however much the
//! shell prints.
//!
//! A session ends with exactly one final message: `Exit{code}` when the child
//! exits (after all of its output was published), or `Closed{reason}` with
//! one of [`REASON_LIVENESS`], [`REASON_MAX_DURATION`],
//! [`REASON_CLOSED_BY_RELAY`], [`REASON_TECH_REMOVED`],
//! [`REASON_INPUT_OVERFLOW`] or [`REASON_LINK`]. Teardown always kills the
//! child.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rmm_platform::PlatformError;
use rmm_platform::indicator::{IndicatorServer, IndicatorState};
use rmm_platform::pty::{Pty, ShellKind};
use rmm_proto::shell::{
    Bytes as WireBytes, CHUNK_INTERVAL_MS, LIVENESS_SECS, MAX_CHUNK, MAX_IN_FLIGHT, ShellCtl,
    ShellIn, ShellOut,
};
use rmm_trust::docs::TechnicianList;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::shell_verify::{ShellReject, VerifiedGrant};

/// Most concurrent shell sessions per agent.
pub const MAX_SESSIONS: usize = 2;
/// Capacity of each inbound (`.in` / `.ctl`) message queue.
pub const INBOUND_QUEUE: usize = 64;
/// Keystroke messages queued for the PTY writer before the session is closed.
pub const INPUT_QUEUE: usize = 256;

/// No `Ping` within the liveness interval.
pub const REASON_LIVENESS: &str = "liveness";
/// The grant's `max_duration` elapsed.
pub const REASON_MAX_DURATION: &str = "max_duration";
/// The relay sent `Close`.
pub const REASON_CLOSED_BY_RELAY: &str = "closed_by_relay";
/// The technician or credential left the technician list.
pub const REASON_TECH_REMOVED: &str = "tech_removed";
/// Keystrokes arrived faster than the shell reads them; the session is
/// closed rather than dropping input (a truncated command line can be worse
/// than none).
pub const REASON_INPUT_OVERFLOW: &str = "input_overflow";
/// The transport failed or a subscription ended.
pub const REASON_LINK: &str = "link_closed";

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const EXIT_POLL: Duration = Duration::from_millis(100);
/// After the child exits, output is drained until the PTY is quiet this long.
const EXIT_DRAIN: Duration = Duration::from_millis(500);
const INITIAL_COLS: u16 = 80;
const INITIAL_ROWS: u16 = 24;
/// Far enough in the future to never fire.
const NEVER: Duration = Duration::from_secs(100 * 365 * 86_400);

/// Flow-control and timeout settings of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// Most unacknowledged output bytes in flight.
    pub max_in_flight: usize,
    /// Largest output chunk (and PTY read).
    pub max_chunk: usize,
    /// Longest time output is held back for coalescing.
    pub chunk_interval: Duration,
    /// Silence (no `Ping`) after which the session is closed.
    pub liveness: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_in_flight: MAX_IN_FLIGHT as usize,
            max_chunk: MAX_CHUNK,
            chunk_interval: Duration::from_millis(CHUNK_INTERVAL_MS),
            liveness: Duration::from_secs(LIVENESS_SECS),
        }
    }
}

impl SessionConfig {
    /// Clamp to values the wire format and the pump can honour.
    fn sanitized(mut self) -> Self {
        self.max_chunk = self.max_chunk.clamp(1, MAX_CHUNK);
        self.max_in_flight = self.max_in_flight.max(self.max_chunk);
        self
    }
}

/// A transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkError(pub String);

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shell link: {}", self.0)
    }
}

impl std::error::Error for LinkError {}

/// Boxed future returned by [`ShellLink`] methods.
pub type LinkFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, LinkError>> + Send + 'a>>;

/// Raw inbound messages (canonical CBOR) of one subject.
pub type Inbound = mpsc::Receiver<Vec<u8>>;

/// Transport of the shell subjects `shell.<agent>.<sid>.{out,in,ctl}`.
/// Dropping an [`Inbound`] ends its subscription.
pub trait ShellLink: Send + Sync {
    /// Publish one output message on `.out`.
    fn publish_out<'a>(
        &'a self,
        agent_id: &'a str,
        sid: &'a str,
        msg: ShellOut,
    ) -> LinkFuture<'a, ()>;
    /// Subscribe to `.in` (keystrokes, resizes).
    fn subscribe_in<'a>(&'a self, agent_id: &'a str, sid: &'a str) -> LinkFuture<'a, Inbound>;
    /// Subscribe to `.ctl` (acks, windows, pings, close).
    fn subscribe_ctl<'a>(&'a self, agent_id: &'a str, sid: &'a str) -> LinkFuture<'a, Inbound>;
}

/// The relay side of a [`MemoryLink`] session.
#[derive(Debug)]
pub struct RelayEnd {
    /// Everything the agent published on `.out`, in order.
    pub out: mpsc::UnboundedReceiver<ShellOut>,
    /// Send canonical `ShellIn` bytes.
    pub input: mpsc::Sender<Vec<u8>>,
    /// Send canonical `ShellCtl` bytes.
    pub ctl: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug)]
struct MemoryEnd {
    out_tx: mpsc::UnboundedSender<ShellOut>,
    out_rx: Option<mpsc::UnboundedReceiver<ShellOut>>,
    in_tx: mpsc::Sender<Vec<u8>>,
    in_rx: Option<Inbound>,
    ctl_tx: mpsc::Sender<Vec<u8>>,
    ctl_rx: Option<Inbound>,
}

impl MemoryEnd {
    fn new() -> Self {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
        let (ctl_tx, ctl_rx) = mpsc::channel(INBOUND_QUEUE);
        Self {
            out_tx,
            out_rx: Some(out_rx),
            in_tx,
            in_rx: Some(in_rx),
            ctl_tx,
            ctl_rx: Some(ctl_rx),
        }
    }
}

/// In-memory [`ShellLink`] for tests: one endpoint per session id, created by
/// whichever side touches it first. The `.out` queue is unbounded, but the
/// agent never has more than its window unacknowledged, so it stays small as
/// long as the relay reads it.
#[derive(Debug, Default)]
pub struct MemoryLink {
    ends: Mutex<BTreeMap<String, MemoryEnd>>,
}

impl MemoryLink {
    /// An empty link.
    pub fn new() -> Self {
        Self::default()
    }

    fn with_end<T>(&self, sid: &str, f: impl FnOnce(&mut MemoryEnd) -> T) -> T {
        let mut ends = lock(&self.ends);
        f(ends.entry(sid.to_owned()).or_insert_with(MemoryEnd::new))
    }

    /// The relay side of `sid`; `None` once taken.
    pub fn relay(&self, sid: &str) -> Option<RelayEnd> {
        self.with_end(sid, |e| {
            Some(RelayEnd {
                out: e.out_rx.take()?,
                input: e.in_tx.clone(),
                ctl: e.ctl_tx.clone(),
            })
        })
    }
}

impl ShellLink for MemoryLink {
    fn publish_out<'a>(
        &'a self,
        _agent_id: &'a str,
        sid: &'a str,
        msg: ShellOut,
    ) -> LinkFuture<'a, ()> {
        let r = self.with_end(sid, |e| e.out_tx.send(msg));
        Box::pin(async move { r.map_err(|_| LinkError("relay gone".into())) })
    }

    fn subscribe_in<'a>(&'a self, _agent_id: &'a str, sid: &'a str) -> LinkFuture<'a, Inbound> {
        let r = self.with_end(sid, |e| e.in_rx.take());
        Box::pin(async move { r.ok_or_else(|| LinkError("already subscribed".into())) })
    }

    fn subscribe_ctl<'a>(&'a self, _agent_id: &'a str, sid: &'a str) -> LinkFuture<'a, Inbound> {
        let r = self.with_end(sid, |e| e.ctl_rx.take());
        Box::pin(async move { r.ok_or_else(|| LinkError("already subscribed".into())) })
    }
}

/// Largest inbound `.in` / `.ctl` payload forwarded to a session. Valid
/// messages carry at most `MAX_CHUNK` data bytes plus a small CBOR header;
/// anything bigger is dropped before it is queued, so the inbound queues
/// stay bounded at `INBOUND_QUEUE * MAX_INBOUND` bytes.
pub const MAX_INBOUND: usize = MAX_CHUNK + 256;

/// Forward a core NATS subscription into an [`Inbound`] queue until either
/// side ends. Dropping the receiver drops the subscriber, which unsubscribes.
async fn nats_subscribe(client: &async_nats::Client, subject: String) -> Result<Inbound, LinkError> {
    use futures_util::StreamExt as _;

    let mut sub = client
        .subscribe(subject.clone())
        .await
        .map_err(|e| LinkError(format!("subscribe {subject}: {e}")))?;
    // Make sure the server has the subscription before the session reports
    // ready, so the relay's first messages are not lost.
    client
        .flush()
        .await
        .map_err(|e| LinkError(format!("flush {subject}: {e}")))?;
    let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
    tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                () = tx.closed() => break,
                m = sub.next() => match m {
                    Some(m) => m,
                    None => break,
                },
            };
            if msg.payload.len() > MAX_INBOUND {
                tracing::debug!(%subject, len = msg.payload.len(), "oversized shell message dropped");
                continue;
            }
            if tx.send(msg.payload.to_vec()).await.is_err() {
                break;
            }
        }
        // Dropping `sub` unsubscribes.
    });
    Ok(rx)
}

impl ShellLink for async_nats::Client {
    fn publish_out<'a>(
        &'a self,
        agent_id: &'a str,
        sid: &'a str,
        msg: ShellOut,
    ) -> LinkFuture<'a, ()> {
        Box::pin(async move {
            let bytes = msg
                .to_cbor()
                .map_err(|e| LinkError(format!("encode: {e}")))?;
            self.publish(rmm_proto::subjects::shell_out(agent_id, sid), bytes.into())
                .await
                .map_err(|e| LinkError(format!("publish: {e}")))
        })
    }

    fn subscribe_in<'a>(&'a self, agent_id: &'a str, sid: &'a str) -> LinkFuture<'a, Inbound> {
        Box::pin(nats_subscribe(self, rmm_proto::subjects::shell_in(agent_id, sid)))
    }

    fn subscribe_ctl<'a>(&'a self, agent_id: &'a str, sid: &'a str) -> LinkFuture<'a, Inbound> {
        Box::pin(nats_subscribe(self, rmm_proto::subjects::shell_ctl(agent_id, sid)))
    }
}

/// Receives the "IT is connected" state.
pub trait Indicator: Send + Sync {
    /// Show `state`.
    fn set(&self, state: IndicatorState);
}

impl Indicator for IndicatorServer {
    fn set(&self, state: IndicatorState) {
        IndicatorServer::set(self, state);
    }
}

/// Starts a shell in a new PTY (`cols`, `rows`).
pub type PtyFactory =
    Arc<dyn Fn(ShellKind, u16, u16) -> Result<Box<dyn Pty>, PlatformError> + Send + Sync>;

/// The real factory: [`rmm_platform::pty::spawn_shell`].
pub fn platform_pty_factory() -> PtyFactory {
    Arc::new(rmm_platform::pty::spawn_shell)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Slot {
    tech_id: String,
    cred_id: Vec<u8>,
    client_id: String,
    close: mpsc::Sender<&'static str>,
}

struct Inner {
    agent_id: String,
    link: Arc<dyn ShellLink>,
    indicator: Option<Arc<dyn Indicator>>,
    config: SessionConfig,
    factory: PtyFactory,
    rt: tokio::runtime::Handle,
    sessions: Mutex<BTreeMap<String, Slot>>,
}

impl Inner {
    /// Push the indicator state for `sessions` (called with the lock held so
    /// updates are applied in order).
    fn show(&self, sessions: &BTreeMap<String, Slot>) {
        let Some(ind) = &self.indicator else { return };
        let mut techs: Vec<&str> = sessions.values().map(|s| s.tech_id.as_str()).collect();
        techs.sort_unstable();
        techs.dedup();
        ind.set(if techs.is_empty() {
            IndicatorState::default()
        } else {
            IndicatorState {
                connected: true,
                tech: Some(techs.join(", ")),
            }
        });
    }

    fn remove(&self, sid: &str) {
        let mut s = lock(&self.sessions);
        s.remove(sid);
        self.show(&s);
    }
}

/// Runs the agent's shell sessions.
#[derive(Clone)]
pub struct ShellManager {
    inner: Arc<Inner>,
}

impl fmt::Debug for ShellManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShellManager")
            .field("agent_id", &self.inner.agent_id)
            .field("config", &self.inner.config)
            .field("active", &self.active())
            .finish_non_exhaustive()
    }
}

impl ShellManager {
    /// A manager spawning real shells. Must be called inside a tokio runtime;
    /// sessions run on that runtime.
    pub fn new(
        agent_id: impl Into<String>,
        link: Arc<dyn ShellLink>,
        indicator: Option<Arc<dyn Indicator>>,
        config: SessionConfig,
    ) -> Self {
        Self::with_pty_factory(agent_id, link, indicator, config, platform_pty_factory())
    }

    /// Like [`ShellManager::new`] with an explicit PTY factory (tests).
    pub fn with_pty_factory(
        agent_id: impl Into<String>,
        link: Arc<dyn ShellLink>,
        indicator: Option<Arc<dyn Indicator>>,
        config: SessionConfig,
        factory: PtyFactory,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                agent_id: agent_id.into(),
                link,
                indicator,
                config: config.sanitized(),
                factory,
                rt: tokio::runtime::Handle::current(),
                sessions: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Start a verified session. Blocks (at most a few seconds) until the
    /// session is subscribed to its input subjects, so call it from a
    /// blocking context, not from an async task.
    pub fn open(&self, v: VerifiedGrant) -> Result<(), ShellReject> {
        let sid = v.sid();
        let (close_tx, close_rx) = mpsc::channel(1);
        {
            let mut s = lock(&self.inner.sessions);
            if s.contains_key(&sid) {
                return Err(ShellReject::Replay);
            }
            if s.len() >= MAX_SESSIONS {
                tracing::warn!(%sid, "shell open rejected: session limit reached");
                return Err(ShellReject::TooManySessions);
            }
            s.insert(
                sid.clone(),
                Slot {
                    tech_id: v.tech_id.clone(),
                    cred_id: v.grant.cred_id.0.clone(),
                    client_id: v.grant.client_id.clone(),
                    close: close_tx,
                },
            );
        }
        let pty = match (self.inner.factory)(v.kind, INITIAL_COLS, INITIAL_ROWS) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(%sid, "shell spawn failed: {e}");
                self.inner.remove(&sid);
                return Err(ShellReject::SpawnFailed);
            }
        };
        self.inner.show(&lock(&self.inner.sessions));
        tracing::info!(
            %sid,
            tech = %v.tech_id,
            shell = %v.grant.shell,
            max_duration = v.grant.max_duration,
            "shell session started"
        );
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let inner = Arc::clone(&self.inner);
        self.inner
            .rt
            .spawn(run_session(inner, sid, v, pty, close_rx, ready_tx));
        // Wait until subscribed, so the relay's first messages are not lost.
        let _ = ready_rx.recv_timeout(READY_TIMEOUT);
        Ok(())
    }

    /// Close every session whose technician, credential or client scope is
    /// no longer in `list` (`Closed{reason: "tech_removed"}`).
    pub fn on_techlist(&self, list: &TechnicianList) {
        let s = lock(&self.inner.sessions);
        for (sid, slot) in s.iter() {
            let listed = list.tech(&slot.tech_id).is_some_and(|t| {
                t.in_scope(&slot.client_id) && t.creds.iter().any(|c| c.cred_id.0 == slot.cred_id)
            });
            if !listed {
                tracing::warn!(%sid, tech = %slot.tech_id, "technician removed; closing shell");
                let _ = slot.close.try_send(REASON_TECH_REMOVED);
            }
        }
    }

    /// Number of open sessions.
    pub fn active(&self) -> usize {
        lock(&self.inner.sessions).len()
    }
}

/// Output sequencing and credit accounting.
struct Pump<'a> {
    link: &'a dyn ShellLink,
    agent_id: &'a str,
    sid: &'a str,
    max_chunk: usize,
    max_in_flight: usize,
    window: usize,
    next_seq: u64,
    unacked: VecDeque<(u64, usize)>,
    unacked_bytes: usize,
    pending: Vec<u8>,
    pending_since: Option<Instant>,
}

impl Pump<'_> {
    /// Whether a further read of up to `max_chunk` bytes fits the window.
    fn can_take(&self) -> bool {
        self.unacked_bytes + self.pending.len() + self.max_chunk <= self.window
    }

    /// Whether the pending chunk may be published now.
    fn can_flush(&self) -> bool {
        !self.pending.is_empty() && self.unacked_bytes + self.pending.len() <= self.window
    }

    async fn publish(&self, msg: ShellOut) {
        if let Err(e) = self.link.publish_out(self.agent_id, self.sid, msg).await {
            tracing::debug!(sid = %self.sid, "{e}");
        }
    }

    async fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let data = std::mem::take(&mut self.pending);
        self.pending_since = None;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.unacked.push_back((seq, data.len()));
        self.unacked_bytes += data.len();
        self.publish(ShellOut::Data {
            seq,
            data: WireBytes(data),
        })
        .await;
    }

    /// Append one PTY read (at most `max_chunk` bytes); only called when
    /// [`Pump::can_take`] holds, so every flush here fits the window.
    async fn push(&mut self, chunk: Vec<u8>) {
        if self.pending.len() + chunk.len() > self.max_chunk {
            self.flush().await;
        }
        if self.pending.is_empty() {
            self.pending = chunk;
            self.pending_since = Some(Instant::now());
        } else {
            self.pending.extend_from_slice(&chunk);
        }
        if self.pending.len() >= self.max_chunk {
            self.flush().await;
        }
    }

    fn ack(&mut self, seq: u64) {
        while let Some(&(s, n)) = self.unacked.front() {
            if s > seq {
                break;
            }
            self.unacked.pop_front();
            self.unacked_bytes -= n;
        }
    }

    fn set_window(&mut self, bytes: u32) {
        self.window = usize::try_from(bytes)
            .unwrap_or(usize::MAX)
            .min(self.max_in_flight);
    }
}

enum End {
    Exit(i32),
    Closed(&'static str),
}

async fn run_session(
    inner: Arc<Inner>,
    sid: String,
    v: VerifiedGrant,
    pty: Box<dyn Pty>,
    close_rx: mpsc::Receiver<&'static str>,
    ready: std::sync::mpsc::SyncSender<()>,
) {
    let pty = Arc::new(Mutex::new(pty));
    let end = pump_session(&inner, &sid, &v, &pty, close_rx, ready).await;
    let last = match end {
        End::Exit(code) => ShellOut::Exit { code },
        End::Closed(reason) => ShellOut::Closed {
            reason: reason.to_owned(),
        },
    };
    if let Err(e) = inner.link.publish_out(&inner.agent_id, &sid, last).await {
        tracing::debug!(%sid, "{e}");
    }
    if let Err(e) = lock(&pty).kill() {
        tracing::debug!(%sid, "kill shell: {e}");
    }
    drop(pty);
    match end {
        End::Exit(code) => tracing::info!(%sid, tech = %v.tech_id, code, "shell session exited"),
        End::Closed(reason) => {
            tracing::info!(%sid, tech = %v.tech_id, reason, "shell session closed");
        }
    }
    inner.remove(&sid);
}

fn spawn_reader(
    mut reader: Box<dyn Read + Send>,
    max_chunk: usize,
    tx: mpsc::Sender<Vec<u8>>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("rmm-shell-reader".into())
        .spawn(move || {
            let mut buf = vec![0u8; max_chunk];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        })
        .map(drop)
}

fn spawn_writer(
    mut writer: Box<dyn Write + Send>,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("rmm-shell-writer".into())
        .spawn(move || {
            for data in rx {
                if writer
                    .write_all(&data)
                    .and_then(|()| writer.flush())
                    .is_err()
                {
                    break;
                }
            }
        })
        .map(drop)
}

async fn pump_session(
    inner: &Inner,
    sid: &str,
    v: &VerifiedGrant,
    pty: &Mutex<Box<dyn Pty>>,
    mut close_rx: mpsc::Receiver<&'static str>,
    ready: std::sync::mpsc::SyncSender<()>,
) -> End {
    let cfg = inner.config;
    let link = inner.link.as_ref();
    let subs = async {
        let ins = link.subscribe_in(&inner.agent_id, sid).await?;
        let ctl = link.subscribe_ctl(&inner.agent_id, sid).await?;
        Ok::<_, LinkError>((ins, ctl))
    }
    .await;
    let _ = ready.try_send(());
    let (mut ins, mut ctl) = match subs {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%sid, "{e}");
            return End::Closed(REASON_LINK);
        }
    };

    let (chunk_tx, mut chunk_rx) = mpsc::channel::<Vec<u8>>(1);
    let (input_tx, input_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(INPUT_QUEUE);
    let (reader, writer) = {
        let mut p = lock(pty);
        (p.reader(), p.writer())
    };
    if let Err(e) =
        spawn_reader(reader, cfg.max_chunk, chunk_tx).and_then(|()| spawn_writer(writer, input_rx))
    {
        tracing::error!(%sid, "shell threads: {e}");
        return End::Closed(REASON_LINK);
    }

    let mut pump = Pump {
        link,
        agent_id: &inner.agent_id,
        sid,
        max_chunk: cfg.max_chunk,
        max_in_flight: cfg.max_in_flight,
        window: cfg.max_in_flight,
        next_seq: 1,
        unacked: VecDeque::new(),
        unacked_bytes: 0,
        pending: Vec::new(),
        pending_since: None,
    };
    let start = Instant::now();
    let max_deadline = start + Duration::from_secs(u64::from(v.grant.max_duration));
    let mut live_deadline = start + cfg.liveness;
    let mut exit_poll = tokio::time::interval(EXIT_POLL);
    exit_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut exit_code: Option<i32> = None;
    let mut reader_done = false;
    let mut drain_deadline: Option<Instant> = None;
    let mut drained = false;
    let mut close_open = true;

    loop {
        if let Some(code) = exit_code
            && pump.pending.is_empty()
            && (reader_done || drained)
        {
            return End::Exit(code);
        }
        let can_take = !reader_done && pump.can_take();
        let flush_at = pump.pending_since.map(|t| t + cfg.chunk_interval);
        tokio::select! {
            biased;
            r = close_rx.recv(), if close_open => match r {
                Some(reason) => return End::Closed(reason),
                None => close_open = false,
            },
            () = tokio::time::sleep_until(max_deadline) => return End::Closed(REASON_MAX_DURATION),
            () = tokio::time::sleep_until(live_deadline) => return End::Closed(REASON_LIVENESS),
            m = ctl.recv() => match m.map(|b| ShellCtl::from_cbor(&b)) {
                None => return End::Closed(REASON_LINK),
                Some(Ok(ShellCtl::Ack { seq })) => pump.ack(seq),
                Some(Ok(ShellCtl::Window { bytes })) => pump.set_window(bytes),
                Some(Ok(ShellCtl::Ping)) => live_deadline = Instant::now() + cfg.liveness,
                Some(Ok(ShellCtl::Close)) => return End::Closed(REASON_CLOSED_BY_RELAY),
                Some(Err(e)) => tracing::debug!(%sid, "bad ctl message: {e}"),
            },
            m = ins.recv() => match m.map(|b| ShellIn::from_cbor(&b)) {
                None => return End::Closed(REASON_LINK),
                Some(Ok(ShellIn::Data { data })) => match input_tx.try_send(data.0) {
                    Ok(()) | Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                        return End::Closed(REASON_INPUT_OVERFLOW);
                    }
                },
                Some(Ok(ShellIn::Resize { cols, rows })) => {
                    if let Err(e) = lock(pty).resize(cols, rows) {
                        tracing::debug!(%sid, "resize: {e}");
                    }
                }
                Some(Err(e)) => tracing::debug!(%sid, "bad input message: {e}"),
            },
            c = chunk_rx.recv(), if can_take => match c {
                Some(chunk) => {
                    pump.push(chunk).await;
                    if exit_code.is_some() {
                        drain_deadline = Some(Instant::now() + EXIT_DRAIN);
                        drained = false;
                    }
                }
                None => reader_done = true,
            },
            () = tokio::time::sleep_until(flush_at.unwrap_or(start + NEVER)),
                if flush_at.is_some() && pump.can_flush() => pump.flush().await,
            _ = exit_poll.tick(), if exit_code.is_none() => {
                if let Ok(Some(code)) = lock(pty).try_wait() {
                    exit_code = Some(code);
                    drain_deadline = Some(Instant::now() + EXIT_DRAIN);
                }
            },
            () = tokio::time::sleep_until(drain_deadline.unwrap_or(start + NEVER)),
                if drain_deadline.is_some() && !drained && can_take => {
                drained = true;
                if pump.can_flush() {
                    pump.flush().await;
                }
            },
        }
    }
}
