//! Shell session pump: credit backpressure with bounded memory, liveness,
//! max_duration, input, exit, relay close, technician removal, the session
//! limit and the indicator. Uses the in-memory link and a scripted PTY
//! (`FakePty` is debug-only; this test also runs with `--release`).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use rmm_agent_core::shell::{
    Indicator, MemoryLink, PtyFactory, REASON_CLOSED_BY_RELAY, REASON_LIVENESS,
    REASON_MAX_DURATION, REASON_TECH_REMOVED, RelayEnd, SessionConfig, ShellManager,
};
use rmm_agent_core::shell_verify::{ShellReject, VerifiedGrant};
use rmm_platform::PlatformError;
use rmm_platform::indicator::IndicatorState;
use rmm_platform::pty::{Pty, ShellKind};
use rmm_proto::shell::{MAX_CHUNK, ShellCtl, ShellIn, ShellOut};
use rmm_trust::docs::{Credential, ShellGrant, Technician, TechnicianList};
use rmm_trust::keys::Bytes;
use tokio::time::{Instant, timeout};

const AGENT: &str = "agent_0000000000000001";
const CLIENT: &str = "client_0000000000000001";

#[derive(Debug, Default)]
struct PtyState {
    out: VecDeque<Vec<u8>>,
    /// Pattern bytes still to generate (no allocation up front).
    generate: u64,
    produced: u64,
    eof: bool,
    killed: bool,
    exit: Option<i32>,
    input: Vec<u8>,
    size: (u16, u16),
}

/// Scripted PTY whose reader blocks until output is available, like a real
/// terminal, and returns EOF once the child is gone.
#[derive(Debug, Clone, Default)]
struct TestPty(Arc<(Mutex<PtyState>, Condvar)>);

impl TestPty {
    fn state(&self) -> MutexGuard<'_, PtyState> {
        self.0
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn update(&self, f: impl FnOnce(&mut PtyState)) {
        f(&mut self.state());
        self.0.1.notify_all();
    }
    fn generating(n: u64) -> Self {
        let p = Self::default();
        p.update(|s| s.generate = n);
        p
    }
    fn output(&self, chunk: &[u8]) {
        self.update(|s| s.out.push_back(chunk.to_vec()));
    }
    /// The child exits with `code` after its queued output.
    fn exit(&self, code: i32) {
        self.update(|s| {
            s.exit = Some(code);
            s.eof = true;
        });
    }
    fn produced(&self) -> u64 {
        self.state().produced
    }
    fn killed(&self) -> bool {
        self.state().killed
    }
    fn input(&self) -> Vec<u8> {
        self.state().input.clone()
    }
    fn size(&self) -> (u16, u16) {
        self.state().size
    }
}

struct TestReader(TestPty);

impl Read for TestReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (lock, cv) = &*self.0.0;
        let mut s = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if s.generate > 0 {
                let n = buf
                    .len()
                    .min(usize::try_from(s.generate).unwrap_or(usize::MAX));
                buf[..n].fill(b'x');
                s.generate -= n as u64;
                s.produced += n as u64;
                return Ok(n);
            }
            if let Some(mut chunk) = s.out.pop_front() {
                let n = buf.len().min(chunk.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                if n < chunk.len() {
                    s.out.push_front(chunk.split_off(n));
                }
                s.produced += n as u64;
                return Ok(n);
            }
            if s.eof || s.killed {
                return Ok(0);
            }
            s = cv
                .wait(s)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

struct TestWriter(TestPty);

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(|s| s.input.extend_from_slice(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Pty for TestPty {
    fn reader(&mut self) -> Box<dyn Read + Send> {
        Box::new(TestReader(self.clone()))
    }
    fn writer(&mut self) -> Box<dyn Write + Send> {
        Box::new(TestWriter(self.clone()))
    }
    fn resize(&self, cols: u16, rows: u16) -> Result<(), PlatformError> {
        self.update(|s| s.size = (cols, rows));
        Ok(())
    }
    fn kill(&mut self) -> Result<(), PlatformError> {
        self.update(|s| {
            s.killed = true;
            s.exit.get_or_insert(137);
        });
        Ok(())
    }
    fn try_wait(&mut self) -> Result<Option<i32>, PlatformError> {
        Ok(self.state().exit)
    }
}

/// Hands out the queued PTYs in order.
fn factory(ptys: Vec<TestPty>) -> PtyFactory {
    let q = Mutex::new(VecDeque::from(ptys));
    Arc::new(move |_, _, _| {
        q.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .map(|p| Box::new(p) as Box<dyn Pty>)
            .ok_or_else(|| PlatformError::Os("no test pty left".into()))
    })
}

#[derive(Debug, Default)]
struct RecordingIndicator(Mutex<Vec<IndicatorState>>);

impl RecordingIndicator {
    fn states(&self) -> Vec<IndicatorState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Indicator for RecordingIndicator {
    fn set(&self, state: IndicatorState) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(state);
    }
}

fn grant(n: u8, tech: &str, max_duration: u32) -> VerifiedGrant {
    VerifiedGrant {
        grant: ShellGrant {
            grant_id: Bytes(vec![n; 16]),
            agent_id: AGENT.into(),
            client_id: CLIENT.into(),
            tech_id: tech.into(),
            cred_id: Bytes(vec![0xA1; 16]),
            issued_at: 1,
            open_by: 2,
            max_duration,
            shell: "sh".into(),
            record: true,
            e2e_pubkey: None,
        },
        tech_id: tech.into(),
        kind: ShellKind::Sh,
    }
}

struct Harness {
    link: Arc<MemoryLink>,
    manager: ShellManager,
    indicator: Arc<RecordingIndicator>,
}

fn harness(ptys: Vec<TestPty>, config: SessionConfig) -> Harness {
    let link = Arc::new(MemoryLink::new());
    let indicator = Arc::new(RecordingIndicator::default());
    let manager = ShellManager::with_pty_factory(
        AGENT,
        link.clone(),
        Some(indicator.clone()),
        config,
        factory(ptys),
    );
    Harness {
        link,
        manager,
        indicator,
    }
}

impl Harness {
    async fn open(&self, v: VerifiedGrant) -> Result<RelayEnd, ShellReject> {
        let sid = v.sid();
        let m = self.manager.clone();
        tokio::task::spawn_blocking(move || m.open(v))
            .await
            .expect("open task")?;
        Ok(self.link.relay(&sid).expect("relay end"))
    }
}

async fn ctl(relay: &RelayEnd, msg: ShellCtl) {
    relay
        .ctl
        .send(msg.to_cbor().expect("encode"))
        .await
        .expect("send ctl");
}

/// Read messages until the final `Exit`/`Closed`, acking all data at once.
async fn finish(relay: &mut RelayEnd, within: Duration) -> (Vec<u8>, ShellOut) {
    let mut data = Vec::new();
    let deadline = Instant::now() + within;
    loop {
        let msg = timeout(deadline - Instant::now(), relay.out.recv())
            .await
            .expect("session did not end in time")
            .expect("out closed");
        match msg {
            ShellOut::Data { seq, data: d } => {
                data.extend_from_slice(&d.0);
                let _ = relay
                    .ctl
                    .send(ShellCtl::Ack { seq }.to_cbor().expect("ack"))
                    .await;
            }
            last => return (data, last),
        }
    }
}

fn closed(reason: &str) -> ShellOut {
    ShellOut::Closed {
        reason: reason.into(),
    }
}

async fn wait_idle(m: &ShellManager) {
    for _ in 0..200 {
        if m.active() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("sessions still active");
}

/// Peak resident set (VmHWM) in bytes; Linux only.
fn peak_rss() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_output_is_bounded_by_credit_and_memory() {
    // The full GiB runs in the release verification; debug builds use less.
    let total: u64 = if cfg!(debug_assertions) {
        64 << 20
    } else {
        1 << 30
    };
    let cfg = SessionConfig::default();
    let pty = TestPty::generating(total);
    let h = harness(vec![pty.clone()], cfg);
    let rss_before = peak_rss();
    let mut relay = h.open(grant(1, "tech_alice", 3600)).await.expect("open");

    let mut received: u64 = 0;
    let mut last_seq = 0u64;
    let mut acked_seq = 0u64;
    let mut sizes: VecDeque<(u64, u64)> = VecDeque::new();
    let mut unacked: u64 = 0;
    let mut max_unacked: u64 = 0;
    let mut max_reader_lead: u64 = 0;
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    let mut ticks: u64 = 0;
    let deadline = Instant::now() + Duration::from_secs(240);
    while received < total {
        assert!(
            Instant::now() < deadline,
            "transfer too slow: {received} bytes"
        );
        tokio::select! {
            m = relay.out.recv() => match m.expect("out") {
                ShellOut::Data { seq, data } => {
                    assert_eq!(seq, last_seq + 1, "sequence gap");
                    assert!(data.0.len() <= MAX_CHUNK);
                    last_seq = seq;
                    let n = data.0.len() as u64;
                    received += n;
                    unacked += n;
                    sizes.push_back((seq, n));
                    max_unacked = max_unacked.max(unacked);
                    max_reader_lead = max_reader_lead.max(pty.produced() - received);
                }
                other => panic!("unexpected {other:?} after {received} bytes"),
            },
            _ = tick.tick() => {
                // A slow relay: ack once per tick, and stall now and then.
                ticks += 1;
                if ticks.is_multiple_of(500) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    ctl(&relay, ShellCtl::Ping).await;
                }
                if last_seq > acked_seq {
                    acked_seq = last_seq;
                    while let Some(&(s, n)) = sizes.front() {
                        if s > acked_seq { break; }
                        sizes.pop_front();
                        unacked -= n;
                    }
                    ctl(&relay, ShellCtl::Ack { seq: acked_seq }).await;
                }
            }
        }
    }
    assert_eq!(received, total);
    assert!(
        max_unacked <= cfg.max_in_flight as u64,
        "unacked {max_unacked} exceeds {}",
        cfg.max_in_flight
    );
    // The reader is held back: it is never ahead of what the relay has read
    // by more than the window (published, still queued) plus a few chunks
    // (reader buffer, channel slot, coalescing buffer).
    assert!(
        max_reader_lead <= (cfg.max_in_flight + 4 * MAX_CHUNK) as u64,
        "reader ran {max_reader_lead} bytes ahead"
    );
    if let (Some(before), Some(after)) = (rss_before, peak_rss()) {
        let growth = after.saturating_sub(before);
        println!("peak RSS growth {} KiB over {total} bytes", growth / 1024);
        assert!(growth < 50 << 20, "peak RSS grew {growth} bytes");
    }
    println!("max unacked {max_unacked} bytes, reader lead {max_reader_lead} bytes");

    pty.exit(0);
    let (_, last) = finish(&mut relay, Duration::from_secs(5)).await;
    assert_eq!(last, ShellOut::Exit { code: 0 });
    wait_idle(&h.manager).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn liveness_timeout_closes() {
    let cfg = SessionConfig {
        liveness: Duration::from_secs(1),
        ..SessionConfig::default()
    };
    let pty = TestPty::default();
    let h = harness(vec![pty.clone()], cfg);
    let started = Instant::now();
    let mut relay = h.open(grant(2, "tech_alice", 3600)).await.expect("open");
    let (_, last) = finish(&mut relay, Duration::from_secs(5)).await;
    assert_eq!(last, closed(REASON_LIVENESS));
    assert!(started.elapsed() >= Duration::from_millis(900));
    wait_idle(&h.manager).await;
    assert!(pty.killed(), "child must be killed on teardown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pings_keep_alive_until_max_duration() {
    let cfg = SessionConfig {
        liveness: Duration::from_secs(1),
        ..SessionConfig::default()
    };
    let pty = TestPty::default();
    let h = harness(vec![pty.clone()], cfg);
    let started = Instant::now();
    let mut relay = h.open(grant(3, "tech_alice", 2)).await.expect("open");
    let pinger = {
        let ctl_tx = relay.ctl.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if ctl_tx
                    .send(ShellCtl::Ping.to_cbor().expect("ping"))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        })
    };
    let (_, last) = finish(&mut relay, Duration::from_secs(6)).await;
    pinger.abort();
    assert_eq!(last, closed(REASON_MAX_DURATION));
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(1900), "closed after {took:?}");
    wait_idle(&h.manager).await;
    assert!(pty.killed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_and_resize_reach_the_pty_and_output_comes_back() {
    let pty = TestPty::default();
    let h = harness(vec![pty.clone()], SessionConfig::default());
    let mut relay = h.open(grant(4, "tech_alice", 3600)).await.expect("open");
    let send_in = |m: ShellIn| m.to_cbor().expect("encode");
    relay
        .input
        .send(send_in(ShellIn::Data {
            data: rmm_proto::shell::Bytes(b"echo hi\n".to_vec()),
        }))
        .await
        .expect("send");
    relay
        .input
        .send(send_in(ShellIn::Resize {
            cols: 132,
            rows: 43,
        }))
        .await
        .expect("send");
    for _ in 0..200 {
        if pty.input() == b"echo hi\n" && pty.size() == (132, 43) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(pty.input(), b"echo hi\n");
    assert_eq!(pty.size(), (132, 43));

    // Small writes within chunk_interval are coalesced into one chunk.
    pty.output(b"h");
    pty.output(b"i\r\n");
    let msg = timeout(Duration::from_secs(2), relay.out.recv())
        .await
        .expect("output")
        .expect("open");
    let ShellOut::Data { seq, data } = msg else {
        panic!("expected data, got {msg:?}");
    };
    assert_eq!(seq, 1);
    assert_eq!(data.0, b"hi\r\n");

    ctl(&relay, ShellCtl::Close).await;
    let (_, last) = finish(&mut relay, Duration::from_secs(2)).await;
    assert_eq!(last, closed(REASON_CLOSED_BY_RELAY));
    wait_idle(&h.manager).await;
    assert!(pty.killed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_waits_for_unacked_output() {
    // More output than the window, then the child exits: everything is
    // delivered once the slow relay acks, and Exit comes last.
    let total = 600 * 1024;
    let pty = TestPty::default();
    pty.output(&vec![b'y'; total]);
    pty.exit(7);
    let h = harness(vec![pty.clone()], SessionConfig::default());
    let mut relay = h.open(grant(5, "tech_alice", 3600)).await.expect("open");
    let mut got = 0usize;
    let mut last_seq = 0;
    // Do not ack for a while: the agent must stop at the window.
    let stalled = Instant::now() + Duration::from_millis(400);
    while let Ok(Some(m)) = timeout(stalled - Instant::now(), relay.out.recv()).await {
        match m {
            ShellOut::Data { seq, data } => {
                got += data.0.len();
                last_seq = seq;
            }
            other => panic!("final message {other:?} before output was acked"),
        }
    }
    assert!(got <= 262_144, "sent {got} bytes without acks");
    ctl(&relay, ShellCtl::Ack { seq: last_seq }).await;
    let (rest, last) = finish(&mut relay, Duration::from_secs(5)).await;
    assert_eq!(got + rest.len(), total);
    assert_eq!(last, ShellOut::Exit { code: 7 });
    wait_idle(&h.manager).await;
}

fn techlist(techs: Vec<Technician>) -> TechnicianList {
    TechnicianList {
        seq: 2,
        issued_at: 1,
        expires_at: 2,
        techs,
    }
}

fn technician(id: &str, cred: u8) -> Technician {
    Technician {
        tech_id: id.into(),
        client_scope: vec![CLIENT.into()],
        perms: vec![],
        creds: vec![Credential {
            cred_id: Bytes(vec![cred; 16]),
            alg: -8,
            cose_pubkey: Bytes(vec![]),
            aaguid: Bytes(vec![0xAA; 16]),
        }],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_technician_or_credential_is_locked_out() {
    let (p1, p2) = (TestPty::default(), TestPty::default());
    let h = harness(vec![p1.clone(), p2.clone()], SessionConfig::default());
    let mut alice = h.open(grant(6, "tech_alice", 3600)).await.expect("alice");
    let mut carol = h.open(grant(7, "tech_carol", 3600)).await.expect("carol");
    assert_eq!(h.manager.active(), 2);

    // Unchanged list: nothing closes.
    h.manager.on_techlist(&techlist(vec![
        technician("tech_alice", 0xA1),
        technician("tech_carol", 0xA1),
    ]));
    // Alice removed, Carol's credential replaced.
    h.manager
        .on_techlist(&techlist(vec![technician("tech_carol", 0xC2)]));
    let (_, a) = finish(&mut alice, Duration::from_secs(2)).await;
    let (_, c) = finish(&mut carol, Duration::from_secs(2)).await;
    assert_eq!(a, closed(REASON_TECH_REMOVED));
    assert_eq!(c, closed(REASON_TECH_REMOVED));
    wait_idle(&h.manager).await;
    assert!(p1.killed() && p2.killed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn third_session_is_rejected_and_indicator_follows() {
    let (p1, p2) = (TestPty::default(), TestPty::default());
    let h = harness(vec![p1, p2], SessionConfig::default());
    let mut one = h.open(grant(8, "tech_alice", 3600)).await.expect("one");
    let mut two = h.open(grant(9, "tech_carol", 3600)).await.expect("two");
    let third = h.open(grant(10, "tech_alice", 3600)).await;
    assert_eq!(third.err(), Some(ShellReject::TooManySessions));
    assert_eq!(h.manager.active(), 2);

    ctl(&one, ShellCtl::Close).await;
    let _ = finish(&mut one, Duration::from_secs(2)).await;
    ctl(&two, ShellCtl::Close).await;
    let _ = finish(&mut two, Duration::from_secs(2)).await;
    wait_idle(&h.manager).await;

    let states = h.indicator.states();
    let connected = |tech: &str| IndicatorState {
        connected: true,
        tech: Some(tech.into()),
    };
    assert_eq!(states.first(), Some(&connected("tech_alice")));
    assert!(states.contains(&connected("tech_alice, tech_carol")));
    assert_eq!(states.last(), Some(&IndicatorState::default()));
    // A slot frees up again.
    assert_eq!(h.manager.active(), 0);
}
