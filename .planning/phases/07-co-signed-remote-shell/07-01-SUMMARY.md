# Plan 07-01 Summary: Shell wire types, PTY abstraction and session indicator

## Result
**Status**: Complete
**Wave**: 1
**Agent**: engineering-senior-developer
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 21 | 3.82 | 24.82 | heuristic |
| engineering-infrastructure-devops | — | 17 | 3.67 | 20.67 | heuristic |
| testing-qa-verification-specialist | — | 16 | 3.5 | 19.5 | heuristic |

- **Task type detected**: implementation
- **Confidence**: HIGH
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Shell wire types and subjects (done)
- [x] Task 2: Pty trait with portable-pty and fake (done)
- [x] Task 3: Indicator server and rmm-session helper (done)

## Files Modified
- `Cargo.lock`
- `Cargo.toml`
- `crates/rmm-platform/Cargo.toml`
- `crates/rmm-platform/src/fake.rs`
- `crates/rmm-platform/src/indicator.rs`
- `crates/rmm-platform/src/lib.rs`
- `crates/rmm-platform/src/pty.rs`
- `crates/rmm-platform/tests/indicator.rs`
- `crates/rmm-platform/tests/pty.rs`
- `crates/rmm-proto/src/lib.rs`
- `crates/rmm-proto/src/shell.rs`
- `crates/rmm-proto/src/subjects.rs`
- `crates/rmm-proto/tests/shell.rs`
- `crates/rmm-session/Cargo.toml`
- `crates/rmm-session/src/main.rs`

## Verification Results
9/9 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-proto` | 0 | PASS |
| `cargo test -p rmm-platform` | 0 | PASS |
| `cargo build -p rmm-session` | 0 | PASS |
| `cargo clippy -p rmm-proto -p rmm-platform -p rmm-session --all-targets -- -D warnings` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `cargo test -p rmm-proto --test shell` | 0 | PASS |
| `cargo test -p rmm-platform --test pty` | 0 | PASS |
| `cargo deny check licenses advisories bans` | 0 | PASS |
| `cargo test -p rmm-platform --test indicator` | 0 | PASS |

## Key Decisions
- `Bytes` is a small newtype in `rmm_proto::shell` rather than the serde_bytes crate, to avoid an unplanned dependency.
- `IndicatorServer::start` takes `Option<PathBuf>`, must be called inside a tokio runtime, and removes the socket file on drop.
- `set()` uses a tokio `watch` channel, so a client that is slow to read sees only the latest state, not every intermediate one.
- rmm-session uses std threads and sockets, not tokio, and sets its own lints with `unsafe_code` allowed for the Win32 tray calls. The workspace lint forbids unsafe, and the plan required the windows crate there.
- rmm-session reads the Windows pipe as a plain file open.

## Issues Encountered
- The Windows paths (ConPTY, named pipe with SDDL, tray icon) were only compile-checked with clippy, not executed.
- `Pty::reader()` returns an empty reader if `try_clone_reader` fails, because the trait signature has no error path.

## Escalations
(none)

## Handoff Context
- **Key outputs**: Cargo.lock; Cargo.toml; crates/rmm-platform/Cargo.toml; crates/rmm-platform/src/fake.rs; crates/rmm-platform/src/indicator.rs; crates/rmm-platform/src/lib.rs; crates/rmm-platform/src/pty.rs; crates/rmm-platform/tests/indicator.rs; crates/rmm-platform/tests/pty.rs; crates/rmm-proto/src/lib.rs; crates/rmm-proto/src/shell.rs; crates/rmm-proto/src/subjects.rs; crates/rmm-proto/tests/shell.rs; crates/rmm-session/Cargo.toml; crates/rmm-session/src/main.rs
- **Decisions made**: `Bytes` is a small newtype in `rmm_proto::shell` rather than the serde_bytes crate, to avoid an unplanned dependency.; `IndicatorServer::start` takes `Option<PathBuf>`, must be called inside a tokio runtime, and removes the socket file on drop.; `set()` uses a tokio `watch` channel, so a client that is slow to read sees only the latest state, not every intermediate one.; rmm-session uses std threads and sockets, not tokio, and sets its own lints with `unsafe_code` allowed for the Win32 tray calls. The workspace lint forbids unsafe, and the plan required the windows crate there.; rmm-session reads the Windows pipe as a plain file open.
- **Open questions**: (none)
- **Conventions established**: Agent crates should create `IndicatorServer` inside a tokio runtime, call `set(IndicatorState{connected, tech})`, and keep the server alive for the agent's lifetime.; Session ids come from `subjects::sid_from_grant_id`. All shell messages go through `ShellOut`/`ShellIn`/`ShellCtl::{to_cbor,from_cbor}`, which enforce `MAX_CHUNK`.; `FakePty` (debug builds only) offers `input()`, `set_exit(code)`, `killed()` and `size()` for tests.; `PlatformError::Refused` is not used by `ShellKind::parse`, which returns `Option`. Callers must map `None` to a refusal themselves.

## Requirements Covered
- REQ-18
- REQ-19

## Token Usage
12 requests, 502576 input tokens (441954 cached), 25588 output tokens, $0.4958
