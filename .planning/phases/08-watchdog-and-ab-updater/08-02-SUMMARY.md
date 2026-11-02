# Plan 08-02 Summary: Watchdog: A/B slots, verified apply, health rollback and supervision

## Result
**Status**: Complete
**Wave**: 2
**Agent**: engineering-senior-developer
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 16 | 3.89 | 19.89 | heuristic |
| testing-qa-verification-specialist | — | 16 | 3.58 | 19.58 | heuristic |
| engineering-infrastructure-devops | — | 15 | 3.67 | 18.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: MEDIUM
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: State, verification and slot install (done)
- [x] Task 2: Supervisor with health rollback (done)
- [x] Task 3: CLI and Windows service host (done)

## Files Modified
- `Cargo.lock`
- `crates/rmm-watchdog/Cargo.toml`
- `crates/rmm-watchdog/src/apply.rs`
- `crates/rmm-watchdog/src/lib.rs`
- `crates/rmm-watchdog/src/main.rs`
- `crates/rmm-watchdog/src/service_windows.rs`
- `crates/rmm-watchdog/src/state.rs`
- `crates/rmm-watchdog/src/supervisor.rs`
- `crates/rmm-watchdog/tests/apply.rs`
- `crates/rmm-watchdog/tests/fixtures/README.md`
- `crates/rmm-watchdog/tests/fixtures/agent-0.1.1.sh`
- `crates/rmm-watchdog/tests/fixtures/agent-crash.sh`
- `crates/rmm-watchdog/tests/fixtures/agent-silent.sh`
- `crates/rmm-watchdog/tests/fixtures/manifest.env`
- `crates/rmm-watchdog/tests/fixtures/release-0.1.1.env`
- `crates/rmm-watchdog/tests/fixtures/release-crash.env`
- `crates/rmm-watchdog/tests/fixtures/release-downgrade.env`
- `crates/rmm-watchdog/tests/fixtures/release-silent.env`
- `crates/rmm-watchdog/tests/fixtures/release-tampered-hash.env`
- `crates/rmm-watchdog/tests/fixtures/release-wrong-role.env`
- `crates/rmm-watchdog/tests/fixtures/root.pub.hex`
- `crates/rmm-watchdog/tests/supervisor.rs`
- `scripts/check-layering.sh`
- `xtask/src/action_fixtures.rs`

## Verification Results
7/7 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-watchdog` | 0 | PASS |
| `cargo clippy -p rmm-watchdog --all-targets -- -D warnings` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `cargo test -p rmm-watchdog --test apply` | 0 | PASS |
| `t=$(mktemp -d) && cp -r crates/rmm-watchdog/tests/fixtures "$t/fx" && cargo run -q -p xtask -- action-fixtures && diff -r "$t/fx" crates/rmm-watchdog/tests/fixtures` | 0 | PASS |
| `cargo test -p rmm-watchdog --test supervisor` | 0 | PASS |
| `cargo build -p rmm-watchdog` | 0 | PASS |

## Key Decisions
- unsafe is needed for the SCM FFI, so rmm-watchdog sets unsafe_code=deny instead of the workspace forbid, and only service_windows.rs carries #[allow(unsafe_code)] (same pattern as rmm-platform)

## Issues Encountered
- std has no signal API, so the foreground `run` cannot catch SIGTERM; killing the watchdog orphans the agent child. On Windows there is no graceful stop, the child is killed at once

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | info | architecture | rmm-watchdog now allows unsafe in one module (service_windows.rs) with unsafe_code=deny crate-wide and undocumented_unsafe_blocks=deny, so rmm-platform is no longer the only crate allowing unsafe. | pending |  |

- #1 context: The plan requires StartServiceCtrlDispatcherW and a DACL helper in the watchdog without depending on rmm-platform, which needs FFI. The workspace sets unsafe_code=forbid, which cannot be overridden locally, so the crate uses its own [lints] block mirroring the workspace lints. rmm-platform's Cargo.toml description ("the only crate allowing unsafe") is now out of date; it is outside this plan's file list.

## Handoff Context
- **Key outputs**: Cargo.lock; crates/rmm-watchdog/Cargo.toml; crates/rmm-watchdog/src/apply.rs; crates/rmm-watchdog/src/lib.rs; crates/rmm-watchdog/src/main.rs; crates/rmm-watchdog/src/service_windows.rs; crates/rmm-watchdog/src/state.rs; crates/rmm-watchdog/src/supervisor.rs; crates/rmm-watchdog/tests/apply.rs; crates/rmm-watchdog/tests/fixtures/README.md; crates/rmm-watchdog/tests/fixtures/agent-0.1.1.sh; crates/rmm-watchdog/tests/fixtures/agent-crash.sh; crates/rmm-watchdog/tests/fixtures/agent-silent.sh; crates/rmm-watchdog/tests/fixtures/manifest.env; crates/rmm-watchdog/tests/fixtures/release-0.1.1.env; crates/rmm-watchdog/tests/fixtures/release-crash.env; crates/rmm-watchdog/tests/fixtures/release-downgrade.env; crates/rmm-watchdog/tests/fixtures/release-silent.env; crates/rmm-watchdog/tests/fixtures/release-tampered-hash.env; crates/rmm-watchdog/tests/fixtures/release-wrong-role.env; crates/rmm-watchdog/tests/fixtures/root.pub.hex; crates/rmm-watchdog/tests/supervisor.rs; scripts/check-layering.sh; xtask/src/action_fixtures.rs
- **Decisions made**: unsafe is needed for the SCM FFI, so rmm-watchdog sets unsafe_code=deny instead of the workspace forbid, and only service_windows.rs carries #[allow(unsafe_code)] (same pattern as rmm-platform)
- **Open questions**: (none)
- **Conventions established**: 08-03 agent staging order is pending/manifest.env, pending/release.env, pending/artifact, then an empty pending/READY last; root is the --root dir (Windows %ProgramData%\RMM)

## Requirements Covered
- REQ-21

## Token Usage
37 requests, 3315342 input tokens (3174237 cached), 74697 output tokens, $2.8342
