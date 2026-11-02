# Plan 07-03 Summary: Agent shell: co-sign verification, ConPTY session pump and lockout

## Result
**Status**: Complete
**Wave**: 2
**Agent**: engineering-security-engineer
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 11 | 2.64 | 13.64 | mandatory |
| engineering-senior-developer | — | 22 | 3.83 | 25.83 | heuristic |
| engineering-infrastructure-devops | — | 17 | 3.67 | 20.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: ShellOpen verification (done)
- [x] Task 2: Session pump with backpressure, liveness and max_duration (done)
- [x] Task 3: Agent wiring (done)

## Files Modified
- `crates/rmm-agent-core/Cargo.toml`
- `crates/rmm-agent-core/src/shell.rs`
- `crates/rmm-agent/src/main.rs`

## Verification Results
8/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-agent-core` | 0 | PASS |
| `RMM_ROOT_PUBKEYS=$(cat crates/rmm-agent-core/tests/fixtures/root.pub.hex) cargo test -p rmm-agent-core --test shell_session --release` | 0 | PASS |
| `cargo clippy -p rmm-agent-core -p rmm-agent --all-targets -- -D warnings` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `bash scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo test -p rmm-agent-core --test shell_verify` | 0 | PASS |
| `t=$(mktemp -d) && cp -r crates/rmm-agent-core/tests/fixtures "$t/fx" && cargo run -q -p xtask -- action-fixtures && diff -r "$t/fx" crates/rmm-agent-core/tests/fixtures` | 0 | PASS |
| `cargo build -p rmm-agent` | 0 | PASS |

## Key Decisions
- main.rs takes the link through a generic `L: ShellLink + Clone` helper, because rmm-agent has no direct async-nats dependency and its Cargo.toml is outside this plan's write list

## Issues Encountered
- my first background test run collided with an edit in progress and failed to compile; the re-run passed

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | info | dependency | Cargo.lock now lists futures-util under rmm-agent-core. This follows from the futures-util dependency the user approved; Cargo.lock is not in files_modified, but the change cannot be avoided. | pending |  |

- #1 context: The diff adds one line to Cargo.lock. The aws-lc-rs line in the same file comes from the parallel 07-02 work.

## Handoff Context
- **Key outputs**: crates/rmm-agent-core/Cargo.toml; crates/rmm-agent-core/src/shell.rs; crates/rmm-agent/src/main.rs
- **Decisions made**: main.rs takes the link through a generic `L: ShellLink + Clone` helper, because rmm-agent has no direct async-nats dependency and its Cargo.toml is outside this plan's write list
- **Open questions**: (none)
- **Conventions established**: ShellManager::open blocks for up to 5 s until it is subscribed, so call it from a blocking context (intake already uses spawn_blocking)

## Requirements Covered
- REQ-18
- REQ-19

## Token Usage
23 requests, 1287107 input tokens (1151868 cached), 12094 output tokens, $1.1484
