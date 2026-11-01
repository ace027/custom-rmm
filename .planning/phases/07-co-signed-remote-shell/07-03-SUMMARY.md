# Plan 07-03 Summary: Agent shell: co-sign verification, ConPTY session pump and lockout

## Result
**Status**: Partial
**Wave**: 2
**Agent**: engineering-security-engineer
**Completed**: 2026-11-01
**Failure Class**: BLOCKER (after one automatic ENVIRONMENT retry) — ENVIRONMENT issue persisted after one automatic retry: $ cargo test -p rmm-agent-core --test shell_session --release (exit 101)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 11 | 2.71 | 13.71 | mandatory |
| engineering-senior-developer | — | 22 | 3.82 | 25.82 | heuristic |
| engineering-infrastructure-devops | — | 17 | 3.67 | 20.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [ ] Task 1: ShellOpen verification (partial)
- [ ] Task 2: Session pump with backpressure, liveness and max_duration (partial)
- [ ] Task 3: Agent wiring (partial)

## Files Modified
- `crates/rmm-agent-core/Cargo.toml`
- `crates/rmm-agent-core/src/commands.rs`
- `crates/rmm-agent-core/src/lib.rs`
- `crates/rmm-agent-core/src/shell.rs`
- `crates/rmm-agent-core/src/shell_verify.rs`
- `crates/rmm-agent-core/tests/fixtures/README.md`
- `crates/rmm-agent-core/tests/fixtures/cmd-shell-server-only.env`
- `crates/rmm-agent-core/tests/fixtures/techlist-removed.env`
- `crates/rmm-agent-core/tests/fixtures/techlist.env`
- `crates/rmm-agent-core/tests/shell_session.rs`
- `crates/rmm-agent-core/tests/shell_verify.rs`
- `xtask/src/action_fixtures.rs`

## Verification Results
6/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-agent-core` | 0 | PASS |
| `cargo test -p rmm-agent-core --test shell_session --release` | 101 | FAIL |
| `cargo clippy -p rmm-agent-core -p rmm-agent --all-targets -- -D warnings` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `bash scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo test -p rmm-agent-core --test shell_verify` | 0 | PASS |
| `cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/` | 1 | FAIL |
| `cargo build -p rmm-agent` | 0 | PASS |

## Key Decisions
(none)

## Issues Encountered
- BLOCKER: ENVIRONMENT issue persisted after one automatic retry: $ cargo test -p rmm-agent-core --test shell_session --release (exit 101)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | quality | Resolve: ENVIRONMENT issue persisted after one automatic retry: $ cargo test -p rmm-agent-core --test shell_session --release (exit 101) | pending |  |

- #1 context: Verification failed (cargo test -p rmm-agent-core --test shell_session --release; cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: crates/rmm-agent-core/Cargo.toml; crates/rmm-agent-core/src/commands.rs; crates/rmm-agent-core/src/lib.rs; crates/rmm-agent-core/src/shell.rs; crates/rmm-agent-core/src/shell_verify.rs; crates/rmm-agent-core/tests/fixtures/README.md; crates/rmm-agent-core/tests/fixtures/cmd-shell-server-only.env; crates/rmm-agent-core/tests/fixtures/techlist-removed.env; crates/rmm-agent-core/tests/fixtures/techlist.env; crates/rmm-agent-core/tests/shell_session.rs; crates/rmm-agent-core/tests/shell_verify.rs; xtask/src/action_fixtures.rs
- **Decisions made**: (none)
- **Open questions**: (none)
- **Conventions established**: (none)

## Requirements Covered
- REQ-18
- REQ-19

### Failed verification output
`cargo test -p rmm-agent-core --test shell_session --release`
```
   Compiling rmm-agent-core v0.1.0 (/home/user/custom-rmm/crates/rmm-agent-core)
error[E0080]: evaluation panicked: RMM_ROOT_PUBKEYS must be set when building a release agent
  --> crates/rmm-agent-core/src/enroll.rs:25:15
   |
25 |   const _: () = assert!(
   |  _______________^
26 | |     ROOT_PUBKEYS.is_some(),
27 | |     "RMM_ROOT_PUBKEYS must be set when building a release agent"
28 | | );
   | |_^ evaluation of `enroll::_` failed here

For more information about this error, try `rustc --explain E0080`.
error: could not compile `rmm-agent-core` (lib) due to 1 previous error

```
`cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/`
```
crates/rmm-agent-core/tests/fixtures/README.md
@@ -35,3 +35,18 @@ techlist; command key holds command. Thresholds 1. capability_ceiling [service,
 - `cmd-unknown-block.env`: invokes `definition-unknown-block.env` (fails static validation).
 - `cmd-bad-param.env`: invokes `definition-param.env` with `wait_s = 9999` (fails param validation).
 - `cmd-good-param.env`: invokes `definition-param.env` with `wait_s = 30` (passes).
+
+## Shell (technician list signed by the catalog key, which holds the techlist role)
+
+Manifest console RP id `console.example.test`, origin `https://console.example.test`. Credentials are software Ed25519
+(COSE alg -8, crv 6) with AAGUID 0xAA x16; the tests sign assertions with these seeds.
+
+- `techlist.env`: seq 1 (issued NOW-86400, expires NOW+30 days). `tech_alice` scope [`client_0000000000000001`],
+cred id 0xA1 x16, seed 0x66; `tech_bob` scope [`client_0000000000000099`], cred id 0xB1 x16, seed 0x67;
+`tech_carol` scope [`*`], cred id 0xC1 x16, seed 0x68.
+- `techlist-removed.env`: seq 2, the same list without `tech_alice`. Applying `techlist.env` after it
+is a rollback.
+- `cmd-shell-server-only.env`: ShellOpen (cmd id 0x20 x16, issued NOW-10, expires NOW+590) with a
+valid grant for `tech_alice` (grant id 0x21 x16, cred 0xA1 x16, issued NOW-5, open_by NOW+60,
+max_duration 3600, shell `sh`) and an assertion with correct authenticator and client data
+but a signature the server cannot make (64 zero bytes): what the command key alone produces.

```

## Token Usage
55 requests, 8936042 input tokens (8699576 cached), 108273 output tokens, $5.0876
