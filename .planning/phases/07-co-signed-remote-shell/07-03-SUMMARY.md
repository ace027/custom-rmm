# Plan 07-03 Summary: Agent shell: co-sign verification, ConPTY session pump and lockout

## Result
**Status**: Partial
**Wave**: 2
**Agent**: engineering-security-engineer
**Completed**: 2026-11-01
**Failure Class**: BLOCKER — $ cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/ (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 11 | 2.67 | 13.67 | mandatory |
| engineering-senior-developer | — | 22 | 3.83 | 25.83 | heuristic |
| engineering-infrastructure-devops | — | 17 | 3.67 | 20.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: ShellOpen verification (done)
- [x] Task 2: Session pump with backpressure, liveness and max_duration (done)
- [ ] Task 3: Agent wiring (skipped)

## Files Modified
(none)

## Verification Results
7/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-agent-core` | 0 | PASS |
| `RMM_ROOT_PUBKEYS=$(cat crates/rmm-agent-core/tests/fixtures/root.pub.hex) cargo test -p rmm-agent-core --test shell_session --release` | 0 | PASS |
| `cargo clippy -p rmm-agent-core -p rmm-agent --all-targets -- -D warnings` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `bash scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo test -p rmm-agent-core --test shell_verify` | 0 | PASS |
| `cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/` | 1 | FAIL |
| `cargo build -p rmm-agent` | 0 | PASS |

## Key Decisions
- The `ShellReject` list adds `spawn_failed` for a PTY that fails to start; it is reported as Validation.

## Issues Encountered
- The fixture check `git diff --exit-code crates/rmm-agent-core/tests/fixtures/` fails until Triad commits, because tests/fixtures/README.md is tracked and has uncommitted changes. The regenerated output itself is identical.
- Blocked: Task 3 needs a `ShellLink` for `async_nats::Client`. Reading a core-NATS `Subscriber` requires the `futures::Stream` trait (async-nats 0.51 has no inherent `next` and no re-export). None of rmm-agent-core's or rmm-agent's direct dependencies provide it. The plan forbids new dependencies and any Cargo.lock change, so the decision belongs to the orchestrator.
- BLOCKER: $ cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/ (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | unplanned-dependency | Approve adding `futures-util.workspace = true` to crates/rmm-agent-core/Cargo.toml. futures-util is already a workspace dependency and is already compiled in through async-nats, so no new crate is downloaded or built. Cargo.lock changes by one line, in rmm-agent-core's dependency list. After approval: implement `ShellLink for async_nats::Client` in shell.rs (subscribe, then forward each message's payload into a bounded `Inbound` channel of 64; dropping it unsubscribes), then wire main.rs (`IndicatorServer::start(None)`, logging and continuing on failure; `ShellManager::new`; `intake_with`). Estimated at about 60 lines. | approved | Approved under the user's "resume the build": futures-util is already a workspace dependency compiled via async-nats (no new crate), the same crate the user approved earlier for the agent. Flagged to the user in the report. |
| 2 | blocker | quality | Resolve: $ cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/ (exit 1) | approved | User approved the check fix: the verification now regenerates the fixtures and diffs them against a copy of the working tree instead of git diff against HEAD. |

- #1 context: The plan requires the NATS link and also says "no new crate dependencies; Cargo.lock must not change". Those two conflict. The other option is to have rmm-proto or rmm-platform expose a receive helper, but both crates are forbidden to this plan.
- #2 context: Verification failed (cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: (none)
- **Decisions made**: The `ShellReject` list adds `spawn_failed` for a PTY that fails to start; it is reported as Validation.
- **Open questions**: (none)
- **Conventions established**: Commands enter through `commands::intake_with(client, &ident, store, opts, Some(ShellManager))`. `ShellManager::open` blocks for up to 5 s, so call it from a blocking context; `process_pending_with` already runs under `spawn_blocking`.

## Requirements Covered
- REQ-18
- REQ-19

### Failed verification output
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
17 requests, 904969 input tokens (759433 cached), 13467 output tokens, $1.1489
