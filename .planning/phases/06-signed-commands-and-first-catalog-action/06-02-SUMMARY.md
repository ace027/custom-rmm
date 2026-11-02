# Plan 06-02 Summary: Agent building blocks, command intake and executor

## Result
**Status**: Complete
**Wave**: 2
**Agent**: engineering-senior-developer
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 16 | 3.77 | 19.77 | mandatory |
| testing-qa-verification-specialist | — | 17 | 3.64 | 20.64 | heuristic |
| engineering-infrastructure-devops | — | 12 | 3.67 | 15.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Platform services and quarantine (done)
- [x] Task 2: Verification chain, executor and signed results (done)
- [x] Task 3: Rejection and pipeline tests (done)

## Files Modified
- `crates/rmm-agent-core/src/blocks.rs`
- `crates/rmm-agent-core/src/commands.rs`
- `crates/rmm-agent-core/src/executor.rs`
- `crates/rmm-agent-core/src/lib.rs`
- `crates/rmm-agent-core/src/store.rs`
- `crates/rmm-agent-core/tests/commands.rs`
- `crates/rmm-agent-core/tests/executor.rs`
- `crates/rmm-agent/src/main.rs`
- `crates/rmm-platform/src/fake.rs`
- `crates/rmm-platform/src/lib.rs`
- `crates/rmm-platform/src/quarantine.rs`
- `crates/rmm-platform/src/services.rs`
- `crates/rmm-platform/src/windows.rs`
- `crates/rmm-platform/tests/windows_spooler.rs`

## Verification Results
10/10 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-platform -p rmm-agent-core --locked` | 0 | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked` | 0 | PASS |
| `scripts/check-layering.sh` | 0 | PASS |
| `scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo test -p rmm-platform --locked` | 0 | PASS |
| `cargo xwin clippy --target x86_64-pc-windows-msvc -p rmm-platform --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo build -p rmm-agent --locked` | 0 | PASS |
| `cargo test -p rmm-agent-core --locked` | 0 | PASS |
| `test $(grep -c '#\[test\]\\|#\[tokio::test\]' crates/rmm-agent-core/tests/commands.rs crates/rmm-agent-core/tests/executor.rs \| awk -F: '{s+=$2} END {print s}') -ge 14` | 0 | PASS |

## Key Decisions
- `executor::run(verified, blocks)` has no `store` argument (the plan listed one). The Store work (outbox push, marking the inbox row done) is in `commands::process_pending` and `queue_result`.
- `sign_result` returns `Result<Envelope, RecipeError>`, not a bare `Envelope`, because it validates and encodes the result first.
- `intake` takes a fourth argument, `IntakeOptions {agent, blocks, outbox_wake, shutdown}`. The intake loop checks the consumer exists with `get_consumer_from_stream` (the CONSUMER.INFO call), then pulls with raw MSG.NEXT requests (batch 1, 30 s expiry) and acks with +ACK. async-nats' streaming API needs `futures_util`, which rmm-agent-core does not depend on.
- `main.rs` passes the telemetry `reconnect` notify as `outbox_wake`. `telemetry.rs` is outside my files, and without this a queued result would wait for the next metric push.
- rmm-platform has no sha2 or serde_json, so `quarantine.rs` has its own SHA-256 (tested against the NIST vectors) and a small JSON reader/writer for the manifest.
- The roots in a recipe are names (`spool`). blocks.rs maps a name to a directory, and that directory must also be on the allowlist passed to `quarantine_in`. The test platform maps `spool` to `<state_dir>/test-spool` and adds it to the allowlist.
- `FakeServices` start under FAIL_START reports success but leaves the service stopped, as CONTEXT describes. So in the full spooler recipe the steps stage fails at `service.wait`. The verify-failure rollback test drops that wait step so the failure is caught in verify.
- Error mapping: Expired/NotYetValid → expired; WrongAgent/WrongClient → wrong_agent; Stale/NoManifest → stale_trust; InvalidDocument → validation; any other trust error → bad_signature. A body that is not Invoke → validation.
- The capability ceiling is checked for the definition's capability and for the capability of every block it uses.
- Every result gets a fresh UUIDv7 as its outbox message id, so a replay rejection is not deduplicated away.
- `commands.rs` repeats the `RMM_ROOT_PUBKEYS` parsing because `enroll.rs` keeps it private and is outside my files.

## Issues Encountered
- Other files in the working tree were changed by 06-03 running in parallel (rmm-api, rmm-db, rmm-server, .sqlx); I did not touch them. Workspace clippy passed with their code included.
- On restart, a pending command that had already been verified is reported as a replay (this follows the plan). Any files it quarantined stay in `<state_dir>/quarantine/<cmd_id hex>/` until someone restores them.
- While a command is running, shutdown waits for it to finish.

## Escalations
(none)

## Handoff Context
- **Key outputs**: crates/rmm-agent-core/src/blocks.rs; crates/rmm-agent-core/src/commands.rs; crates/rmm-agent-core/src/executor.rs; crates/rmm-agent-core/src/lib.rs; crates/rmm-agent-core/src/store.rs; crates/rmm-agent-core/tests/commands.rs; crates/rmm-agent-core/tests/executor.rs; crates/rmm-agent/src/main.rs; crates/rmm-platform/src/fake.rs; crates/rmm-platform/src/lib.rs; crates/rmm-platform/src/quarantine.rs; crates/rmm-platform/src/services.rs; crates/rmm-platform/src/windows.rs; crates/rmm-platform/tests/windows_spooler.rs
- **Decisions made**: `executor::run(verified, blocks)` has no `store` argument (the plan listed one). The Store work (outbox push, marking the inbox row done) is in `commands::process_pending` and `queue_result`.; `sign_result` returns `Result<Envelope, RecipeError>`, not a bare `Envelope`, because it validates and encodes the result first.; `intake` takes a fourth argument, `IntakeOptions {agent, blocks, outbox_wake, shutdown}`. The intake loop checks the consumer exists with `get_consumer_from_stream` (the CONSUMER.INFO call), then pulls with raw MSG.NEXT requests (batch 1, 30 s expiry) and acks with +ACK. async-nats' streaming API needs `futures_util`, which rmm-agent-core does not depend on.; `main.rs` passes the telemetry `reconnect` notify as `outbox_wake`. `telemetry.rs` is outside my files, and without this a queued result would wait for the next metric push.; rmm-platform has no sha2 or serde_json, so `quarantine.rs` has its own SHA-256 (tested against the NIST vectors) and a small JSON reader/writer for the manifest.; The roots in a recipe are names (`spool`). blocks.rs maps a name to a directory, and that directory must also be on the allowlist passed to `quarantine_in`. The test platform maps `spool` to `<state_dir>/test-spool` and adds it to the allowlist.; `FakeServices` start under FAIL_START reports success but leaves the service stopped, as CONTEXT describes. So in the full spooler recipe the steps stage fails at `service.wait`. The verify-failure rollback test drops that wait step so the failure is caught in verify.; Error mapping: Expired/NotYetValid → expired; WrongAgent/WrongClient → wrong_agent; Stale/NoManifest → stale_trust; InvalidDocument → validation; any other trust error → bad_signature. A body that is not Invoke → validation.; The capability ceiling is checked for the definition's capability and for the capability of every block it uses.; Every result gets a fresh UUIDv7 as its outbox message id, so a replay rejection is not deduplicated away.; `commands.rs` repeats the `RMM_ROOT_PUBKEYS` parsing because `enroll.rs` keeps it private and is outside my files.
- **Open questions**: (none)
- **Conventions established**: Result subject is `result.<client_id>.<agent_id>` with the agent's UUID strings. The payload is the canonical bytes of an `rmm.result/1` envelope, signed with the device seed (the same key as the enrolled credential_pubkey). The outbox message id is a random UUIDv7, not the cmd_id.; 06-03 ingest: a redelivered command produces a second result for the same cmd_id with outcome rejected and reason replay. Ingest should not let it overwrite an action_run that is already finished.; For a rejected envelope whose payload cannot be read, cmd_id falls back to the first 16 bytes of SHA-256 of the envelope, and definition_content_id is all zeros.; The agent pulls from consumer `agent_<agent_uuid>` on stream `CMD` via `$JS.API.CONSUMER.MSG.NEXT.CMD.agent_<a>`. It needs CONSUMER.INFO, MSG.NEXT and `$JS.ACK.CMD.agent_<a>.>` publish rights, plus its `_INBOX_<agent>` inbox for replies.; 06-04 e2e: build the debug agent and run it with `RMM_AGENT_TEST_PLATFORM=1`, with `RMM_AGENT_FAKE_FAIL_START=Spooler` for the rollback run. Seed spool files into `<state_dir>/test-spool/`; quarantined files go to `<state_dir>/quarantine/<cmd_id hex>/`.

## Requirements Covered
- REQ-15
- REQ-16
- REQ-17

## Token Usage
50 requests, 6925674 input tokens (6707583 cached), 96261 output tokens, $4.3571
