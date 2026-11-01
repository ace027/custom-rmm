# Phase 8: Watchdog and A/B updater — Review Summary

## Result: PASSED

**Cycles Used**: 1
**Reviewers**: testing-qa-verification-specialist, engineering-senior-developer, engineering-laravel-specialist
**Evaluators**: code-quality, integration, business-logic
**Completed**: 2026-11-01

## Findings Summary
- Must-fix (blocker, critical, major) found: 0; fixed: 0; unresolved: 0
- Suggestions (minor, advisory): 1
- Deferred (confidence 50-79%): 14
- Hot spots (flagged by 2+ reviewers): `crates/rmm-watchdog/src/supervisor.rs`, `crates/rmm-watchdog/src/apply.rs`, `crates/rmm-watchdog/src/state.rs`, `crates/rmm-agent-core/src/update.rs`

## Findings Detail
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | minor | `crates/rmm-watchdog/src/lib.rs (also crates/rmm-agent-core/src/commands.rs, crates/rmm-agent-core/src/enroll.rs):60-72` | `parse_hex32` is now copied three times in the agent and watchdog crates. `rmm-sign/src/cli.rs:212` has a fourth, differently shaped version. This phase added the copy in the watchdog. The watchdog also has its own `hex()` helper, and `update.rs` has another. The comment "same rules as the agent" confirms the copy is deliberate. The root-key parsing that goes with it is duplicated as well. | engineering-senior-developer | 80% | deferred |

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-senior-developer: **NEEDS WORK**
- Cycle 1, engineering-laravel-specialist: **NEEDS WORK**
- Cycle 1, evaluator:code-quality: **NEEDS WORK**
- Cycle 1, evaluator:integration: **NEEDS WORK**
- Cycle 1, evaluator:business-logic: **NEEDS WORK**

## Suggestions (Not Required)
- F-001 `crates/rmm-watchdog/src/lib.rs (also crates/rmm-agent-core/src/commands.rs, crates/rmm-agent-core/src/enroll.rs)`: `parse_hex32` is now copied three times in the agent and watchdog crates. `rmm-sign/src/cli.rs:212` has a fourth, differently shaped version. This phase added the copy in the watchdog. The watchdog also has its own `hex()` helper, and `update.rs` has another. The comment "same rules as the agent" confirms the copy is deliberate. The root-key parsing that goes with it is duplicated as well. (fix: Put `hex`, `parse_hex32` and the root-key/threshold parsing in `rmm-trust`, which both crates already depend on. Have the agent, the watchdog and the CLI call that one copy.)

## Deferred (Medium Confidence)
- `crates/rmm-watchdog/src/supervisor.rs` [major, 70%]: The 5-minute rollback criterion holds only for the default health timeout. `MAX_HEALTH_TIMEOUT` is 300 s, and `rollback()` calls `stop_child()` first, which can wait up to `STOP_GRACE` (10 s) before it kills the agent. A bad build that ignores SIGTERM and is configured with the maximum timeout is rolled back at about 310 s or later. Nothing tests the deadline-to-restore path with a non-terminating child.
- `crates/rmm-watchdog/src/supervisor.rs` [major, 75%]: A resumed trial gets a fresh `deadline` and `crashes: 0` on every watchdog start. If the watchdog restarts more often than the health window, for example when the whole host or service crash-loops or reboots on a bad build, the trial never expires and never rolls back. The crash count is also lost across restarts.
- `crates/rmm-watchdog/src/apply.rs` [major, 65%]: `verify_pending` builds a new `TrustStore` and a `MemorySeqStore::new()` on every check. The staged manifest's `seq` is never compared with a persisted manifest floor, and `State` has no such field. Any older, unexpired root-signed manifest that the agent stages is accepted. That includes one from before a release key was revoked or rotated, and a release signed by that old key then passes `verify_release`.
- `crates/rmm-watchdog/src/supervisor.rs` [minor, 60%]: When `try_wait()` returns `Err`, the code only logs, and it does so every 100 ms tick. The child is never dropped or restarted, so the log fills with repeated entries.
- `crates/rmm-watchdog/src/supervisor.rs` [minor, 50%]: If saving state fails after `promote` or `rollback`, only a log line is written and the in-memory decision stands. After a restart, a rolled-back bad build resumes as a trial. Its `bad_hashes` entry is lost, and the release-seq floor in memory is no longer enforced.
- `crates/rmm-watchdog/src/state.rs` [major, 60%]: A corrupt or inconsistent `state.json` falls back to `State::bootstrap`. This resets `active` to the bootstrap slot, `active_version` to the bootstrap version, `release_seq_floor` to 0, `bad_hashes` to empty and `trial` to none.
- `crates/rmm-api/src/distribution.rs` [minor, 75%]: `Err(_) => tracing::error!(subject, "distribution reply failed")` discards the `ApiError`.
- `crates/rmm-agent-core/src/update.rs` [minor, 50%]: `busy` is cleared only after `handle` returns, and the task body is not panic-safe. A panic or abort inside the spawned task leaves `busy` true.
- `crates/rmm-watchdog/tests/supervisor.rs` [minor, 65%]: The supervisor tests cover restart, promotion, silent rollback and crash-loop rollback. No test covers a trial resumed after a watchdog restart (`trial_resumed`). None covers the `install_failed` path or the 300 s clamp of `health_timeout` in `Supervisor::new`. The `apply.rs` tests do not cover `compare_versions` with a non-semver `active_version` falling back to `0.0.0`.
- `crates/rmm-watchdog/src/main.rs` [advisory, 50%]: `run` supervises with `AtomicBool::new(false)` and no signal handling. Killing the watchdog leaves the agent child running. The next watchdog start then spawns a second agent.
- `crates/rmm-agent-core/src/update.rs` [major, 70%]: `on_release` skips known-bad hashes but never reads the watchdog's `release_seq_floor` from `state.json`. `WatchdogState` only deserializes `bad_hashes`. A release the watchdog will always reject (`replayed_seq`, `expired`, `bad_manifest`) is still downloaded in full and staged on every refresh. The watchdog then deletes `pending/`, and the cycle repeats.
- `crates/rmm-watchdog/src/supervisor.rs` [major, 50%]: The crash counter and the rollback exist only while `self.trial` is set. After promotion, a build that wrote one healthy signal and then crash-loops (or hangs) is restarted forever at an 8s backoff. `previous` is stored but never used to fall back.
- `deploy/nginx/nginx.conf` [advisory, 50%]: The unauthenticated download route is limited to 5 requests per second per IP with a burst of 10. There is no `limit_conn`, no `proxy_read_timeout` and no bandwidth cap, and files can be up to 256 MiB.
- `crates/rmm-watchdog/src/apply.rs` [minor, 50%]: The watchdog checks only its local `bad_hashes`. It does not check the catalog-signed `ArtifactRevocations` (`revoked_hashes`), which the manifest and trust crate define.

## Fixes Applied
- minor findings: engineering-backend-architect on F-001, F-002, F-003, F-004, F-005, F-007, F-008, F-009 (partial); left as is: F-003 not fixed: it needs a new persisted `manifest_seq_floor` field in `State` and changes to the apply flow, which is a design decision. The flow also lives in apply.rs, which I did not touch. / F-001 test not added: the suggested test (an agent that ignores SIGTERM, a small timeout, and a restore within `timeout + STOP_GRACE`) is not written. The cap is applied in `Supervisor::new` rather than by lowering `MAX_HEALTH_TIMEOUT`, because a main.rs unit test asserts that 300 is accepted and I can't edit main.rs. / F-007 test not added: the suggested test that a corrupt state does not lower the floor is not written. The `.bak` fallback only helps when the backup is valid. With both files corrupt it still falls back to bootstrap. / </br>; checks failed (1/24), changes undone

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
