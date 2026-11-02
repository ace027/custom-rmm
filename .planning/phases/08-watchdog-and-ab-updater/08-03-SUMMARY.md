# Plan 08-03 Summary: Agent update client, health signal and end-to-end update

## Result
**Status**: Complete with Warnings
**Wave**: 3
**Agent**: engineering-senior-developer
**Completed**: 2026-11-01
**Failure Class**: ENVIRONMENT (auto-remediated: one retry passed) — 22.57 error: failed to write to `/src/target/release/deps/rmetarn4VYe/full.rmeta`: No space left on device (os error 28)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 16 | 3.89 | 19.89 | mandatory |
| engineering-infrastructure-devops | — | 18 | 3.67 | 21.67 | heuristic |
| testing-qa-verification-specialist | — | 18 | 3.58 | 21.58 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Update client and health signal (done)
- [x] Task 2: End-to-end update script (done)
- [x] Task 3: Release runbook and docs (done)

## Files Modified
- `.github/workflows/ci.yml`
- `Cargo.lock`
- `crates/rmm-agent-core/Cargo.toml`
- `crates/rmm-agent-core/src/health.rs`
- `crates/rmm-agent-core/src/lib.rs`
- `crates/rmm-agent-core/src/telemetry.rs`
- `crates/rmm-agent-core/src/update.rs`
- `crates/rmm-agent-core/tests/update.rs`
- `crates/rmm-agent/src/main.rs`
- `docs/dev-environment.md`
- `docs/runbooks/release.md`
- `scripts/ci-local.sh`
- `scripts/dev-trust.sh`
- `scripts/e2e-update.sh`

## Verification Results
8/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-agent-core` | 0 | PASS |
| `cargo clippy -p rmm-agent-core -p rmm-agent --all-targets -- -D warnings` | 0 | PASS |
| `bash scripts/check-agent-no-sign.sh` | 0 | PASS |
| `bash scripts/e2e-update.sh` | 0 | PASS |
| `cargo test -p rmm-agent-core --test update` | 0 | PASS |
| `bash -n scripts/e2e-update.sh` | 0 | PASS |
| `test -s docs/runbooks/release.md` | 0 | PASS |
| `grep -q 'e2e-update' docs/dev-environment.md` | 0 | PASS |

## Key Decisions
- The server does not store agent_version, so check (1) reads the version from health.json (written only after a heartbeat went out) and checks that last_seen keeps advancing.
- Check (4a) overwrites the stored artifact in deploy/dev/artifacts after upload, since the server names files by hash. Check (4b) plants a complete pending/ directory.
- e2e-update.sh recreates nats, api, authd and ingest when the api log shows a Permissions Violation on svc.*, which a stack older than the 08-01 nats.conf produces.
- The script strips agent copies to about 27 MB to save disk.
- "Pending already exists" is reported as Failed("pending_exists"); no new outcome variants.

## Issues Encountered
- The host disk is tight (3.3 GB free after the run); the docker server image build and the 22 GB target directory need space. Re-running the full e2e may need another cache prune.
- Auto-remediated: 22.57 error: failed to write to `/src/target/release/deps/rmetarn4VYe/full.rmeta`: No space left on device (os error 28) → one retry → passed

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | info | architecture | The server never persists the heartbeat's agent_version, so the console cannot show rollout progress, and the runbook's "watch the rollout" section assumes it can. | pending |  |
| 2 | info | out-of-scope-file | Should refresh.rs pass the release envelope bytes to on_release? Today the callback gets only the decoded release, so Updater asks svc.release.latest a second time. | pending | INVALID: type "out-of-scope-file" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |

- #1 context: Fixing this needs a schema and ingest change in rmm-db and rmm-server, which are outside this plan.
- #2 context: This costs one extra request per offer and is safe, because the second reply must decode to the same release. Changing the callback signature in refresh.rs would remove it; that file is not in this plan's list.

## Handoff Context
- **Key outputs**: .github/workflows/ci.yml; Cargo.lock; crates/rmm-agent-core/Cargo.toml; crates/rmm-agent-core/src/health.rs; crates/rmm-agent-core/src/lib.rs; crates/rmm-agent-core/src/telemetry.rs; crates/rmm-agent-core/src/update.rs; crates/rmm-agent-core/tests/update.rs; crates/rmm-agent/src/main.rs; docs/dev-environment.md; docs/runbooks/release.md; scripts/ci-local.sh; scripts/dev-trust.sh; scripts/e2e-update.sh
- **Decisions made**: The server does not store agent_version, so check (1) reads the version from health.json (written only after a heartbeat went out) and checks that last_seen keeps advancing.; Check (4a) overwrites the stored artifact in deploy/dev/artifacts after upload, since the server names files by hash. Check (4b) plants a complete pending/ directory.; e2e-update.sh recreates nats, api, authd and ingest when the api log shows a Permissions Violation on svc.*, which a stack older than the 08-01 nats.conf produces.; The script strips agent copies to about 27 MB to save disk.; "Pending already exists" is reported as Failed("pending_exists"); no new outcome variants.
- **Open questions**: (none)
- **Conventions established**: Updates are staged only when RMM_WATCHDOG_ROOT (default: parent of the state dir; %ProgramData%\RMM on Windows) contains state.json or bootstrap/.; Staging order is manifest.env, release.env, artifact, then READY.; Dev release seq is date +%s%N.

## Requirements Covered
- REQ-21

## Token Usage
57 requests, 7563312 input tokens (7033537 cached), 66762 output tokens, $3.3987
