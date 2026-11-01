---
phase: 08-watchdog-and-ab-updater
compacted: 2026-11-01
original_summaries: [08-01-SUMMARY.md, 08-02-SUMMARY.md, 08-03-SUMMARY.md]
requirements_satisfied: [REQ-21]
---

# Phase 8: Watchdog and A/B updater — Compacted Summary

## Deliverables
- 08-01 Signed releases, artifact hosting and trust/release distribution (Complete with Warnings): crates/rmm-agent-core/src/commands.rs, crates/rmm-agent-core/src/lib.rs, crates/rmm-agent-core/src/refresh.rs, crates/rmm-agent-core/tests/refresh.rs, crates/rmm-agent/src/main.rs, crates/rmm-api/Cargo.toml, crates/rmm-api/src/admin.rs, crates/rmm-api/src/artifacts.rs, crates/rmm-api/src/distribution.rs, crates/rmm-api/src/lib.rs, crates/rmm-api/src/state.rs, crates/rmm-api/tests/artifacts.rs, crates/rmm-api/tests/distribution.rs, crates/rmm-db/migrations/0007_releases.sql, crates/rmm-db/src/lib.rs, crates/rmm-db/src/releases.rs, crates/rmm-server/src/api.rs, crates/rmm-server/src/natsjwt.rs, crates/rmm-server/tests/natsjwt.rs, crates/rmm-sign/src/cli.rs, crates/rmm-sign/src/drafts.rs, crates/rmm-sign/tests/cli.rs, crates/rmm-trust/src/docs.rs, crates/rmm-trust/src/envelope.rs, crates/rmm-trust/tests/release.rs, deploy/.env.example, deploy/compose.yaml, deploy/nats/nats.conf, deploy/nginx/nginx.conf, docs/openapi.json
- 08-02 Watchdog: A/B slots, verified apply, health rollback and supervision (Complete): Cargo.lock, crates/rmm-watchdog/Cargo.toml, crates/rmm-watchdog/src/apply.rs, crates/rmm-watchdog/src/lib.rs, crates/rmm-watchdog/src/main.rs, crates/rmm-watchdog/src/service_windows.rs, crates/rmm-watchdog/src/state.rs, crates/rmm-watchdog/src/supervisor.rs, crates/rmm-watchdog/tests/apply.rs, crates/rmm-watchdog/tests/fixtures/README.md, crates/rmm-watchdog/tests/fixtures/agent-0.1.1.sh, crates/rmm-watchdog/tests/fixtures/agent-crash.sh, crates/rmm-watchdog/tests/fixtures/agent-silent.sh, crates/rmm-watchdog/tests/fixtures/manifest.env, crates/rmm-watchdog/tests/fixtures/release-0.1.1.env, crates/rmm-watchdog/tests/fixtures/release-crash.env, crates/rmm-watchdog/tests/fixtures/release-downgrade.env, crates/rmm-watchdog/tests/fixtures/release-silent.env, crates/rmm-watchdog/tests/fixtures/release-tampered-hash.env, crates/rmm-watchdog/tests/fixtures/release-wrong-role.env, crates/rmm-watchdog/tests/fixtures/root.pub.hex, crates/rmm-watchdog/tests/supervisor.rs, scripts/check-layering.sh, xtask/src/action_fixtures.rs
- 08-03 Agent update client, health signal and end-to-end update (Complete with Warnings): .github/workflows/ci.yml, Cargo.lock, crates/rmm-agent-core/Cargo.toml, crates/rmm-agent-core/src/health.rs, crates/rmm-agent-core/src/lib.rs, crates/rmm-agent-core/src/telemetry.rs, crates/rmm-agent-core/src/update.rs, crates/rmm-agent-core/tests/update.rs, crates/rmm-agent/src/main.rs, docs/dev-environment.md, docs/runbooks/release.md, scripts/ci-local.sh, scripts/dev-trust.sh, scripts/e2e-update.sh

## Decisions
- 08-01: `rmm-trust/Cargo.toml` is not in the file list, so I could not add the `semver` crate there. Version validation uses a hand-written strict semver 2.0 check (`do
- 08-01: The trust upload route stays `PUT /api/v1/trust/{kind}` (the plan wrote POST); 'release' is handled outside `DocKind`, because `store.rs` is not writable.
- 08-01: Extra `validate()` rules beyond the plan: `expires_at` must be after `issued_at` (max 400 days), artifact names must be plain file names, and platform strings a
- 08-02: unsafe is needed for the SCM FFI, so rmm-watchdog sets unsafe_code=deny instead of the workspace forbid, and only service_windows.rs carries #[allow(unsafe_code
- 08-03: The server does not store agent_version, so check (1) reads the version from health.json (written only after a heartbeat went out) and checks that last_seen kee
- 08-03: Check (4a) overwrites the stored artifact in deploy/dev/artifacts after upload, since the server names files by hash. Check (4b) plants a complete pending/ dire
- 08-03: e2e-update.sh recreates nats, api, authd and ingest when the api log shows a Permissions Violation on svc.*, which a stack older than the 08-01 nats.conf produc

## Conventions and Open Questions
- 08-01 convention: `refresh::run(client, store, RefreshOptions{agent, shell, on_release, wake, shutdown}, interval)`: 08-03 sets `on_release` in `crates/rmm-agent/src/main.rs`. Th
- 08-01 convention: `rmm_trust::docs::verify_release(&TrustStore, envelope_bytes, now)` is the check for a release envelope. The watchdog can use the same function, since `rmm-trus
- 08-01 convention: Artifacts are named by the server-computed SHA-256 at `GET /v1/artifacts/{sha256_hex}`
- 08-02 convention: 08-03 agent staging order is pending/manifest.env, pending/release.env, pending/artifact, then an empty pending/READY last
- 08-02 convention: root is the --root dir (Windows %ProgramData%\RMM)
- 08-03 convention: Updates are staged only when RMM_WATCHDOG_ROOT (default: parent of the state dir
- 08-03 convention: %ProgramData%\RMM on Windows) contains state.json or bootstrap/.
- 08-03 convention: Staging order is manifest.env, release.env, artifact, then READY.

## Files Modified
| File | Change |
|------|--------|
| `crates/rmm-agent-core/src/commands.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-agent-core/src/lib.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-agent-core/src/refresh.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-agent-core/tests/refresh.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-agent/src/main.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/Cargo.toml` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/src/admin.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/src/artifacts.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/src/distribution.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/src/lib.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/src/state.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/tests/artifacts.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-api/tests/distribution.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-db/migrations/0007_releases.sql` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-db/src/lib.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-db/src/releases.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-server/src/api.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-server/src/natsjwt.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-server/tests/natsjwt.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-sign/src/cli.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-sign/src/drafts.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-sign/tests/cli.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-trust/src/docs.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-trust/src/envelope.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `crates/rmm-trust/tests/release.rs` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `deploy/.env.example` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `deploy/compose.yaml` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `deploy/nats/nats.conf` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `deploy/nginx/nginx.conf` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `docs/openapi.json` | 08-01: Signed releases, artifact hosting and trust/release distribution |
| `Cargo.lock` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/Cargo.toml` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/src/apply.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/src/lib.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/src/main.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/src/service_windows.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/src/state.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/src/supervisor.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/apply.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/README.md` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/agent-0.1.1.sh` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/agent-crash.sh` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/agent-silent.sh` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/manifest.env` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/release-0.1.1.env` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/release-crash.env` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/release-downgrade.env` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/release-silent.env` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/release-tampered-hash.env` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/release-wrong-role.env` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/fixtures/root.pub.hex` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `crates/rmm-watchdog/tests/supervisor.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `scripts/check-layering.sh` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `xtask/src/action_fixtures.rs` | 08-02: Watchdog: A/B slots, verified apply, health rollback and supervision |
| `.github/workflows/ci.yml` | 08-03: Agent update client, health signal and end-to-end update |
| `Cargo.lock` | 08-03: Agent update client, health signal and end-to-end update |
| `crates/rmm-agent-core/Cargo.toml` | 08-03: Agent update client, health signal and end-to-end update |
| `crates/rmm-agent-core/src/health.rs` | 08-03: Agent update client, health signal and end-to-end update |
| `crates/rmm-agent-core/src/lib.rs` | 08-03: Agent update client, health signal and end-to-end update |
| `crates/rmm-agent-core/src/telemetry.rs` | 08-03: Agent update client, health signal and end-to-end update |
| `crates/rmm-agent-core/src/update.rs` | 08-03: Agent update client, health signal and end-to-end update |
| `crates/rmm-agent-core/tests/update.rs` | 08-03: Agent update client, health signal and end-to-end update |
| `crates/rmm-agent/src/main.rs` | 08-03: Agent update client, health signal and end-to-end update |
| `docs/dev-environment.md` | 08-03: Agent update client, health signal and end-to-end update |
| `docs/runbooks/release.md` | 08-03: Agent update client, health signal and end-to-end update |
| `scripts/ci-local.sh` | 08-03: Agent update client, health signal and end-to-end update |
| `scripts/dev-trust.sh` | 08-03: Agent update client, health signal and end-to-end update |
| `scripts/e2e-update.sh` | 08-03: Agent update client, health signal and end-to-end update |

## Verification
- 08-01 (REQ-21): 13/13 verification commands passed
- 08-02 (REQ-21): 7/7 verification commands passed
- 08-03 (REQ-21): 8/8 verification commands passed

## Agents
- 08-01: engineering-backend-architect
- 08-02: engineering-senior-developer
- 08-03: engineering-senior-developer

## Also Covered
- crates/rmm-trust/src/lib.rs
- crates/rmm-db/src/trust.rs
- crates/rmm-db/.sqlx/
