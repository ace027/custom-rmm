# Codebase Map

**Analyzed:** 2026-11-09
**Generated At:** 2026-11-09T23:04:27Z
**Map Schema Version:** 2.0
**Analyzed Commit:** 7ba7318
**Source File Count:** 130
**Source Fingerprint:** 6c6645cb41dd062f
**Scope:** project-root
**Root:** /home/user/custom-rmm
**Confidence:** HIGH. Layering, CI jobs, compose services and the crate list come straight from `README.md`, `docs/ci.md`, `scripts/check-layering.sh`, `deploy/compose.yaml` and `.planning/PROJECT.md`; file paths were checked against the tree; behavior summaries come from the reviewed phase plans; untested files and line counts are computed by the map build.

```yaml
map_schema_version: "2.0"
generated_at: "2026-11-09T23:04:27Z"
analyzed_commit: "7ba7318"
source_file_count: 130
source_fingerprint: "6c6645cb41dd062f"
source_fingerprint_kind: content
scope: project-root
```

## Architecture Overview
- Workspace of 12 crates under `crates/` (see `README.md`). Shared layer `rmm-proto` → `rmm-trust` → `rmm-recipe` is used by both agent and server.
- Endpoint side: `rmm-platform` (Platform trait, the only crate allowing unsafe) → `rmm-agent-core` → `rmm-agent`. `rmm-watchdog` is sync std with no network, and `rmm-session` is the tray helper.
- Server side: `rmm-db`, `rmm-api`, `rmm-server` (subcommands api, ingest, authd, migrate, results). `rmm-server` must not depend on platform or agent-core.
- Agent flow: outbound-only NATS over WSS 443. The agent authenticates through the authd auth callout (nonce signed by the device key, DB status check, 1-hour scoped JWT), then telemetry goes to ingest and results go to the DB.
- Command flow: API invokes a pre-signed definition, which is queued on JetStream per-agent durable consumers. The agent verifies the signature chain and then runs the executor. The server never creates signed definitions and holds no signing key.
- Trust chain: offline root key (rmm-sign, age or YubiKey OpenPGP) signs TrustManifest and catalog docs. The agent verifies via rmm-trust and fails closed on stale trust. Shell is co-signed by a technician WebAuthn assertion.
- Source: `.planning/PROJECT.md`, `docs/dev-environment.md`.

## Language Distribution
| Extension | File Count | % of Codebase |
|-----------|------------|---------------|
| .rs | 129 | 99% |

## Detected Stack
| Layer | Technology | Evidence |
|-------|------------|----------|
| Language | Python | 1 .py files |
| Language | Rust | Cargo.toml |
| Framework | tokio | Cargo.toml |

## Conventions Detected
- **File naming**: lowercase
- **Module structure**: Monorepo
- **Config location**: none detected
- **Test approach**: separate test directories (75 test files)
- **Import style**: package / absolute
- **Linting/formatting**: none detected

## Entry Points
_None detected_

## Functionality Inventory
| Feature | Entry | Key files |
| --- | --- | --- |
| Signed envelopes, trust verify | rmm-trust lib | `crates/rmm-trust/src/envelope.rs`, `verify.rs`, `store.rs` |
| Enrollment (scoped token, PoP) | rmm-api `/v1/enroll` | `crates/rmm-api/src/enroll.rs`, `crates/rmm-agent-core/src/enroll.rs` |
| NATS auth callout | `rmm-server authd` | `crates/rmm-server/src/authd.rs`, `natsjwt.rs` |
| Telemetry ingest | `rmm-server ingest` | `crates/rmm-server/src/ingest.rs` |
| Results consumer | `rmm-server results` | `crates/rmm-server/src/results.rs` |
| Signed command intake and executor | agent-core | `crates/rmm-agent-core/src/commands.rs`, `executor.rs`, `blocks.rs` |
| Catalog actions (print spooler) | catalog/actions API | `crates/rmm-api/src/actions.rs`, `crates/rmm-recipe`, `catalog/printing.spooler-restart.json` |
| Remote shell (co-signed) | shell grant API and agent | `crates/rmm-api/src/shell.rs`, `crates/rmm-agent-core/src/shell_verify.rs`, `crates/rmm-agent-core/src/shell.rs`, `crates/rmm-platform/src/pty.rs` |
| WebAuthn registration and attestation | technicians API | `crates/rmm-api/src/technicians.rs`, `attestation.rs`, `crates/rmm-trust/src/webauthn.rs` |
| Admin trust upload | admin API | `crates/rmm-api/src/admin.rs` |
| Artifacts and distribution | API and NATS responders | `crates/rmm-api/src/artifacts.rs`, `distribution.rs` |
| Recordings | API | `crates/rmm-api/src/recording.rs` |
| WebSocket relay | API | `crates/rmm-api/src/relay.rs` |
| A/B watchdog and updater | watchdog bin; agent update client | `crates/rmm-watchdog/src/apply.rs`, `supervisor.rs`, `state.rs`; `crates/rmm-agent-core/src/update.rs`, `refresh.rs` |
| Platform (DPAPI, SCM, PTY, quarantine, indicator) | rmm-platform | `crates/rmm-platform/src/windows.rs`, `keystore.rs`, `services.rs`, `pty.rs`, `quarantine.rs`, `indicator.rs` |
| Offline signing CLI | rmm-sign bin | `crates/rmm-sign/src/cli.rs`, `drafts.rs`, `file_backend.rs`, `card_backend.rs` |
| MSI packaging | `cargo run -p xtask -- msi` | `installer/wix/Package.wxs`, `xtask/src/msi.rs`, `scripts/msi-check.ps1` |
| DB schema and migrations | rmm-db | `crates/rmm-db/src/lib.rs`, `crates/rmm-db/migrations/` 0001-0007 |

## Module Ownership
| Module | Responsibility | Suggested agent |
| --- | --- | --- |
| rmm-trust, rmm-sign | Signature verify, trust manifests, signing ceremony | engineering-security-engineer |
| rmm-server authd.rs/natsjwt.rs, rmm-api shell.rs/attestation.rs/technicians.rs, agent-core shell_verify.rs | Auth callout, shell grants, hardware attestation, co-sign checks | engineering-security-engineer |
| rmm-server ingest.rs, results.rs | Telemetry and result persistence | engineering-backend-architect |
| rmm-db, migrations | Schema, RLS, Scoped transactions | engineering-backend-architect |
| rmm-api (routes), OpenAPI | HTTP handlers, utoipa docs | engineering-senior-developer |
| rmm-agent-core, rmm-recipe | Command executor, store, transport, shell sessions, updates | engineering-senior-developer |
| rmm-platform, rmm-watchdog, rmm-session | OS-specific code, updater, services, indicator | engineering-senior-developer |
| scripts/, deploy/, .github/workflows, installer/, xtask | Compose, CI, e2e, MSI | engineering-infrastructure-devops |
| Tests (tests/ dirs), e2e scripts | Verification | testing-qa-verification-specialist |
| docs/, README | Operator and dev docs | product-technical-writer |

## Risk Areas
- Untested (MEDIUM): `xtask/src/action_fixtures.rs`, `xtask/src/fake_authn.rs`, `crates/rmm-watchdog/src/service_windows.rs`, `crates/rmm-sign/src/drafts.rs`, `crates/rmm-sign/src/file_backend.rs`.
- Largest files: `crates/rmm-server/src/authd.rs` (1113 lines), `crates/rmm-server/src/ingest.rs` (936), `crates/rmm-agent-core/src/commands.rs` (925), `crates/rmm-platform/src/quarantine.rs` (862), `crates/rmm-agent-core/src/shell.rs` (793).
- Security-critical: trust verification in `crates/rmm-trust/src/verify.rs` and `store.rs`, the auth callout in `crates/rmm-server/src/authd.rs` and `natsjwt.rs`, shell co-sign checks in `crates/rmm-agent-core/src/shell_verify.rs`, hardware attestation in `crates/rmm-api/src/attestation.rs`, and release verification in `crates/rmm-watchdog/src/apply.rs`.
- Windows-only paths (`crates/rmm-platform/src/windows.rs`, `crates/rmm-watchdog/src/service_windows.rs`, `installer/wix/Package.wxs`) are exercised only by the `test-windows` and `msi` CI jobs, not locally on Linux.
- The secret-exposure warning on `crates/rmm-api/tests/enroll.rs` is a test-only enrollment token seeded into a throwaway sqlx test database, not a real credential.
- Known gaps: agent version not stored server-side; recordings are plain 0600 files with no quota; manual MSI matrix and real YubiKey registration pending.

## Technical Debt Signals
**TODO/FIXME/HACK/XXX density**: 0 per source file — LOW

_None detected_

### Complexity (largest files)
| File | Lines | Level |
|------|-------|-------|
| `crates/rmm-server/src/authd.rs` | 1113 | HIGH |
| `crates/rmm-server/src/ingest.rs` | 936 | HIGH |
| `crates/rmm-agent-core/src/commands.rs` | 925 | HIGH |
| `crates/rmm-platform/src/quarantine.rs` | 862 | HIGH |
| `crates/rmm-agent-core/src/shell.rs` | 793 | HIGH |

### Git Hotspots (90 days)
_Skipped: fewer than 10 commits in 90 days, or not a git repository._

### Hygiene
_None detected_

## Dependency Risk
Direct dependencies: see manifest. Package manager not available or no lockfile found. Dependency currency check skipped. (Network checks are off: run `npm outdated` or the ecosystem equivalent to check currency.)

## Agent Guidance
- Layering: run `scripts/check-layering.sh` and `scripts/test-layering.sh`. Agent crates must not enable the rmm-trust `sign` feature. Use `scripts/check-agent-no-sign.sh` to confirm at binary level. Watchdog must not depend on tokio, reqwest, async-nats or hyper.
- Conventions: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo deny check`.
- After route changes: `cargo run -q -p xtask -- openapi` to regenerate `docs/openapi.json`; CI regenerates it and fails on any diff.
- After query changes: `cargo sqlx prepare --workspace` with the stack up, then commit `.sqlx/`.
- Fixtures: regenerate via `cargo run -p xtask -- action-fixtures` (signed fixtures are never hand-edited; `.gitattributes` keeps them byte-exact on Windows).
- Tests live in each crate's `tests/` directory. DB tests use `#[sqlx::test]` and need `DATABASE_URL`.
- e2e scripts run the agent as root via sudo: anything the test user touches (sockets, kills) must account for that.
- Do not edit applied migrations 0001-0007; add new ones. Do not add AI to endpoints, do not let the server create signed definitions, do not add obfuscation or -EncodedCommand, and do not add n8n. Keep the web UI out of this repo.

## Dependency Graph
**Files analyzed**: 130 | **Internal edges**: 0 | **External deps**: 368

### Fan-out (most imports)
_None detected_

### Fan-in (most imported)
_None detected_

### Key Dependency Chains
_None detected_

## Test Coverage Map
**Test convention**: tests/ or test/ directory
**Coverage**: 100% of sampled source files have a matching test — HIGH
**Source**: file-name matching (no coverage report read)

### Critical Untested Files
| File | Lines | Fan-in | Risk Score | Risk Level |
|------|-------|--------|------------|------------|
| `xtask/src/action_fixtures.rs` | 738 | 0 | 7.4 | MEDIUM |
| `xtask/src/fake_authn.rs` | 492 | 0 | 4.9 | MEDIUM |
| `crates/rmm-watchdog/src/service_windows.rs` | 234 | 0 | 2.3 | MEDIUM |
| `crates/rmm-sign/src/drafts.rs` | 167 | 0 | 1.7 | MEDIUM |
| `crates/rmm-sign/src/file_backend.rs` | 124 | 0 | 1.2 | MEDIUM |

## API Surface
No web framework detected or no HTTP route definitions found.

## Config & Environment
**Config files**: 2 detected | **Env variables**: 0 referenced | **Sensitive vars**: 0

### Config Files
| File |
|------|
| `.github/workflows/ci.yml` |
| `deploy/.env.example` |

### Environment Variables
_None detected_

### Secret Exposure Warnings
- MEDIUM: crates/rmm-api/tests/enroll.rs has a long literal assigned to a key/secret/token name (value not shown)

## Setup / Runbook
- Dev stack: `scripts/dev-up.sh` (creates `deploy/.env` from the example, generates certs, builds `rmm-server:dev`). Or `docker compose -f deploy/compose.yaml up -d`. Reset with `docker compose -f deploy/compose.yaml down -v`.
- Smoke: `scripts/smoke-dev.sh` (port via `RMM_HTTPS_PORT`, default 8443 in CI).
- Dev trust: `scripts/dev-trust.sh` bootstraps a throwaway trust chain with `rmm-sign` (file backend) under the gitignored `deploy/dev/trust`.
- Tests: `DATABASE_URL=postgres://rmm:<RMM_PG_PASSWORD from deploy/.env.example>@127.0.0.1:5432/rmm cargo test --workspace --locked` with the stack up (the same command is `adapter.test_command` in `settings.json`). Read the password at runtime; do not print it.
- E2E: `scripts/e2e-{enroll,telemetry,offline,actions,shell,update}.sh` against the running stack.
- Windows cross: `cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked`.
- MSI: `cargo run -p xtask -- msi` (Windows, WiX 5). On Windows: `scripts/msi-check.ps1 -Msi <path>`.
- Local CI: `scripts/ci-local.sh [lint|windows-cross|test-linux]`. Needs cargo-deny, cargo-xwin, sqlx-cli and Docker. Linux needs `libpcsclite-dev`.

## Pattern Library
- Signed envelope verify-then-decode: `crates/rmm-trust/src/envelope.rs` and `verify.rs`.
- Scoped RLS transaction: `crates/rmm-db/src/lib.rs` (`Scope::Service("authd")` in authd).
- Platform trait plus fake for tests: `crates/rmm-platform/src/lib.rs` and `fake.rs` (debug-only `RMM_AGENT_TEST_PLATFORM` in e2e).
- Strict canonical CBOR decode (re-encode and byte-compare): `crates/rmm-proto/src/canonical.rs`.
- Feature-gated signing: `crates/rmm-trust/src/lib.rs` (`#[cfg(feature = "sign")]`).
- Verification-command e2e scripts with PASS/FAIL lines: `scripts/check-layering.sh`, `scripts/e2e-*.sh`.

## Monorepo Structure
| Package | Path |
|---------|------|
| rmm-agent-core | `crates/rmm-agent-core` |
| rmm-agent | `crates/rmm-agent` |
| rmm-api | `crates/rmm-api` |
| rmm-db | `crates/rmm-db` |
| rmm-platform | `crates/rmm-platform` |
| rmm-proto | `crates/rmm-proto` |
| rmm-recipe | `crates/rmm-recipe` |
| rmm-server | `crates/rmm-server` |
| rmm-session | `crates/rmm-session` |
| rmm-sign | `crates/rmm-sign` |
| rmm-trust | `crates/rmm-trust` |
| rmm-watchdog | `crates/rmm-watchdog` |
| xtask | `xtask` |

## Directory Mappings
| Category | Primary Location | Priority | Pattern |
|----------|------------------|----------|---------|
| tests | `crates/rmm-agent-core/tests` | explicit | `crates/rmm-agent-core/tests/**` |
| scripts | `scripts` | inferred | `scripts/**` |
| docs | `docs` | inferred | `docs/**` |

### Path Enforcement Rules
Strictness: warn (writes outside a category's location are reported, not blocked).

## Retrieval Artifacts
- Chunk index: `.planning/codebase/index.jsonl`
- Symbols: `.planning/codebase/symbols.json`
- Search guide: `.planning/codebase/search.md`
