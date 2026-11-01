# Project State

## Current Position
- **Phase**: 6 of 9 (partial — 1 plan(s) failed)
- **Status**: Phase 6 partial — 06-04 failed, stopped after wave 3, review needed
- **Last Activity**: Plan 06-04 execution (2026-11-01)

## Progress
```
[#############.......] 66% — 20/30 plans complete
```

## Recent Decisions
- Approach B (balanced) from the design exploration
- Remote shell requires a technician WebAuthn co-signature verified by the agent
- Hardware-only authenticators for shell co-sign (AAGUID allowlist)
- YubiKey signing via OpenPGP applet Ed25519 with openpgp-card crates; PIV Ed25519 (fw 5.7+) is the fallback
- Deterministic CBOR envelopes, signatures over a fixed digest
- NATS agent auth via a Rust auth callout issuing scoped JWTs
- Agent key Ed25519 wrapped by DPAPI in phase 1; TPM later
- Metrics in a private compressed hypertable behind scoped views
- App-level AEAD local store instead of SQLCipher
- CI uses both cargo-xwin cross-compile and a native Windows runner
- Entra ID OIDC for technician login; recordings retained 1 year; revocation mirror deferred
- Root key generated air-gapped, age-encrypted on two USB sticks (safe + offsite)
- Foundation is broken into 9 Triad phases (design milestones M0-M8); product phases 2-6 come later
- Open a pull request for the working branch through the GitHub MCP tools so CI runs on every push (replaces the earlier "no PR" default; gh CLI is not available)
- Phase 4 throughput check split (user-approved): real agent at 50 ms interval must land >= 40 batches in 20 s (sysinfo CPU sampling blocks 200 ms per sample); ingest capacity proven by a 10000-sample burst within 60 s

## Next Action
Fix the failed plans and run `/triad:build` again (completed plans are kept), or run `/triad:review`

## Phase 1 Results
(build started 2026-10-31)
- Plan 01-01 (Wave 1): Workspace skeleton, layering and Windows cross-build — Complete
- Plan 01-02 (Wave 2): Docker compose dev environment and server stubs — Complete
- Plan 01-03 (Wave 3): GitHub Actions CI — PARTIAL: ci.yml, ci-local.sh, docs/ci.md and the README CI section are written. actionlint is clean, and windows-cross and test-linux pass locally. `ci-local.sh lint` fails at `cargo deny check` on an advisory
- Plan 01-03 (Wave 3): GitHub Actions CI — Complete

## Phase 2 Results
(build started 2026-10-31)
- Plan 02-01 (Wave 1): Canonical CBOR codec, keys and signed envelope — Complete
- Plan 02-02 (Wave 2): Trust documents, manifest chain and revocation verification — Complete with Warnings
- Plan 02-03 (Wave 2): WebAuthn assertion verification — Complete
- Plan 02-04 (Wave 3): rmm-sign CLI, YubiKey backend, runbooks and agent no-sign check — PARTIAL: The rmm-sign CLI, card backend, runbooks, agent no-sign check and CI wiring are done and verified. The one failing gate is `scripts/ci-local.sh lint`, which stops at `cargo deny check` on two advisori
- Plan 02-04 (Wave 3): rmm-sign CLI, YubiKey backend, runbooks and agent no-sign check — Complete

## Phase 3 Results
(build started 2026-10-31)
- Plan 03-01 (Wave 1): Identity schema, RLS and repositories — Complete
- Plan 03-02 (Wave 1): Device identity: key store, hardware facts and shared enrollment types — Complete
- Plan 03-03 (Wave 2): Enrollment API, Entra auth and trust artifact upload — Complete
- Plan 03-04 (Wave 2): Agent enroll and connect — Complete
- Plan 03-05 (Wave 3): NATS auth callout service and end-to-end enrollment — BLOCKED: The disk problem is fixed, but scripts/e2e-enroll.sh cannot pass until the agent's rustls provider bug is fixed in crates/rmm-agent-core, which is outside this plan's files.
- Plan 03-05 (Wave 3): NATS auth callout service and end-to-end enrollment — BLOCKED: The fix is to add "nkeys" to the async-nats features in the root Cargo.toml (`features = ["websockets", "ring", "server_2_11", "nkeys"]`) and update Cargo.lock. Both files are forbidden to this plan. 
- Plan 03-05 (Wave 3): NATS auth callout service and end-to-end enrollment — Complete with Warnings

## Phase 4 Results
(build started 2026-11-01)
- Plan 04-01 (Wave 1): Telemetry schema, roles, RLS and repositories — Complete
- Plan 04-02 (Wave 1): Telemetry wire types, collectors and agent publisher — PARTIAL: Telemetry wire types, sysinfo collectors and the `rmm-agent run` publisher are implemented and pass their tests, the Windows build, layering, no-sign and cargo deny. The workspace-wide clippy command 
- Plan 04-02 (Wave 1): Telemetry wire types, collectors and agent publisher — Complete
- Plan 04-03 (Wave 2): Ingest service and end-to-end telemetry — FAILED: Verification failed: RMM_HTTPS_PORT=8443 scripts/e2e-telemetry.sh; RMM_HTTPS_PORT=8443 scripts/e2e-enroll.sh
- Plan 04-03 (Wave 2): Ingest service and end-to-end telemetry — Complete

## Phase 5 Results
(build started 2026-11-01)
- Plan 05-01 (Wave 1): Encrypted local store — FAILED: Verification failed: scripts/check-layering.sh
- Plan 05-01 (Wave 1): Encrypted local store — Complete
- Plan 05-02 (Wave 2): Offline outbox, drain and server-side dedupe — PARTIAL: Dedupe, the agent outbox with drain on reconnect, and e2e-offline.sh are done. e2e-offline.sh passes again after the retry (Docker Hub 429 cleared). e2e-telemetry.sh still fails at check (6b) because 
- Plan 05-02 (Wave 2): Offline outbox, drain and server-side dedupe — FAILED: Verification failed: RMM_HTTPS_PORT=8443 scripts/e2e-offline.sh; RMM_HTTPS_PORT=8443 scripts/e2e-telemetry.sh; DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example | cut -d= -f2)
- Plan 05-02 (Wave 2): Offline outbox, drain and server-side dedupe — Complete

## Phase 6 Results
(build started 2026-11-01)
- Plan 06-01 (Wave 1): Recipe schema, validator, fixtures and phase dependencies — PARTIAL: none
- Plan 06-01 (Wave 1): Recipe schema, validator, fixtures and phase dependencies — Complete
- Plan 06-02 (Wave 2): Agent building blocks, command intake and executor — Complete
- Plan 06-03 (Wave 2): Catalog, command issuing and result ingest — Complete
- Plan 06-04 (Wave 3): Dev trust bootstrap, end-to-end actions and CI — BLOCKED: ENVIRONMENT issue requires human approval: free disk space on the Docker host. Separately, `rmm-sign` lacks definition signing and seed export, which needs a change in `crates/rmm-sign`.
