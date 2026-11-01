# Project State

## Current Position
- **Phase**: 4 of 9 (executed, pending review)
- **Status**: Phase 4 complete — all plans executed successfully
- **Last Activity**: Plan 04-03 execution (2026-11-01)

## Progress
```
[##########..........] 50% — 15/30 plans complete
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
Run `/triad:review` to verify Phase 4: Heartbeat, inventory and metrics

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
