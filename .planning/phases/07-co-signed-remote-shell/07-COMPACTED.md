---
phase: 07-co-signed-remote-shell
compacted: 2026-11-01
original_summaries: [07-01-SUMMARY.md, 07-02-SUMMARY.md, 07-03-SUMMARY.md, 07-04-SUMMARY.md]
requirements_satisfied: [REQ-18, REQ-19]
---

# Phase 7: Co-signed remote shell — Compacted Summary

## Deliverables
- 07-01 Shell wire types, PTY abstraction and session indicator (Complete): Cargo.lock, Cargo.toml, crates/rmm-platform/Cargo.toml, crates/rmm-platform/src/fake.rs, crates/rmm-platform/src/indicator.rs, crates/rmm-platform/src/lib.rs, crates/rmm-platform/src/pty.rs, crates/rmm-platform/tests/indicator.rs, crates/rmm-platform/tests/pty.rs, crates/rmm-proto/src/lib.rs, crates/rmm-proto/src/shell.rs, crates/rmm-proto/src/subjects.rs, crates/rmm-proto/tests/shell.rs, crates/rmm-session/Cargo.toml, crates/rmm-session/src/main.rs
- 07-02 Hardware-only WebAuthn registration, shell tables and techlist allowlist (Complete with Warnings): Cargo.lock, crates/rmm-api/Cargo.toml, crates/rmm-api/src/attestation.rs, crates/rmm-api/tests/technicians.rs
- 07-03 Agent shell: co-sign verification, ConPTY session pump and lockout (Complete): crates/rmm-agent-core/Cargo.toml, crates/rmm-agent-core/src/shell.rs, crates/rmm-agent/src/main.rs
- 07-04 Grant API, browser relay, recordings and end-to-end shell (Complete with Warnings)

## Decisions
- 07-01: `Bytes` is a small newtype in `rmm_proto::shell` rather than the serde_bytes crate, to avoid an unplanned dependency.
- 07-01: `IndicatorServer::start` takes `Option<PathBuf>`, must be called inside a tokio runtime, and removes the socket file on drop.
- 07-01: `set()` uses a tokio `watch` channel, so a client that is slow to read sees only the latest state, not every intermediate one.
- 07-02: Accepted chain-link pairs are exactly ecdsa-with-SHA256 with P-256, ecdsa-with-SHA384 with P-384, and sha256WithRSAEncryption with RSA; mixed pairs such as P-38
- 07-03: main.rs takes the link through a generic `L: ShellLink + Clone` helper, because rmm-agent has no direct async-nats dependency and its Cargo.toml is outside this
- 07-04: The e2e script reaches the WebSocket relay on the API's loopback port, because deploy/nginx/nginx.conf is not in this plan's file list.
- 07-04: Check 1 uses a techlist with a corrupted key, because the API itself returns 400 for a bad assertion and never forwards it to the agent.
- 07-04: Check 7 enrolls a fresh agent after the techlist without the technician is published.

## Conventions and Open Questions
- 07-01 convention: Agent crates should create `IndicatorServer` inside a tokio runtime, call `set(IndicatorState{connected, tech})`, and keep the server alive for the agent's life
- 07-01 convention: Session ids come from `subjects::sid_from_grant_id`. All shell messages go through `ShellOut`/`ShellIn`/`ShellCtl::{to_cbor,from_cbor}`, which enforce `MAX_CHUN
- 07-01 convention: `FakePty` (debug builds only) offers `input()`, `set_exit(code)`, `killed()` and `size()` for tests.
- 07-02 convention: Attestation roots in RMM_WEBAUTHN_ATTESTATION_ROOTS may now be P-256, P-384 or RSA 2048-8192
- 07-02 convention: 07-04's dev fake authenticator may keep using a P-256 root at deploy/dev/webauthn/attestation-root.pem
- 07-03 convention: ShellManager::open blocks for up to 5 s until it is subscribed, so call it from a blocking context (intake already uses spawn_blocking)
- 07-04 convention: Before the browser console can use the relay, add proxy_http_version 1.1, the Upgrade and Connection headers, and a long read timeout for /api/v1/shell-sessions
- 07-04 convention: Add a push of TrustUpdate to running agents.
- 07-04 convention: Add a release-checklist item against the dev attestation root and dev AAGUID reaching production.

## Files Modified
| File | Change |
|------|--------|
| `Cargo.lock` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `Cargo.toml` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-platform/Cargo.toml` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-platform/src/fake.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-platform/src/indicator.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-platform/src/lib.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-platform/src/pty.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-platform/tests/indicator.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-platform/tests/pty.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-proto/src/lib.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-proto/src/shell.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-proto/src/subjects.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-proto/tests/shell.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-session/Cargo.toml` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `crates/rmm-session/src/main.rs` | 07-01: Shell wire types, PTY abstraction and session indicator |
| `Cargo.lock` | 07-02: Hardware-only WebAuthn registration, shell tables and techlist allowlist |
| `crates/rmm-api/Cargo.toml` | 07-02: Hardware-only WebAuthn registration, shell tables and techlist allowlist |
| `crates/rmm-api/src/attestation.rs` | 07-02: Hardware-only WebAuthn registration, shell tables and techlist allowlist |
| `crates/rmm-api/tests/technicians.rs` | 07-02: Hardware-only WebAuthn registration, shell tables and techlist allowlist |
| `crates/rmm-agent-core/Cargo.toml` | 07-03: Agent shell: co-sign verification, ConPTY session pump and lockout |
| `crates/rmm-agent-core/src/shell.rs` | 07-03: Agent shell: co-sign verification, ConPTY session pump and lockout |
| `crates/rmm-agent/src/main.rs` | 07-03: Agent shell: co-sign verification, ConPTY session pump and lockout |

## Verification
- 07-01 (REQ-18, REQ-19): 9/9 verification commands passed
- 07-02 (REQ-18): 7/7 verification commands passed
- 07-03 (REQ-18, REQ-19): 8/8 verification commands passed
- 07-04 (REQ-18, REQ-19): 8/8 verification commands passed

## Agents
- 07-01: engineering-senior-developer
- 07-02: engineering-security-engineer
- 07-03: engineering-security-engineer
- 07-04: engineering-backend-architect

## Also Covered
- deny.toml
- crates/rmm-db/migrations/0006_shell.sql
- crates/rmm-db/src/lib.rs
- crates/rmm-db/src/shell.rs
- crates/rmm-db/tests/shell.rs
- crates/rmm-db/.sqlx/
- crates/rmm-api/src/lib.rs
- crates/rmm-api/src/state.rs
- crates/rmm-api/src/technicians.rs
- crates/rmm-api/tests/fixtures/
- crates/rmm-sign/src/cli.rs
- crates/rmm-sign/src/drafts.rs
- crates/rmm-sign/src/aaguid.rs
- crates/rmm-sign/src/main.rs
- crates/rmm-sign/tests/
- deploy/.env.example
- deploy/compose.yaml
- docs/openapi.json
- xtask/src/main.rs
- xtask/src/openapi.rs
- crates/rmm-agent-core/src/lib.rs
- crates/rmm-agent-core/src/shell_verify.rs
- crates/rmm-agent-core/src/commands.rs
- crates/rmm-agent-core/src/store.rs
- crates/rmm-agent-core/tests/shell_verify.rs
- crates/rmm-agent-core/tests/shell_session.rs
- crates/rmm-agent-core/tests/fixtures/
- xtask/src/action_fixtures.rs
- crates/rmm-api/src/lib.rs
- crates/rmm-api/src/state.rs
- crates/rmm-api/src/shell.rs
- crates/rmm-api/src/relay.rs
- crates/rmm-api/src/recording.rs
- crates/rmm-api/tests/shell.rs
- crates/rmm-server/src/api.rs
- deploy/nats/
- deploy/compose.yaml
- deploy/.env.example
- xtask/Cargo.toml
- xtask/src/main.rs
- xtask/src/fake_authn.rs
- scripts/e2e-shell.sh
- scripts/dev-trust.sh
- scripts/ci-local.sh
- .github/workflows/ci.yml
- docs/openapi.json
- docs/dev-environment.md
- docs/runbooks/technician-onboarding.md
