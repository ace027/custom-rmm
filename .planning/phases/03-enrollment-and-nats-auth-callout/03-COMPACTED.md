---
phase: 03-enrollment-and-nats-auth-callout
compacted: 2026-10-31
original_summaries: [03-01-SUMMARY.md, 03-02-SUMMARY.md, 03-03-SUMMARY.md, 03-04-SUMMARY.md]
requirements_satisfied: [REQ-08, REQ-09, REQ-20, REQ-10]
---

# Phase 3: Enrollment and NATS auth callout — Compacted Summary

## Deliverables
- 03-01 Identity schema, RLS and repositories (Complete): .sqlx/query-0373b549524bfcd17379f63976561a476def698b4500200ddadb1f1f07058e0e.json, .sqlx/query-1f8c30ec8e1ffa51e448ad38475a7bcd007bd60989dadd6191dd55cfe7f4652e.json, .sqlx/query-35aff84b44dee0617ba0f7f5f6751ac4c551187e41daf10ed902589bbb44a3f9.json, .sqlx/query-3ae1646e3f96fa18eb8c6691a7775fb31e52eef378b44b155e3a1aaa96533789.json, .sqlx/query-4246b70cec235d64404d88f279b4b51a28f7d0dbdc5723fcf00053d662cd7b28.json, .sqlx/query-8bf24669ddee2c88b5efcc3a8da2f112ce59ff3a598449954ba45bbbfac83108.json, .sqlx/query-963ec38da1c2348a21af9d7a18709fc7557745ceeb75a589d660a334537f9e02.json, .sqlx/query-9fa6bf89e1049a9886bb9ed5c66a4ccc0144bd512ff96dabcc877d260fab2321.json, .sqlx/query-a05ba31298e23a6fd1312745cd4f450ba7c0e1275a1a6b18d2867719b2ae9c02.json, .sqlx/query-a2835fdeb8c2bb2434c032401f9e9dd3d6aa4bb460bcb286400fb1d708e56283.json, .sqlx/query-a7808595433509122fc980413341df2aecde186471684a528f08c172a3878820.json, .sqlx/query-ad56fcdca8332f0c67c101bb23f6085f39c8f2ef35c10575267b9d78c8814c01.json, .sqlx/query-b47ca99aedb13917d685ee37e70e51608070bdd7fccaba8ea00679780186e7c8.json, crates/rmm-db/Cargo.toml, crates/rmm-db/migrations/0002_identity.sql, crates/rmm-db/src/lib.rs, crates/rmm-db/src/repo.rs, crates/rmm-db/src/scope.rs, crates/rmm-db/tests/identity.rs
- 03-02 Device identity: key store, hardware facts and shared enrollment types (Complete): Cargo.lock, Cargo.toml, crates/rmm-agent-core/Cargo.toml, crates/rmm-agent/Cargo.toml, crates/rmm-api/Cargo.toml, crates/rmm-platform/Cargo.toml, crates/rmm-platform/src/keystore.rs, crates/rmm-platform/src/lib.rs, crates/rmm-platform/src/linux.rs, crates/rmm-platform/src/macos.rs, crates/rmm-platform/src/smbios.rs, crates/rmm-platform/src/windows.rs, crates/rmm-proto/Cargo.toml, crates/rmm-proto/src/enroll.rs, crates/rmm-proto/src/lib.rs, crates/rmm-server/Cargo.toml
- 03-03 Enrollment API, Entra auth and trust artifact upload (Complete): crates/rmm-api/src/admin.rs, crates/rmm-api/src/auth.rs, crates/rmm-api/src/enroll.rs, crates/rmm-api/src/lib.rs, crates/rmm-api/src/state.rs, crates/rmm-api/tests/auth.rs, crates/rmm-api/tests/enroll.rs, crates/rmm-server/src/api.rs, crates/rmm-server/src/dev_token.rs, crates/rmm-server/src/main.rs, docs/openapi.json, docs/runbooks/entra-setup.md
- 03-04 Agent enroll and connect (Complete): crates/rmm-agent-core/src/enroll.rs, crates/rmm-agent-core/src/identity.rs, crates/rmm-agent-core/src/lib.rs, crates/rmm-agent-core/src/transport.rs, crates/rmm-agent-core/tests/enroll_client.rs, crates/rmm-agent/src/main.rs

## Decisions
- 03-01: tenant.client policy uses id = ANY(rmm.scope()), since the table has no client_id column
- 03-01: Scope::Service(reason) also sets rmm.service_reason; Scope::Clients sets rmm.service to 'off'
- 03-01: rmm_authd gets SELECT on client/device/agent and msp.trust_artifact, UPDATE(last_seen) on agent and INSERT on audit_event; it has no other write access
- 03-02: jsonwebtoken uses the `aws_lc_rs` backend, not `rust_crypto`. `rust_crypto` pulls in `rsa`, which fails `cargo deny check` with the RUSTSEC Marvin advisory, and
- 03-02: reqwest is 0.13 with `default-features = false` and features `rustls` and `json`, because 0.13 renamed `rustls-tls` to `rustls`.
- 03-02: Byte fields in JSON use a small base64 module inside rmm-proto, since the plan limits rmm-proto's new dependencies to sha2, uuid and serde_json.
- 03-03: jsonwebtoken has `use_pem` off (default-features = false), so I wrote PEM-to-DER helpers in auth.rs that accept PKCS#1 and PKCS#8 private keys and PKCS#1 and SP
- 03-03: The pubkey-already-enrolled check (409) runs before the token is consumed, so a retry costs no token use. A unique-violation on insert also maps to 409.
- 03-03: A same-client match becomes PendingReview when the old agent was seen in the last 24 h, its agent is revoked, or the token disallows reattach; otherwise Reattac
- 03-04: `enroll(server, token, keystore, platform, http, &EnrollOptions)` returns `Enrolled { identity, status }`. The extra argument carries `state_dir`, `force` and t
- 03-04: The `async-nats` `nkeys` feature is not enabled in the workspace, so `ConnectOptions::nkey` does not exist. `transport.rs` uses `with_auth_callback` and signs t
- 03-04: The release-build guard is a const `assert!` on `option_env!("RMM_ROOT_PUBKEYS").is_some()` under `cfg(not(debug_assertions))`, not a literal `compile_error!`, 

## Conventions and Open Questions
- 03-01 convention: Use begin_scoped(pool, &Scope, actor) on a pool from connect_as(url, "rmm_api" or "rmm_authd"). Enrollment must run under Scope::Service, because the token look
- 03-01 convention: Repos take &mut Transaction and return DbError. The status strings are plain text with CHECK constraints.
- 03-01 convention: latest_trust_artifacts returns Vec<(kind, seq, envelope)> ordered by kind.
- 03-02 convention: Use `rmm_platform::{keystore, default_state_dir, KeyStore}` and `Platform::{hw_facts, os_info}`. The key file is `agent.key` in the state dir.
- 03-02 convention: Use `rmm_proto::enroll::{fingerprint, EnrollRequest::signing_bytes, ...}` in the agent and the server. The proof is Ed25519 over the 42-byte `signing_bytes`, an
- 03-02 convention: All phase dependencies are already in the root manifest, the crate manifests and Cargo.lock, so later plans should not touch them.
- 03-03 convention: Agents enroll with POST /v1/enroll and a JSON EnrollRequest (header `X-Real-IP` is used for rate limiting). The 201 body is an EnrollResponse whose `status` is 
- 03-03 convention: nkey is a NATS user public key made from the agent's Ed25519 key (`rmm_api::enroll::nkey_from_pubkey`). authd should expect `suspect_clone` agents on pending_re
- 03-03 convention: Revocation publishes `{agent_id, nkey}` to `rmm.internal.agent.revoked` after commit. It only logs a warning if NATS is absent or the publish fails.
- 03-04 convention: Identity files are `identity.json` and `trust/{manifest,revocations,techlist}.env`, which are the raw envelope bytes. The key is `agent.key` in the state dir.
- 03-04 convention: The server contract the agent assumes is `POST {server}/v1/enroll` with an `EnrollRequest` JSON body. 200 returns `EnrollResponse`
- 03-04 convention: 401 means the token was rejected

## Files Modified
| File | Change |
|------|--------|
| `.sqlx/query-0373b549524bfcd17379f63976561a476def698b4500200ddadb1f1f07058e0e.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-1f8c30ec8e1ffa51e448ad38475a7bcd007bd60989dadd6191dd55cfe7f4652e.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-35aff84b44dee0617ba0f7f5f6751ac4c551187e41daf10ed902589bbb44a3f9.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-3ae1646e3f96fa18eb8c6691a7775fb31e52eef378b44b155e3a1aaa96533789.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-4246b70cec235d64404d88f279b4b51a28f7d0dbdc5723fcf00053d662cd7b28.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-8bf24669ddee2c88b5efcc3a8da2f112ce59ff3a598449954ba45bbbfac83108.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-963ec38da1c2348a21af9d7a18709fc7557745ceeb75a589d660a334537f9e02.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-9fa6bf89e1049a9886bb9ed5c66a4ccc0144bd512ff96dabcc877d260fab2321.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-a05ba31298e23a6fd1312745cd4f450ba7c0e1275a1a6b18d2867719b2ae9c02.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-a2835fdeb8c2bb2434c032401f9e9dd3d6aa4bb460bcb286400fb1d708e56283.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-a7808595433509122fc980413341df2aecde186471684a528f08c172a3878820.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-ad56fcdca8332f0c67c101bb23f6085f39c8f2ef35c10575267b9d78c8814c01.json` | 03-01: Identity schema, RLS and repositories |
| `.sqlx/query-b47ca99aedb13917d685ee37e70e51608070bdd7fccaba8ea00679780186e7c8.json` | 03-01: Identity schema, RLS and repositories |
| `crates/rmm-db/Cargo.toml` | 03-01: Identity schema, RLS and repositories |
| `crates/rmm-db/migrations/0002_identity.sql` | 03-01: Identity schema, RLS and repositories |
| `crates/rmm-db/src/lib.rs` | 03-01: Identity schema, RLS and repositories |
| `crates/rmm-db/src/repo.rs` | 03-01: Identity schema, RLS and repositories |
| `crates/rmm-db/src/scope.rs` | 03-01: Identity schema, RLS and repositories |
| `crates/rmm-db/tests/identity.rs` | 03-01: Identity schema, RLS and repositories |
| `Cargo.lock` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `Cargo.toml` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-agent-core/Cargo.toml` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-agent/Cargo.toml` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-api/Cargo.toml` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-platform/Cargo.toml` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-platform/src/keystore.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-platform/src/lib.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-platform/src/linux.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-platform/src/macos.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-platform/src/smbios.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-platform/src/windows.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-proto/Cargo.toml` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-proto/src/enroll.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-proto/src/lib.rs` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-server/Cargo.toml` | 03-02: Device identity: key store, hardware facts and shared enrollment types |
| `crates/rmm-api/src/admin.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-api/src/auth.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-api/src/enroll.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-api/src/lib.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-api/src/state.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-api/tests/auth.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-api/tests/enroll.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-server/src/api.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-server/src/dev_token.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-server/src/main.rs` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `docs/openapi.json` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `docs/runbooks/entra-setup.md` | 03-03: Enrollment API, Entra auth and trust artifact upload |
| `crates/rmm-agent-core/src/enroll.rs` | 03-04: Agent enroll and connect |
| `crates/rmm-agent-core/src/identity.rs` | 03-04: Agent enroll and connect |
| `crates/rmm-agent-core/src/lib.rs` | 03-04: Agent enroll and connect |
| `crates/rmm-agent-core/src/transport.rs` | 03-04: Agent enroll and connect |
| `crates/rmm-agent-core/tests/enroll_client.rs` | 03-04: Agent enroll and connect |
| `crates/rmm-agent/src/main.rs` | 03-04: Agent enroll and connect |

## Verification
- 03-01 (REQ-08, REQ-09): 7/7 verification commands passed
- 03-02 (REQ-08, REQ-09): 10/10 verification commands passed
- 03-03 (REQ-08, REQ-09, REQ-20): 10/10 verification commands passed
- 03-04 (REQ-08, REQ-10): 9/9 verification commands passed

## Agents
- 03-01: engineering-backend-architect
- 03-02: engineering-senior-developer
- 03-03: engineering-backend-architect
- 03-04: engineering-senior-developer
