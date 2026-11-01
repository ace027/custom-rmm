# Plan 07-02 Summary: Hardware-only WebAuthn registration, shell tables and techlist allowlist

## Result
**Status**: Complete with Warnings
**Wave**: 2
**Agent**: engineering-security-engineer
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 8 | 2.64 | 10.64 | mandatory |
| engineering-senior-developer | — | 20 | 3.83 | 23.83 | heuristic |
| engineering-infrastructure-devops | — | 19 | 3.67 | 22.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Migration 0006 and rmm-db shell module (done)
- [x] Task 2: Hardware-only registration and techlist draft API (done)
- [x] Task 3: AAGUID allowlist in rmm-sign techlist (done)

## Files Modified
- `Cargo.lock`
- `crates/rmm-api/Cargo.toml`
- `crates/rmm-api/src/attestation.rs`
- `crates/rmm-api/tests/technicians.rs`

## Verification Results
7/7 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-db --test shell` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-api --test technicians` | 0 | PASS |
| `cargo test -p rmm-sign` | 0 | PASS |
| `cargo clippy -p rmm-db -p rmm-api -p rmm-sign --all-targets -- -D warnings` | 0 | PASS |
| `t=$(mktemp) && cp docs/openapi.json "$t" && cargo run -q -p xtask -- openapi && cmp docs/openapi.json "$t"` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo sqlx prepare --workspace --check` | 0 | PASS |

## Key Decisions
- Accepted chain-link pairs are exactly ecdsa-with-SHA256 with P-256, ecdsa-with-SHA384 with P-384, and sha256WithRSAEncryption with RSA; mixed pairs such as P-384 with SHA-256 are rejected, as the plan asked (this fails safe)

## Issues Encountered
- No database was running at first. dockerd was not started; I started it and brought up the compose timescale container (rmm-timescale-1, existing volume rmm_pgdata). It is still running.

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | info | deployment | Production deployments must not set RMM_WEBAUTHN_ATTESTATION_ROOTS or RMM_WEBAUTHN_AAGUIDS to the dev values (the dev root PEM and dev AAGUID). Add a startup refusal or a release checklist item for this. | pending | INVALID: type "deployment" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |

- #1 context: If the dev root is trusted, a software (fake) authenticator can register and land in the technician list, which removes the hardware-only guarantee (LOW, carried over as SEC-003). The dev values appear only in deploy/.env.example and deploy/compose.yaml. A startup guard would need a change outside 07-02's files, so I did not add one.

## Handoff Context
- **Key outputs**: Cargo.lock; crates/rmm-api/Cargo.toml; crates/rmm-api/src/attestation.rs; crates/rmm-api/tests/technicians.rs
- **Decisions made**: Accepted chain-link pairs are exactly ecdsa-with-SHA256 with P-256, ecdsa-with-SHA384 with P-384, and sha256WithRSAEncryption with RSA; mixed pairs such as P-384 with SHA-256 are rejected, as the plan asked (this fails safe)
- **Open questions**: (none)
- **Conventions established**: Attestation roots in RMM_WEBAUTHN_ATTESTATION_ROOTS may now be P-256, P-384 or RSA 2048-8192; 07-04's dev fake authenticator may keep using a P-256 root at deploy/dev/webauthn/attestation-root.pem

## Requirements Covered
- REQ-18

## Token Usage
49 requests, 3493766 input tokens (3398719 cached), 31607 output tokens, $1.7870
