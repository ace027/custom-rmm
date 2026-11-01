# Plan 07-02 Summary: Hardware-only WebAuthn registration, shell tables and techlist allowlist

## Result
**Status**: Failed
**Wave**: 2
**Agent**: engineering-security-engineer
**Completed**: 2026-11-01
**Failure Class**: BLOCKER — $ cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 8 | 2.67 | 10.67 | mandatory |
| engineering-senior-developer | — | 24 | 3.83 | 27.83 | heuristic |
| engineering-infrastructure-devops | — | 17 | 3.67 | 20.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Migration 0006 and rmm-db shell module (done)
- [x] Task 2: Hardware-only registration and techlist draft API (done)
- [x] Task 3: AAGUID allowlist in rmm-sign techlist (done)

## Files Modified
(none)

## Verification Results
6/7 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-db --test shell` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-api --test technicians` | 0 | PASS |
| `cargo test -p rmm-sign` | 0 | PASS |
| `cargo clippy -p rmm-db -p rmm-api -p rmm-sign --all-targets -- -D warnings` | 0 | PASS |
| `cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json` | 1 | FAIL |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo sqlx prepare --workspace --check` | 0 | PASS |

## Key Decisions
- The new queries are checked at runtime (sqlx::query), so crates/rmm-db/.sqlx/ holds no new entries.

## Issues Encountered
- Certificate chains are checked with ECDSA P-256/SHA-256 only, as the plan specified. Real Yubico roots may use other algorithms, so real YubiKeys may fail registration (escalation below).
- BLOCKER: $ cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | warning | architecture | Should attestation chain verification support RSA and P-384 issuers? That needs a new dependency. | pending |  |
| 2 | info | security | Production deployments must not set the dev attestation root or the dev AAGUID. | pending | INVALID: type "security" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 3 | blocker | quality | Resolve: $ cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json (exit 1) | pending |  |

- #1 context: crates/rmm-api/src/attestation.rs verify_signed_by accepts only ecdsa-with-SHA256 on P-256 issuers. Yubico's FIDO attestation roots may be RSA, so production registration with real YubiKeys can be rejected. It fails closed, so this is not a security hole. It is a functionality gap to settle before production.
- #2 context: If they do, a software (fake) authenticator could register. The dev values are only in deploy/.env.example and compose.yaml (SEC-003 LOW).
- #3 context: Verification failed (cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: (none)
- **Decisions made**: The new queries are checked at runtime (sqlx::query), so crates/rmm-db/.sqlx/ holds no new entries.
- **Open questions**: (none)
- **Conventions established**: 07-04 must create the dev root PEM at the path deploy/compose.yaml points to (deploy/dev/webauthn/attestation-root.pem). Until it exists, registration answers 503.

## Requirements Covered
- REQ-18

## Error Details
Verification failed: cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json

### Failed verification output
`cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json`
```
ring",
+            "description": "User name (the technician id)."
+          }
+        }
+      },
+      "RegisterFinishRequest": {
+        "type": "object",
+        "description": "The authenticator's response to `navigator.credentials.create`.",
+        "required": [
+          "challenge_id",
+          "attestation_object_b64url",
+          "client_data_json_b64url"
+        ],
+        "properties": {
+          "attestation_object_b64url": {
+            "type": "string",
+            "description": "`response.attestationObject`, unpadded base64url."
+          },
+          "challenge_id": {
+            "type": "string",
+            "description": "`challenge_id` from `begin`."
+          },
+          "client_data_json_b64url": {
+            "type": "string",
+            "description": "`response.clientDataJSON`, unpadded base64url."
+          }
+        },
+        "additionalProperties": false
+      },
+      "RegisterFinishResponse": {
+        "type": "object",
+        "description": "A registered credential.",
+        "required": [
+          "cred_id_b64url",
+          "aaguid_hex"
+        ],
+        "properties": {
+          "aaguid_hex": {
+            "type": "string",
+            "description": "Authenticator AAGUID, lowercase hex."
+          },
+          "cred_id_b64url": {
+            "type": "string",
+            "description": "Credential id, unpadded base64url."
+          }
+        }
       }
     },
     "securitySchemes": {

```

## Token Usage
13 requests, 463610 input tokens (421111 cached), 6613 output tokens, $0.4290
