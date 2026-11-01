# Plan 07-02 Summary: Hardware-only WebAuthn registration, shell tables and techlist allowlist

## Result
**Status**: Failed
**Wave**: 2
**Agent**: engineering-security-engineer
**Completed**: 2026-11-01
**Failure Class**: BLOCKER — $ cargo test -p rmm-db --test shell (exit 101)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 8 | 2.71 | 10.71 | mandatory |
| engineering-senior-developer | — | 24 | 3.82 | 27.82 | heuristic |
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
- `Cargo.lock`
- `crates/rmm-api/Cargo.toml`
- `crates/rmm-api/src/attestation.rs`
- `crates/rmm-api/src/lib.rs`
- `crates/rmm-api/src/state.rs`
- `crates/rmm-api/src/technicians.rs`
- `crates/rmm-api/tests/technicians.rs`
- `crates/rmm-db/migrations/0006_shell.sql`
- `crates/rmm-db/src/lib.rs`
- `crates/rmm-db/src/shell.rs`
- `crates/rmm-db/tests/shell.rs`
- `crates/rmm-sign/src/aaguid.rs`
- `crates/rmm-sign/src/cli.rs`
- `crates/rmm-sign/src/drafts.rs`
- `crates/rmm-sign/src/main.rs`
- `crates/rmm-sign/tests/cli.rs`
- `deploy/.env.example`
- `deploy/compose.yaml`
- `docs/openapi.json`

## Verification Results
3/7 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-db --test shell` | 101 | FAIL |
| `cargo test -p rmm-api --test technicians` | 101 | FAIL |
| `cargo test -p rmm-sign` | 0 | PASS |
| `cargo clippy -p rmm-db -p rmm-api -p rmm-sign --all-targets -- -D warnings` | 0 | PASS |
| `cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json` | 1 | FAIL |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `cargo sqlx prepare --workspace --check` | 1 | FAIL |

## Key Decisions
- All new queries are runtime-checked (`sqlx::query`, as some queries in repo.rs already are). The offline cache actually lives at the workspace-root `.sqlx/`, not the listed `crates/rmm-db/.sqlx/`, so no cache entries were needed or written.
- `tech_id` is `Claims.sub`. The WebAuthn user handle is SHA-256("rmm-webauthn-user:" + tech_id), so no PII goes to the key.
- The begin response adds `challenge_id`, `user_name`, `user_display_name` and `exclude_credentials_b64url` beyond the spec, because finish needs the challenge id and the browser needs the user name.
- rp_id and origins come from the stored, root-verified trust manifest; without one, both endpoints return 503.
- `finish` consumes and commits the challenge before verifying, so a failed attempt burns it. Rejections are audited as `webauthn.register_rejected`, successes as `webauthn.register`. A duplicate cred_id returns 409.
- Hardening beyond the plan: the backup-eligible flag is rejected (synced passkeys), as are unknown critical extensions. The leaf must be X.509 v3 with OU "Authenticator Attestation" and must not be a CA. Intermediates must be CAs, and path length limits apply. x5c holds at most 4 certificates.
- The techlist draft is filled with real values rather than placeholders: seq = stored techlist seq + 1, issued_at = now, expires_at = now + 30 days, perms = ["shell"], client_scope from msp.technician_client (empty if none assigned). It parses and validates as a TechnicianList, the type rmm-sign's techlist loader uses.
- The ws ticket has a composite foreign key (grant_id, client_id) to shell_session with ON DELETE CASCADE, so a ticket's client must match its session's.
- The attestation config is read from env inside `AppState::new` (rmm-server is not in my file list) and fails closed: unset or invalid means 503, with an error logged.
- Dev AAGUID is `726d6d2d6465762d66616b652d6b6579` ("rmm-dev-fake-key" in ASCII).

## Issues Encountered
- `scripts/yubikey-smoke.sh` (manual hardware smoke test, not in CI) signs a techlist with `"creds": []`, which rmm-sign now refuses. It is outside my file list, so I did not change it.
- The compose env sets the root PEM path, but until 07-04 creates `deploy/dev/webauthn/attestation-root.pem` the api logs an error at startup and answers 503 for registration.
- BLOCKER: $ cargo test -p rmm-db --test shell (exit 101)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | warning | architecture | Certificate chain signatures are checked with ECDSA P-256/SHA-256 only, as the plan specified. Yubico's real attestation roots use other algorithms (I recall the U2F root as RSA-2048 and was not able to confirm the newer FIDO root), so real YubiKeys will likely fail registration in production until RSA and P-384 chain verification is added. That needs a new dependency (for example `rsa`, or using aws-lc-rs directly, which is already in the tree through jsonwebtoken). | pending |  |
| 2 | info | out-of-scope-file | `scripts/yubikey-smoke.sh` needs a credential with a YubiKey AAGUID in its techlist draft (or `--allow-aaguid`). Separately, rmm-server's api startup could load `AttestationConfig::from_env()` explicitly and refuse to start on an invalid config, instead of the current log-and-disable. | pending | INVALID: type "out-of-scope-file" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 3 | blocker | api | Resolve: $ cargo test -p rmm-db --test shell (exit 101) | pending |  |

- #1 context: crates/rmm-api/src/attestation.rs `verify_signed_by`. The dev fake authenticator and the tests are unaffected.
- #2 context: rmm-sign now rejects technicians with empty creds; `AppState::new` reads the env as a stopgap because rmm-server was not in my file list.
- #3 context: Verification failed (cargo test -p rmm-db --test shell; cargo test -p rmm-api --test technicians; cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json; cargo sqlx prepare --workspace --check); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: Cargo.lock; crates/rmm-api/Cargo.toml; crates/rmm-api/src/attestation.rs; crates/rmm-api/src/lib.rs; crates/rmm-api/src/state.rs; crates/rmm-api/src/technicians.rs; crates/rmm-api/tests/technicians.rs; crates/rmm-db/migrations/0006_shell.sql; crates/rmm-db/src/lib.rs; crates/rmm-db/src/shell.rs; crates/rmm-db/tests/shell.rs; crates/rmm-sign/src/aaguid.rs; crates/rmm-sign/src/cli.rs; crates/rmm-sign/src/drafts.rs; crates/rmm-sign/src/main.rs; crates/rmm-sign/tests/cli.rs; deploy/.env.example; deploy/compose.yaml; docs/openapi.json
- **Decisions made**: All new queries are runtime-checked (`sqlx::query`, as some queries in repo.rs already are). The offline cache actually lives at the workspace-root `.sqlx/`, not the listed `crates/rmm-db/.sqlx/`, so no cache entries were needed or written.; `tech_id` is `Claims.sub`. The WebAuthn user handle is SHA-256("rmm-webauthn-user:" + tech_id), so no PII goes to the key.; The begin response adds `challenge_id`, `user_name`, `user_display_name` and `exclude_credentials_b64url` beyond the spec, because finish needs the challenge id and the browser needs the user name.; rp_id and origins come from the stored, root-verified trust manifest; without one, both endpoints return 503.; `finish` consumes and commits the challenge before verifying, so a failed attempt burns it. Rejections are audited as `webauthn.register_rejected`, successes as `webauthn.register`. A duplicate cred_id returns 409.; Hardening beyond the plan: the backup-eligible flag is rejected (synced passkeys), as are unknown critical extensions. The leaf must be X.509 v3 with OU "Authenticator Attestation" and must not be a CA. Intermediates must be CAs, and path length limits apply. x5c holds at most 4 certificates.; The techlist draft is filled with real values rather than placeholders: seq = stored techlist seq + 1, issued_at = now, expires_at = now + 30 days, perms = ["shell"], client_scope from msp.technician_client (empty if none assigned). It parses and validates as a TechnicianList, the type rmm-sign's techlist loader uses.; The ws ticket has a composite foreign key (grant_id, client_id) to shell_session with ON DELETE CASCADE, so a ticket's client must match its session's.; The attestation config is read from env inside `AppState::new` (rmm-server is not in my file list) and fails closed: unset or invalid means 503, with an error logged.; Dev AAGUID is `726d6d2d6465762d66616b652d6b6579` ("rmm-dev-fake-key" in ASCII).
- **Open questions**: (none)
- **Conventions established**: `rmm_db::shell` for 07-04: `insert_shell_session`, `shell_session`, `update_shell_status(grant_id, from, to, reason)` (stamps opened_at/closed_at), `insert_ws_ticket(hash, client, grant, ttl)`, `consume_ws_ticket` returns `Some((grant_id, client_id))` once, `set_recording`, `recordings_older_than(cutoff, limit)`, `delete_shell_session` (tickets cascade), `credential(cred_id)`, `list_credentials`, `add_technician_client`.; 07-04's fake authenticator should mirror `crates/rmm-api/tests/technicians.rs`: a P-256 root, an optional intermediate, a leaf with OU "Authenticator Attestation", the AAGUID extension (1.3.6.1.4.1.45724.1.1.4), flags UP|UV|AT with BE clear, attStmt alg -7. It should write the root to `deploy/dev/webauthn/attestation-root.pem` and use AAGUID 726d6d2d6465762d66616b652d6b6579.; Signing a techlist with the dev credential needs `--allow-aaguid 726d6d2d6465762d66616b652d6b6579`.

## Requirements Covered
- REQ-18

## Error Details
Verification failed: cargo test -p rmm-db --test shell; cargo test -p rmm-api --test technicians; cargo run -q -p xtask -- openapi && git diff --exit-code docs/openapi.json; cargo sqlx prepare --workspace --check

### Failed verification output
`cargo test -p rmm-db --test shell`
```
g/mod.rs:194:5
  31: <fn(sqlx_core::pool::Pool<sqlx_postgres::database::Postgres>) -> shell::ws_ticket_consumes_once_and_never_after_expiry::ws_ticket_consumes_once_and_never_after_expiry::{closure#0} as sqlx_core::testing::TestFn>::run_test
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sqlx-core-0.8.6/src/testing/mod.rs:97:9
  32: shell::ws_ticket_consumes_once_and_never_after_expiry
             at ./tests/shell.rs:190:1
  33: shell::ws_ticket_consumes_once_and_never_after_expiry::{closure#0}
             at ./tests/shell.rs:190:43
  34: <shell::ws_ticket_consumes_once_and_never_after_expiry::{closure#0} as core::ops::function::FnOnce<()>>::call_once
             at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/core/src/ops/function.rs:250:5
  35: <fn() -> core::result::Result<(), alloc::string::String> as core::ops::function::FnOnce<()>>::call_once
             at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.


failures:
    challenge_consumes_once_for_its_owner_only
    credential_ids_are_unique_across_technicians
    shell_session_and_ticket_are_scoped_per_client
    status_transitions_and_retention
    ws_ticket_consumes_once_and_never_after_expiry

test result: FAILED. 0 passed; 5 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.16s

error: test failed, to rerun pass `-p rmm-db --test shell`

```
`cargo test -p rmm-api --test technicians`
```
) -> technicians::two_technicians_cannot_share_a_credential_id::two_technicians_cannot_share_a_credential_id::{closure#0} as sqlx_core::testing::TestFn>::run_test
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sqlx-core-0.8.6/src/testing/mod.rs:97:9
  32: technicians::two_technicians_cannot_share_a_credential_id
             at ./tests/technicians.rs:939:1
  33: technicians::two_technicians_cannot_share_a_credential_id::{closure#0}
             at ./tests/technicians.rs:939:51
  34: <technicians::two_technicians_cannot_share_a_credential_id::{closure#0} as core::ops::function::FnOnce<()>>::call_once
             at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/core/src/ops/function.rs:250:5
  35: <fn() -> core::result::Result<(), alloc::string::String> as core::ops::function::FnOnce<()>>::call_once
             at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/core/src/ops/function.rs:250:5
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.


failures:
    begin_returns_creation_options
    challenges_are_per_technician_and_expire
    hardware_key_registers_once_and_appears_in_the_draft
    registration_is_unavailable_without_configuration
    rejected_attestations_do_not_register
    two_technicians_cannot_share_a_credential_id

test result: FAILED. 12 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.34s

error: test failed, to rerun pass `-p rmm-api --test technicians`

```
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
`cargo sqlx prepare --workspace --check`
```
error: `--database-url` or `DATABASE_URL` must be set

```

## Token Usage
73 requests, 11974368 input tokens (11731294 cached), 101114 output tokens, $5.5838
