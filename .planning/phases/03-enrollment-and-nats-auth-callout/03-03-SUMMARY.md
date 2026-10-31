# Plan 03-03 Summary: Enrollment API, Entra auth and trust artifact upload

## Result
**Status**: Complete
**Wave**: 2
**Agent**: engineering-backend-architect
**Completed**: 2026-10-31

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-backend-architect | — | 12 | 0 | 12 | mandatory |
| engineering-senior-developer | — | 18 | 4.2 | 22.2 | heuristic |
| engineering-infrastructure-devops | — | 18 | 3.67 | 21.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Technician authentication (done)
- [x] Task 2: Enrollment, tokens, revocation and trust upload (done)
- [x] Task 3: Server wiring and OpenAPI (done)

## Files Modified
- `crates/rmm-api/src/admin.rs`
- `crates/rmm-api/src/auth.rs`
- `crates/rmm-api/src/enroll.rs`
- `crates/rmm-api/src/lib.rs`
- `crates/rmm-api/src/state.rs`
- `crates/rmm-api/tests/auth.rs`
- `crates/rmm-api/tests/enroll.rs`
- `crates/rmm-server/src/api.rs`
- `crates/rmm-server/src/dev_token.rs`
- `crates/rmm-server/src/main.rs`
- `docs/openapi.json`
- `docs/runbooks/entra-setup.md`

## Verification Results
10/10 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-api --locked` | 0 | PASS |
| `cargo run -q -p xtask -- openapi --check` | 0 | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | PASS |
| `scripts/check-layering.sh` | 0 | PASS |
| `cargo test -p rmm-api --test auth --locked` | 0 | PASS |
| `cargo clippy -p rmm-api --all-targets --locked -- -D warnings` | 0 | PASS |
| `test $(grep -c 'sqlx::test' crates/rmm-api/tests/enroll.rs) -ge 12` | 0 | PASS |
| `cargo build -p rmm-server --locked` | 0 | PASS |
| `cargo test -p rmm-server --locked` | 0 | PASS |
| `python3 -c "import json;p=json.load(open('docs/openapi.json'))['paths'];assert '/v1/enroll' in p and '/api/v1/enrollment-tokens' in p"` | 0 | PASS |

## Key Decisions
- jsonwebtoken has `use_pem` off (default-features = false), so I wrote PEM-to-DER helpers in auth.rs that accept PKCS#1 and PKCS#8 private keys and PKCS#1 and SPKI public keys. dev_token.rs and the tests reuse them.
- The pubkey-already-enrolled check (409) runs before the token is consumed, so a retry costs no token use. A unique-violation on insert also maps to 409.
- A same-client match becomes PendingReview when the old agent was seen in the last 24 h, its agent is revoked, or the token disallows reattach; otherwise Reattach. A PendingReview device gets agent status `suspect_clone`; a flagged device's agent stays `active`.
- The enroll limiter keys on the `X-Real-IP` header, falling back to the socket address, and is skipped when neither is present. It is only safe behind the nginx that sets `X-Real-IP`.
- Oversize or unreadable enroll bodies return 400, not 413, to match the plan.
- Trust upload replays only the latest stored artifact per kind, because rmm-db has no list-all query. A stored artifact that no longer verifies (for example expired) is skipped with a warning. The tests hand-sign manifests, since rmm-api cannot enable the rmm-trust `sign` feature without a Cargo.toml edit.
- The test key fixtures are embedded as consts in the test files, because tests/fixtures is not in the allowed file list.

## Issues Encountered
- `cargo fmt --all` also touched files in other crates that plan 03-04 is editing (crates/rmm-agent-core/src/lib.rs and crates/rmm-agent/src/main.rs show as modified). Formatting only is expected, but 03-04's output should be checked for it.
- Missing `utoipa` uuid feature, so Uuid fields use `#[schema(value_type = String)]`.

## Escalations
(none)

## Handoff Context
- **Key outputs**: crates/rmm-api/src/admin.rs; crates/rmm-api/src/auth.rs; crates/rmm-api/src/enroll.rs; crates/rmm-api/src/lib.rs; crates/rmm-api/src/state.rs; crates/rmm-api/tests/auth.rs; crates/rmm-api/tests/enroll.rs; crates/rmm-server/src/api.rs; crates/rmm-server/src/dev_token.rs; crates/rmm-server/src/main.rs; docs/openapi.json; docs/runbooks/entra-setup.md
- **Decisions made**: jsonwebtoken has `use_pem` off (default-features = false), so I wrote PEM-to-DER helpers in auth.rs that accept PKCS#1 and PKCS#8 private keys and PKCS#1 and SPKI public keys. dev_token.rs and the tests reuse them.; The pubkey-already-enrolled check (409) runs before the token is consumed, so a retry costs no token use. A unique-violation on insert also maps to 409.; A same-client match becomes PendingReview when the old agent was seen in the last 24 h, its agent is revoked, or the token disallows reattach; otherwise Reattach. A PendingReview device gets agent status `suspect_clone`; a flagged device's agent stays `active`.; The enroll limiter keys on the `X-Real-IP` header, falling back to the socket address, and is skipped when neither is present. It is only safe behind the nginx that sets `X-Real-IP`.; Oversize or unreadable enroll bodies return 400, not 413, to match the plan.; Trust upload replays only the latest stored artifact per kind, because rmm-db has no list-all query. A stored artifact that no longer verifies (for example expired) is skipped with a warning. The tests hand-sign manifests, since rmm-api cannot enable the rmm-trust `sign` feature without a Cargo.toml edit.; The test key fixtures are embedded as consts in the test files, because tests/fixtures is not in the allowed file list.
- **Open questions**: (none)
- **Conventions established**: Agents enroll with POST /v1/enroll and a JSON EnrollRequest (header `X-Real-IP` is used for rate limiting). The 201 body is an EnrollResponse whose `status` is active, pending_review or flagged.; nkey is a NATS user public key made from the agent's Ed25519 key (`rmm_api::enroll::nkey_from_pubkey`). authd should expect `suspect_clone` agents on pending_review devices.; Revocation publishes `{agent_id, nkey}` to `rmm.internal.agent.revoked` after commit. It only logs a warning if NATS is absent or the publish fails.; Audit actions written: `agent.enroll`, `agent.enroll_denied`, `enrollment_token.create`, `agent.revoke`, `trust.upload`.; Env for the api subcommand: RMM_DATABASE_URL, RMM_ENTRA_TENANT_ID, RMM_ENTRA_AUDIENCE (required), RMM_AUTH_ALLOW_DEV, RMM_AUTH_DEV_PUBKEY_FILE, RMM_ROOT_PUBKEYS, RMM_ROOT_THRESHOLD, RMM_NATS_PUBLIC_URL, and optionally RMM_NATS_URL, RMM_NATS_USER (default `api`) and RMM_NATS_PASSWORD.

## Requirements Covered
- REQ-08
- REQ-09
- REQ-20

## Token Usage
47 requests, 4526143 input tokens (4372908 cached), 78346 output tokens, $2.0411
