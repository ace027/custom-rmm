# Plan 03-05 Summary: NATS auth callout service and end-to-end enrollment

## Result
**Status**: BLOCKED
**Wave**: 3
**Agent**: engineering-security-engineer
**Completed**: 2026-10-31
**Failure Class**: BLOCKER — $ scripts/e2e-enroll.sh (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 9 | 2.83 | 11.83 | mandatory |
| engineering-infrastructure-devops | — | 22 | 3.67 | 25.67 | heuristic |
| engineering-senior-developer | — | 21 | 4.14 | 25.14 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: NATS JWT encoding and callout handler (done)
- [x] Task 2: Dev stack auth callout configuration (done)
- [ ] Task 3: End-to-end enrollment test and CI (partial)

## Files Modified
(none)

## Verification Results
11/12 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `scripts/e2e-enroll.sh` | 1 | FAIL |
| `cargo test -p rmm-server --locked` | 0 | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | PASS |
| `scripts/check-layering.sh` | 0 | PASS |
| `scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo clippy -p rmm-server --all-targets --locked -- -D warnings` | 0 | PASS |
| `docker compose -f deploy/compose.yaml --env-file deploy/.env.example config -q` | 0 | PASS |
| `bash -n scripts/dev-up.sh` | 0 | PASS |
| `scripts/dev-up.sh` | 0 | PASS |
| `scripts/smoke-dev.sh` | 0 | PASS |
| `$HOME/.local/bin/actionlint .github/workflows/ci.yml \|\| actionlint .github/workflows/ci.yml` | 0 | PASS |
| `grep -q e2e-enroll .github/workflows/ci.yml` | 0 | PASS |

## Key Decisions
- authd also denies when the stored nkey differs from connect_opts.nkey. A non-WebSocket conn_type is denied in the precheck; an empty conn_type passes the precheck, but the JWT's allowed_connection_types [WEBSOCKET] still blocks it at the server.

## Issues Encountered
- The 03-04 transport.rs workaround (`with_auth_callback` setting `auth.signature`) never worked: without the async-nats `nkeys` feature the connector discards the signature. authd fails closed here, which is the correct security behaviour.
- Blocked: The fix is to add "nkeys" to the async-nats features in the root Cargo.toml (`features = ["websockets", "ring", "server_2_11", "nkeys"]`) and update Cargo.lock. Both files are forbidden to this plan. The nkeys crate is already a workspace dependency, so this adds no new crate.
- BLOCKER: $ scripts/e2e-enroll.sh (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | unplanned-dependency-change | Enable the `nkeys` feature on the workspace async-nats dependency in Cargo.toml and refresh Cargo.lock. | pending | INVALID: type "unplanned-dependency-change" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 2 | blocker | quality | Resolve: $ scripts/e2e-enroll.sh (exit 1) | pending |  |

- #1 context: async-nats 0.51 built without `nkeys` drops Auth.signature from CONNECT (connector.rs:698-701), so agents cannot prove possession of their key and authd denies every agent (fail closed). The 03-04 workaround in crates/rmm-agent-core/src/transport.rs depended on that field being sent. This is the only remaining failure in plan 03-05. Do not work around it by loosening authd; signature verification is the core authentication control.
- #2 context: Verification failed (scripts/e2e-enroll.sh); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: (none)
- **Decisions made**: authd also denies when the stored nkey differs from connect_opts.nkey. A non-WebSocket conn_type is denied in the precheck; an empty conn_type passes the precheck, but the JWT's allowed_connection_types [WEBSOCKET] still blocks it at the server.
- **Open questions**: (none)
- **Conventions established**: Once the feature is enabled, re-run scripts/e2e-enroll.sh. The dev stack is up and healthy. The agent code should not need changes.

## Requirements Covered
- REQ-10
- REQ-08
- REQ-09

### Failed verification output
`scripts/e2e-enroll.sh`
```
rmm_agent[0m[2m:[0m connecting [3magent_id[0m[2m=[0m64ae33ee-6f66-471e-b990-e0253afc1248 [3murl[0m[2m=[0mwss://localhost:443/nats
[2m2026-10-31T18:45:19.962126Z[0m [31mERROR[0m [2masync_nats::connector[0m[2m:[0m signature authentication requires 'nkeys' feature
[2m2026-10-31T18:45:19.962326Z[0m [32m INFO[0m [2masync_nats[0m[2m:[0m event: client error: nats: failed signing nonce
[2m2026-10-31T18:45:21.570522Z[0m [31mERROR[0m [2masync_nats::connector[0m[2m:[0m signature authentication requires 'nkeys' feature
[2m2026-10-31T18:45:21.570773Z[0m [32m INFO[0m [2masync_nats[0m[2m:[0m event: client error: nats: failed signing nonce
[2m2026-10-31T18:45:25.334261Z[0m [31mERROR[0m [2masync_nats::connector[0m[2m:[0m signature authentication requires 'nkeys' feature
[2m2026-10-31T18:45:25.334484Z[0m [32m INFO[0m [2masync_nats[0m[2m:[0m event: client error: nats: failed signing nonce
[2m2026-10-31T18:45:29.582764Z[0m [31mERROR[0m [2masync_nats::connector[0m[2m:[0m signature authentication requires 'nkeys' feature
[2m2026-10-31T18:45:29.582996Z[0m [32m INFO[0m [2masync_nats[0m[2m:[0m event: client error: nats: failed signing nonce
[2m2026-10-31T18:45:40.541410Z[0m [31mERROR[0m [2masync_nats::connector[0m[2m:[0m signature authentication requires 'nkeys' feature
[2m2026-10-31T18:45:40.541673Z[0m [32m INFO[0m [2masync_nats[0m[2m:[0m event: client error: nats: failed signing nonce
FAIL agent A run --once

```

## Token Usage
11 requests, 352143 input tokens (309770 cached), 4924 output tokens, $0.3723
