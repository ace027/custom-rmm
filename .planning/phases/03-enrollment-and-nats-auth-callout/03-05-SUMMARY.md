# Plan 03-05 Summary: NATS auth callout service and end-to-end enrollment

## Result
**Status**: Complete with Warnings
**Wave**: 3
**Agent**: engineering-security-engineer
**Completed**: 2026-10-31

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 9 | 2.75 | 11.75 | mandatory |
| engineering-infrastructure-devops | — | 22 | 3.67 | 25.67 | heuristic |
| engineering-senior-developer | — | 21 | 4.14 | 25.14 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: NATS JWT encoding and callout handler (done)
- [x] Task 2: Dev stack auth callout configuration (done)
- [x] Task 3: End-to-end enrollment test and CI (done)

## Files Modified
- `crates/rmm-server/src/authd.rs`
- `crates/rmm-server/src/natsjwt.rs`
- `scripts/dev-up.sh`
- `scripts/e2e-enroll.sh`

## Verification Results
12/12 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `scripts/e2e-enroll.sh` | 0 | PASS |
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
- authd finds a revoked agent's connections by the JWT `name` (`agent:<uuid>`) that authd itself signs, so a client cannot spoof it; the `nkey` field of the revoke notice is ignored.

## Issues Encountered
- The disk filled up during builds; I freed space with `docker builder prune -af` (build cache only, it regenerates).

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | warning | out-of-scope-file | Make nginx re-resolve upstreams at runtime (docker DNS resolver plus variable proxy_pass) in deploy/nginx/nginx.conf, then drop the reload workaround in scripts/dev-up.sh. | pending | INVALID: type "out-of-scope-file" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 2 | info | architecture | Before running a NATS cluster, make the revocation kick gather every CONNZ ping reply (not just the first) so connections on all servers are kicked. | pending |  |

- #1 context: Rebuilding the image recreates the api container with a new IP. nginx keeps the old one, returns 502, and `up --wait` fails. dev-up.sh now reloads nginx as a workaround; in production the same problem would follow any api redeploy.
- #2 context: For now it relies on the single-server dev stack. The 1 h JWT expiry plus the deny on reconnect still limit how long a revoked agent stays connected on a server the kick missed.

## Handoff Context
- **Key outputs**: crates/rmm-server/src/authd.rs; crates/rmm-server/src/natsjwt.rs; scripts/dev-up.sh; scripts/e2e-enroll.sh
- **Decisions made**: authd finds a revoked agent's connections by the JWT `name` (`agent:<uuid>`) that authd itself signs, so a client cannot spoof it; the `nkey` field of the revoke notice is ignored.
- **Open questions**: (none)
- **Conventions established**: Agent NATS user name is `natsjwt::agent_user_name(agent_id)` = `agent:<uuid>`; it appears in NATS logs and connz as the authorized user.

## Requirements Covered
- REQ-10
- REQ-08
- REQ-09

## Token Usage
33 requests, 2406704 input tokens (2309567 cached), 22294 output tokens, $1.3934
