# Plan 07-04 Summary: Grant API, browser relay, recordings and end-to-end shell

## Result
**Status**: Complete with Warnings
**Wave**: 3
**Agent**: engineering-backend-architect
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-backend-architect | — | 14 | 3.59 | 17.59 | mandatory |
| engineering-senior-developer | — | 24 | 3.83 | 27.83 | heuristic |
| engineering-infrastructure-devops | — | 20 | 3.67 | 23.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Grant and open endpoints (done)
- [x] Task 2: Relay, recording and retention (done)
- [x] Task 3: Fake authenticator and end-to-end shell (done)

## Files Modified
(none)

## Verification Results
8/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-api --test shell` | 0 | PASS |
| `cargo clippy -p rmm-api -p rmm-server -p xtask --all-targets -- -D warnings` | 0 | PASS |
| `t=$(mktemp) && cp docs/openapi.json "$t" && cargo run -q -p xtask -- openapi && cmp docs/openapi.json "$t"` | 0 | PASS |
| `bash scripts/e2e-shell.sh` | 0 | PASS |
| `cargo build -p rmm-server` | 0 | PASS |
| `cargo clippy -p rmm-api -p rmm-server --all-targets -- -D warnings` | 0 | PASS |
| `bash -n scripts/e2e-shell.sh` | 0 | PASS |
| `cargo build -p xtask` | 0 | PASS |

## Key Decisions
- The e2e script reaches the WebSocket relay on the API's loopback port, because deploy/nginx/nginx.conf is not in this plan's file list.
- Check 1 uses a techlist with a corrupted key, because the API itself returns 400 for a bad assertion and never forwards it to the agent.
- Check 7 enrolls a fresh agent after the techlist without the technician is published.

## Issues Encountered
- deploy/nginx/nginx.conf still lacks WebSocket upgrade headers, so the browser cannot reach the relay through nginx.
- Nothing in the server sends TrustUpdate to running agents.
- Recordings have no size quota.
- The e2e script prints a harmless "revocations not changed (422 rollback)" notice from re-publishing revocations on a reused dev state.

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | warning | infrastructure | Edit deploy/nginx/nginx.conf so /api/v1/shell-sessions/ forwards WebSocket upgrades. The file is outside this plan's file list. | pending |  |

- #1 context: Without this edit the browser console cannot reach the relay through nginx. The e2e script bypasses nginx.

## Handoff Context
- **Key outputs**: (none)
- **Decisions made**: The e2e script reaches the WebSocket relay on the API's loopback port, because deploy/nginx/nginx.conf is not in this plan's file list.; Check 1 uses a techlist with a corrupted key, because the API itself returns 400 for a bad assertion and never forwards it to the agent.; Check 7 enrolls a fresh agent after the techlist without the technician is published.
- **Open questions**: (none)
- **Conventions established**: Before the browser console can use the relay, add proxy_http_version 1.1, the Upgrade and Connection headers, and a long read timeout for /api/v1/shell-sessions/ in deploy/nginx/nginx.conf.; Add a push of TrustUpdate to running agents.; Add a release-checklist item against the dev attestation root and dev AAGUID reaching production.

## Requirements Covered
- REQ-18
- REQ-19

## Token Usage
10 requests, 268908 input tokens (236203 cached), 3367 output tokens, $0.1627
