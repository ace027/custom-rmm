# Plan 07-04 Summary: Grant API, browser relay, recordings and end-to-end shell

## Result
**Status**: Partial
**Wave**: 3
**Agent**: engineering-backend-architect
**Completed**: 2026-11-01
**Failure Class**: BLOCKER — $ bash scripts/e2e-shell.sh (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-backend-architect | — | 14 | 3.67 | 17.67 | mandatory |
| engineering-senior-developer | — | 24 | 3.83 | 27.83 | heuristic |
| engineering-infrastructure-devops | — | 20 | 3.67 | 23.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Grant and open endpoints (done)
- [x] Task 2: Relay, recording and retention (done)
- [ ] Task 3: Fake authenticator and end-to-end shell (partial)

## Files Modified
- `.github/workflows/ci.yml`
- `Cargo.lock`
- `crates/rmm-api/Cargo.toml`
- `crates/rmm-api/src/lib.rs`
- `crates/rmm-api/src/recording.rs`
- `crates/rmm-api/src/relay.rs`
- `crates/rmm-api/src/shell.rs`
- `crates/rmm-api/src/state.rs`
- `crates/rmm-api/tests/shell.rs`
- `crates/rmm-server/src/api.rs`
- `deploy/.env.example`
- `deploy/compose.yaml`
- `deploy/nats/nats.conf`
- `docs/dev-environment.md`
- `docs/openapi.json`
- `docs/runbooks/technician-onboarding.md`
- `scripts/ci-local.sh`
- `scripts/dev-trust.sh`
- `scripts/e2e-shell.sh`
- `xtask/Cargo.toml`
- `xtask/src/fake_authn.rs`
- `xtask/src/main.rs`

## Verification Results
7/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-api --test shell` | 0 | PASS |
| `cargo clippy -p rmm-api -p rmm-server -p xtask --all-targets -- -D warnings` | 0 | PASS |
| `t=$(mktemp) && cp docs/openapi.json "$t" && cargo run -q -p xtask -- openapi && cmp docs/openapi.json "$t"` | 0 | PASS |
| `bash scripts/e2e-shell.sh` | 1 | FAIL |
| `cargo build -p rmm-server` | 0 | PASS |
| `cargo clippy -p rmm-api -p rmm-server --all-targets -- -D warnings` | 0 | PASS |
| `bash -n scripts/e2e-shell.sh` | 0 | PASS |
| `cargo build -p xtask` | 0 | PASS |

## Key Decisions
- The WebSocket relay is reached on the API's loopback port. deploy/nginx/nginx.conf is not in my file list, so it still lacks upgrade headers.
- Check 1 reaches the agent's own assertion check by publishing a techlist with a corrupted key for the credential. The API itself rejects a bad assertion with 400, so a bad one never reaches the agent.
- Check 7 enrolls a fresh agent after the techlist without the technician is published. Nothing in the server sends TrustUpdate, so a running agent cannot pick up a new techlist.
- A browser that vanishes without a close frame gets no ShellCtl::Close, so the agent ends the session with `liveness`. A close frame sends Close.
- An unknown agent answers 403, the same as an out-of-scope one, so agent existence is not revealed.
- The grant is opened exactly once. The ShellOpen command lapses at the grant's `open_by`.
- The 50 MB check uses `yes ... | head -c` so real output volume is exercised. The literal `od -An` suppresses repeated lines and prints almost nothing.
- Unplanned `futures-util` dependency in rmm-api (already a workspace dependency).
- I ran `cargo fmt -p rmm-api`, which reformatted attestation.rs and tests/technicians.rs, then restored both with git checkout.

## Issues Encountered
- Two things in e2e-shell.sh are unproven. The recording-file permissions and ownership under the bind mount may block the API container, which runs as uid 10001. The agent's idle memory may be close to the 50 MB limit.
- An unrelated `rustfmt --check` on my files reported differences (probably in other modules they pull in). I did not investigate.
- Recordings (including keystrokes) have no size quota.
- BLOCKER: $ bash scripts/e2e-shell.sh (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | warning | deployment | Edit deploy/nginx/nginx.conf so /api/v1/shell-sessions/ forwards WebSocket upgrades (HTTP/1.1, Upgrade and Connection headers, long read and send timeouts). It is outside this plan's file list. | pending | INVALID: type "deployment" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 2 | info | dependency | rmm-api now depends on the workspace futures-util and on axum's `ws` feature. xtask gained p256, x509-cert, reqwest, tokio and others. All of these are already in Cargo.lock. | pending |  |
| 3 | info | deployment | The earlier escalation about dev AAGUID/root values reaching production is partly addressed. The API now disables registration when the dev AAGUID is listed without RMM_AUTH_ALLOW_DEV=1. A release-checklist item for the dev attestation root is still needed. | pending | INVALID: type "deployment" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 4 | blocker | api | Resolve: $ bash scripts/e2e-shell.sh (exit 1) | pending |  |

- #1 context: Without it the browser console cannot reach the relay through nginx. The dev e2e script bypasses nginx via the API's loopback port.
- #2 context: futures-util is needed for stream handling on the NATS subscription. The xtask crates serve the fake authenticator's attestation and HTTP calls.
- #3 context: The guard only checks the AAGUID, not the root PEM.
- #4 context: Verification failed (bash scripts/e2e-shell.sh); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: .github/workflows/ci.yml; Cargo.lock; crates/rmm-api/Cargo.toml; crates/rmm-api/src/lib.rs; crates/rmm-api/src/recording.rs; crates/rmm-api/src/relay.rs; crates/rmm-api/src/shell.rs; crates/rmm-api/src/state.rs; crates/rmm-api/tests/shell.rs; crates/rmm-server/src/api.rs; deploy/.env.example; deploy/compose.yaml; deploy/nats/nats.conf; docs/dev-environment.md; docs/openapi.json; docs/runbooks/technician-onboarding.md; scripts/ci-local.sh; scripts/dev-trust.sh; scripts/e2e-shell.sh; xtask/Cargo.toml; xtask/src/fake_authn.rs; xtask/src/main.rs
- **Decisions made**: The WebSocket relay is reached on the API's loopback port. deploy/nginx/nginx.conf is not in my file list, so it still lacks upgrade headers.; Check 1 reaches the agent's own assertion check by publishing a techlist with a corrupted key for the credential. The API itself rejects a bad assertion with 400, so a bad one never reaches the agent.; Check 7 enrolls a fresh agent after the techlist without the technician is published. Nothing in the server sends TrustUpdate, so a running agent cannot pick up a new techlist.; A browser that vanishes without a close frame gets no ShellCtl::Close, so the agent ends the session with `liveness`. A close frame sends Close.; An unknown agent answers 403, the same as an out-of-scope one, so agent existence is not revealed.; The grant is opened exactly once. The ShellOpen command lapses at the grant's `open_by`.; The 50 MB check uses `yes ... | head -c` so real output volume is exercised. The literal `od -An` suppresses repeated lines and prints almost nothing.; Unplanned `futures-util` dependency in rmm-api (already a workspace dependency).; I ran `cargo fmt -p rmm-api`, which reformatted attestation.rs and tests/technicians.rs, then restored both with git checkout.
- **Open questions**: (none)
- **Conventions established**: Free disk space before rerunning (`docker builder prune -af`, `rm -rf target/debug/incremental`), then run `bash scripts/e2e-shell.sh`. It needs docker and root, takes about 2 minutes plus the image build, and logs PASS/FAIL per check.; The nginx upgrade fix (proxy_http_version 1.1, Upgrade and Connection headers, long read timeout for /api/v1/shell-sessions/) is still needed before the browser can use the relay through nginx.; The TrustUpdate push to running agents is still missing.; Output ordering caveat: the agent's first prompt may be lost if it is emitted before the relay subscribes.

## Requirements Covered
- REQ-18
- REQ-19

### Failed verification output
`bash scripts/e2e-shell.sh`
```
rmm-timescale-1 Running 
 Container rmm-nats-1 Running 
 Container rmm-api-1 Running 
 Container rmm-timescale-1 Waiting 
 Container rmm-timescale-1 Healthy 
 Container rmm-migrate-1 Starting 
 Container rmm-migrate-1 Started 
 Container rmm-migrate-1 Waiting 
 Container rmm-nats-1 Waiting 
 Container rmm-migrate-1 Waiting 
 Container rmm-nats-1 Waiting 
 Container rmm-migrate-1 Waiting 
 Container rmm-nats-1 Waiting 
 Container rmm-migrate-1 Exited 
 Container rmm-migrate-1 Exited 
 Container rmm-migrate-1 Exited 
 Container rmm-nats-1 Healthy 
 Container rmm-nats-1 Healthy 
 Container rmm-nats-1 Healthy 
 Container rmm-api-1 Waiting 
 Container rmm-api-1 Healthy 
 Container rmm-migrate-1 Waiting 
 Container rmm-api-1 Waiting 
 Container rmm-ingest-1 Waiting 
 Container rmm-authd-1 Waiting 
 Container rmm-nginx-1 Waiting 
 Container rmm-timescale-1 Waiting 
 Container rmm-nats-1 Waiting 
 Container rmm-api-1 Healthy 
 Container rmm-nats-1 Healthy 
 Container rmm-migrate-1 Exited 
 Container rmm-ingest-1 Healthy 
 Container rmm-authd-1 Healthy 
 Container rmm-timescale-1 Healthy 
 Container rmm-nginx-1 Healthy 
notice: /api/v1/trust/revocations not changed (422: {"error":"rollback: stored seq 1793557035619250434, got 1793547510455812842"})
FAIL (1) agent did not refuse with bad_assertion: [2m2026-11-01T20:35:45.079665Z[0m [33m WARN[0m [2mrmm_agent_core::shell_verify[0m[2m:[0m shell open rejected: bad COSE key: point not on P-256 [3mreason[0m[2m=[0m"bad_assertion"

```

## Token Usage
72 requests, 13519376 input tokens (12941742 cached), 133465 output tokens, $5.3670
