# Plan 03-05 Summary: NATS auth callout service and end-to-end enrollment

## Result
**Status**: BLOCKED
**Wave**: 3
**Agent**: engineering-security-engineer
**Completed**: 2026-10-31
**Failure Class**: BLOCKER (after one automatic ENVIRONMENT retry) — ENVIRONMENT issue persisted after one automatic retry: $ scripts/e2e-enroll.sh (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 9 | 3 | 12 | mandatory |
| engineering-infrastructure-devops | — | 22 | 3.67 | 25.67 | heuristic |
| engineering-senior-developer | — | 21 | 4.2 | 25.2 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: NATS JWT encoding and callout handler (done)
- [x] Task 2: Dev stack auth callout configuration (done)
- [ ] Task 3: End-to-end enrollment test and CI (partial)

## Files Modified
- `.github/workflows/ci.yml`
- `crates/rmm-server/src/authd.rs`
- `crates/rmm-server/src/main.rs`
- `crates/rmm-server/src/natsjwt.rs`
- `crates/rmm-server/tests/natsjwt.rs`
- `deploy/.env.example`
- `deploy/compose.yaml`
- `deploy/nats/nats.conf`
- `docs/dev-environment.md`
- `docs/runbooks/windows-enroll-check.md`
- `scripts/ci-local.sh`
- `scripts/dev-up.sh`
- `scripts/e2e-enroll.sh`
- `scripts/nkey-seed.py`

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
- Nonce: NATS has no `always_enable_nonce` config option. The server sends a nonce only when at least one nkey user exists, so nats.conf has one deny-all nkey user whose seed I discarded.

## Issues Encountered
- Agent bug in rmm-agent-core: TLS has no default rustls CryptoProvider, so the agent panics on every wss:// connect. This blocks e2e steps 1, 5 and 7.
- Blocked: The disk problem is fixed, but scripts/e2e-enroll.sh cannot pass until the agent's rustls provider bug is fixed in crates/rmm-agent-core, which is outside this plan's files.
- BLOCKER: ENVIRONMENT issue persisted after one automatic retry: $ scripts/e2e-enroll.sh (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | out-of-scope-file | Fix the rustls CryptoProvider selection in the agent: in crates/rmm-agent-core/src/transport.rs, call `async_nats::rustls::crypto::ring::default_provider().install_default()` (ignore the result) before connecting, or remove the duplicate ring/aws-lc-rs features. | pending | INVALID: type "out-of-scope-file" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 2 | info | unplanned-dependency | Consider adding futures-util (already in Cargo.lock as a transitive dependency) as a direct dependency of rmm-server, so authd can use an async_nats Subscriber instead of the hand-written protocol reader. The same change would give the callout connection TLS. | pending | INVALID: type "unplanned-dependency" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 3 | blocker | quality | Resolve: ENVIRONMENT issue persisted after one automatic retry: $ scripts/e2e-enroll.sh (exit 1) | pending |  |

- #1 context: The debug rmm-agent panics on every wss:// connect with "Could not automatically determine the process-level CryptoProvider", because both rustls backends are enabled in its build. This blocks e2e steps 1, 5 and 7, the phase's main success criterion. Those files belong to plan 03-04.
- #2 context: Cargo.toml and Cargo.lock were forbidden in this plan.
- #3 context: Verification failed (scripts/e2e-enroll.sh); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: .github/workflows/ci.yml; crates/rmm-server/src/authd.rs; crates/rmm-server/src/main.rs; crates/rmm-server/src/natsjwt.rs; crates/rmm-server/tests/natsjwt.rs; deploy/.env.example; deploy/compose.yaml; deploy/nats/nats.conf; docs/dev-environment.md; docs/runbooks/windows-enroll-check.md; scripts/ci-local.sh; scripts/dev-up.sh; scripts/e2e-enroll.sh; scripts/nkey-seed.py
- **Decisions made**: Nonce: NATS has no `always_enable_nonce` config option. The server sends a nonce only when at least one nkey user exists, so nats.conf has one deny-all nkey user whose seed I discarded.
- **Open questions**: (none)
- **Conventions established**: Once the agent fix lands, run `RMM_HTTPS_PORT=8443 scripts/e2e-enroll.sh`. It needs root or passwordless sudo, plus docker and natsio/nats-box.

## Requirements Covered
- REQ-10
- REQ-08
- REQ-09

### Failed verification output
`scripts/e2e-enroll.sh`
```
:task::raw::RawTask>::poll
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/task/raw.rs:267:18
  61: <tokio::runtime::task::UnownedTask<tokio::runtime::blocking::schedule::BlockingSchedule>>::run
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/task/mod.rs:560:13
  62: <tokio::runtime::blocking::pool::Task>::run
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/blocking/pool.rs:220:19
  63: <tokio::runtime::blocking::pool::LockedImpl>::run_worker
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/blocking/pool.rs:660:22
  64: <tokio::runtime::blocking::pool::InnerImpl>::run_worker
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/blocking/pool.rs:571:39
  65: <tokio::runtime::blocking::pool::Inner>::run
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/blocking/pool.rs:764:18
  66: <tokio::runtime::blocking::pool::Spawner>::spawn_thread::{closure#0}
             at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/blocking/pool.rs:525:47
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
[2m2026-10-31T18:24:29.348839Z[0m [31mERROR[0m [2mrmm_agent[0m[2m:[0m nats connection closed
FAIL agent A run --once

```

## Token Usage
69 requests, 8370303 input tokens (8005134 cached), 99862 output tokens, $5.4240
