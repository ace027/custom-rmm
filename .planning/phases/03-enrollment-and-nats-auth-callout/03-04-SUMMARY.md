# Plan 03-04 Summary: Agent enroll and connect

## Result
**Status**: Complete
**Wave**: 2
**Agent**: engineering-senior-developer
**Completed**: 2026-10-31

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 20 | 4.2 | 24.2 | heuristic |
| testing-qa-verification-specialist | — | 14 | 4.5 | 18.5 | heuristic |
| engineering-infrastructure-devops | — | 11 | 3.67 | 14.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: HIGH
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Identity persistence and enrollment client (done)
- [x] Task 2: NATS transport and CLI (done)
- [x] Task 3: Enrollment client tests (done)

## Files Modified
- `crates/rmm-agent-core/src/enroll.rs`
- `crates/rmm-agent-core/src/identity.rs`
- `crates/rmm-agent-core/src/lib.rs`
- `crates/rmm-agent-core/src/transport.rs`
- `crates/rmm-agent-core/tests/enroll_client.rs`
- `crates/rmm-agent/src/main.rs`

## Verification Results
9/9 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-agent-core --locked` | 0 | PASS |
| `cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked` | 0 | PASS |
| `scripts/check-agent-no-sign.sh` | 0 | PASS |
| `scripts/check-layering.sh` | 0 | PASS |
| `cargo build -p rmm-agent-core --locked` | 0 | PASS |
| `cargo clippy -p rmm-agent-core --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo build -p rmm-agent --locked` | 0 | PASS |
| `cargo test -p rmm-agent-core --test enroll_client --locked` | 0 | PASS |
| `test $(grep -c '#\[tokio::test\]' crates/rmm-agent-core/tests/enroll_client.rs) -ge 5` | 0 | PASS |

## Key Decisions
- `enroll(server, token, keystore, platform, http, &EnrollOptions)` returns `Enrolled { identity, status }`. The extra argument carries `state_dir`, `force` and the retry policy, so tests can use short backoff. It also persists the trust bundle and identity, and writes the identity last because that file marks the agent as enrolled. The status is returned because the CLI has to print it.
- The `async-nats` `nkeys` feature is not enabled in the workspace, so `ConnectOptions::nkey` does not exist. `transport.rs` uses `with_auth_callback` and signs the server nonce with `nkeys::KeyPair` (User type, from the raw seed). This is the same wire auth.
- The release-build guard is a const `assert!` on `option_env!("RMM_ROOT_PUBKEYS").is_some()` under `cfg(not(debug_assertions))`, not a literal `compile_error!`, because `compile_error!` cannot be made conditional on an env var. The effect is the same: release builds fail to compile.
- The root threshold before the first manifest comes from the optional build-time env `RMM_ROOT_THRESHOLD`. The plan did not specify it, so it defaults to the number of compiled keys (strictest). An empty bundle is always accepted. A non-empty bundle with no roots configured is rejected (fail closed).
- Plain `http://` is accepted only for localhost, 127.0.0.1 and [::1], so the token is never sent in clear to a remote host. Other URLs must be `https://`.
- The extra CA (`RMM_AGENT_EXTRA_CA`) is honoured in debug builds only. `http_client` lives in core because `rmm-agent` has no `reqwest` dependency.
- `rmm-agent-core` has no `tracing` dependency, so core code does not log. `connect_observed` reports `ConnState` events over a channel and `main.rs` logs them. `connect` is the plain wrapper with the plan's signature.

## Issues Encountered
- The test server in `enroll_client.rs` is built on tokio `TcpListener` instead of axum, because `rmm-agent-core` has no axum dev-dependency and `Cargo.toml` was off-limits.
- No test covers `transport::connect` against a real NATS server. Only `reconnect_delay` is unit-tested.
- The Unix `FileKeyStore` was already in place; I did not touch `rmm-platform`.

## Escalations
(none)

## Handoff Context
- **Key outputs**: crates/rmm-agent-core/src/enroll.rs; crates/rmm-agent-core/src/identity.rs; crates/rmm-agent-core/src/lib.rs; crates/rmm-agent-core/src/transport.rs; crates/rmm-agent-core/tests/enroll_client.rs; crates/rmm-agent/src/main.rs
- **Decisions made**: `enroll(server, token, keystore, platform, http, &EnrollOptions)` returns `Enrolled { identity, status }`. The extra argument carries `state_dir`, `force` and the retry policy, so tests can use short backoff. It also persists the trust bundle and identity, and writes the identity last because that file marks the agent as enrolled. The status is returned because the CLI has to print it.; The `async-nats` `nkeys` feature is not enabled in the workspace, so `ConnectOptions::nkey` does not exist. `transport.rs` uses `with_auth_callback` and signs the server nonce with `nkeys::KeyPair` (User type, from the raw seed). This is the same wire auth.; The release-build guard is a const `assert!` on `option_env!("RMM_ROOT_PUBKEYS").is_some()` under `cfg(not(debug_assertions))`, not a literal `compile_error!`, because `compile_error!` cannot be made conditional on an env var. The effect is the same: release builds fail to compile.; The root threshold before the first manifest comes from the optional build-time env `RMM_ROOT_THRESHOLD`. The plan did not specify it, so it defaults to the number of compiled keys (strictest). An empty bundle is always accepted. A non-empty bundle with no roots configured is rejected (fail closed).; Plain `http://` is accepted only for localhost, 127.0.0.1 and [::1], so the token is never sent in clear to a remote host. Other URLs must be `https://`.; The extra CA (`RMM_AGENT_EXTRA_CA`) is honoured in debug builds only. `http_client` lives in core because `rmm-agent` has no `reqwest` dependency.; `rmm-agent-core` has no `tracing` dependency, so core code does not log. `connect_observed` reports `ConnState` events over a channel and `main.rs` logs them. `connect` is the plain wrapper with the plan's signature.
- **Open questions**: (none)
- **Conventions established**: Identity files are `identity.json` and `trust/{manifest,revocations,techlist}.env`, which are the raw envelope bytes. The key is `agent.key` in the state dir.; The server contract the agent assumes is `POST {server}/v1/enroll` with an `EnrollRequest` JSON body. 200 returns `EnrollResponse`; 401 means the token was rejected; any other status is a generic error.; The agent signs `EnrollRequest::signing_bytes()` with a plain Ed25519 signature, and the server should verify it with `verify_strict`.; The agent's NATS identity is the nkey user public key derived from the same Ed25519 seed, i.e. the `agent_pubkey` sent at enrollment. The auth callout can derive it with `nkeys::KeyPair::new_from_raw(User, ..)` or by encoding the 32-byte public key as a user nkey.; To build a release agent, set `RMM_ROOT_PUBKEYS` (comma-separated 32-byte hex keys) and optionally `RMM_ROOT_THRESHOLD`.

## Requirements Covered
- REQ-08
- REQ-10

## Token Usage
19 requests, 1070561 input tokens (996259 cached), 34248 output tokens, $0.7275
