# Continuous integration

Workflow: `.github/workflows/ci.yml`. It runs on pull requests and on pushes to `main`, uses read-only permissions (`contents: read`) and needs no secrets, so fork PRs run the same jobs. A newer run on the same ref cancels the older one.

## Jobs

| Job | Runner | Purpose | Commands |
| --- | --- | --- | --- |
| lint | ubuntu-24.04 | Formatting, lints, licences/advisories, crate layering, API spec drift | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo deny check`; `scripts/check-layering.sh`; `scripts/test-layering.sh`; `cargo run -q -p xtask -- openapi --check` |
| windows-cross | ubuntu-24.04 | Agent-side crates compile and lint cleanly for Windows | `cargo xwin clippy` and `cargo xwin build` for x86_64-pc-windows-msvc; `cargo xwin check` for aarch64-pc-windows-msvc |
| test-linux | ubuntu-24.04 | Unit tests, dev-stack smoke test, sqlx offline data check | `cargo test --workspace --locked`; `scripts/smoke-dev.sh` (port 8443); `cargo sqlx prepare --workspace --check` |
| test-windows | windows-2025 | Native tests of the agent-side crates | `cargo test --locked -p ...`; `cargo build --locked -p rmm-agent` |

test-linux prints `docker compose logs` on failure and always runs `docker compose down -v`.

Artifacts: `openapi` (docs/openapi.json) from lint and `rmm-agent-windows-x64` (rmm-agent.exe) from windows-cross.

## Layering rules

`scripts/check-layering.sh` prints one PASS or FAIL line per rule and exits 1 on any FAIL:

- rmm-db, rmm-api and rmm-server must not depend on rmm-platform or rmm-agent-core.
- rmm-agent, rmm-agent-core, rmm-watchdog and rmm-session must not enable the `sign` feature of rmm-trust.
- rmm-watchdog must not depend on tokio.
- rmm-proto, rmm-trust and rmm-recipe must not depend on rmm-platform.

A FAIL line names the crate and the forbidden dependency. Inspect it with `cargo tree -p <crate> -e normal,build --target all --prefix none`, or for the sign rule `cargo tree -p <crate> -e features --target all -i rmm-trust`. `scripts/test-layering.sh` proves the checker detects violations.

## cargo-xwin cache

windows-cross caches `~/.cache/cargo-xwin` (the Windows SDK and CRT, about 1.5 GB). The key is `cargo-xwin-<cargo-xwin version>-<hash of rust-toolchain.toml>-xwin-v1`. A miss still succeeds: cargo-xwin downloads the SDK again. Bump the `xwin-v1` suffix to force a refresh.

## Reproducing locally

```sh
scripts/ci-local.sh lint
scripts/ci-local.sh windows-cross
scripts/ci-local.sh test-linux   # needs Docker; honours RMM_HTTPS_PORT (default 8443)
scripts/ci-local.sh              # all three
```

Required tools: cargo-deny, cargo-xwin (with clang and lld), sqlx-cli, Docker. `XWIN_ACCEPT_LICENSE=1` is set by the script. The test-linux subcommand tears the stack down in an exit trap.

test-windows is only exercised on GitHub; it cannot be reproduced on Linux.
