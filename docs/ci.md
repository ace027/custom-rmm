# Continuous integration

Workflow: `.github/workflows/ci.yml`. It runs on pull requests and on pushes to `main`, uses read-only permissions (`contents: read`) and needs no secrets, so fork PRs run the same jobs. A newer run on the same ref cancels the older one.

## Jobs

| Job | Runner | Purpose | Commands |
| --- | --- | --- | --- |
| lint | ubuntu-24.04 | Formatting, lints, licences/advisories, crate layering, API spec drift | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo deny check`; `scripts/check-layering.sh`; `scripts/test-layering.sh`; `cargo run -q -p xtask -- openapi --check` |
| windows-cross | ubuntu-24.04 | Agent-side crates compile and lint cleanly for Windows | `cargo xwin clippy` for x86_64-pc-windows-msvc; `cargo xwin build` of rmm-agent alone, then of the other crates; `scripts/check-agent-no-sign.sh` |
| test-linux | ubuntu-24.04 | Unit tests, dev-stack smoke test, sqlx offline data check | `cargo test --workspace --locked`; `scripts/smoke-dev.sh` (port 8443); `cargo sqlx prepare --workspace --check` |
| test-windows | windows-2025 | Native tests of the agent-side crates | `cargo test --locked -p ...`; `cargo build --locked -p rmm-agent`; `cargo build --locked -p rmm-sign`; `cargo check` for aarch64-pc-windows-msvc (cargo-xwin cannot build ring/aws-lc-sys aarch64 assembly from Linux) |

lint, windows-cross and test-linux first run `apt-get install libpcsclite-dev pkg-config`: rmm-sign's default `card` feature links the PC/SC library (`pcsc-sys`) on Linux. Windows uses the system WinSCard and needs nothing extra. Locally, install `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (Fedora), or build with `--no-default-features` to leave the card backend out.

test-linux prints `docker compose logs` on failure and always runs `docker compose down -v`.

Artifacts: `openapi` (docs/openapi.json) from lint and `rmm-agent-windows-x64` (rmm-agent.exe) from windows-cross.

## Layering rules

`scripts/check-layering.sh` prints one PASS or FAIL line per rule and exits 1 on any FAIL:

- rmm-db, rmm-api and rmm-server must not depend on rmm-platform or rmm-agent-core.
- rmm-agent, rmm-agent-core, rmm-watchdog and rmm-session must not enable the `sign` feature of rmm-trust.
- rmm-watchdog must not depend on tokio.
- rmm-proto, rmm-trust and rmm-recipe must not depend on rmm-platform.

A FAIL line names the crate and the forbidden dependency. Inspect it with `cargo tree -p <crate> -e normal,build --target all --prefix none`, or for the sign rule `cargo tree -p <crate> -e features --target all -i rmm-trust`. `scripts/test-layering.sh` proves the checker detects violations.

## Agent contains no signing code

Signing lives in rmm-trust behind the `sign` feature, enabled only by rmm-sign. `scripts/check-agent-no-sign.sh` proves at binary level that the agent does not contain it:

1. It deletes old binaries, then builds `rmm-agent` alone for Linux (`cargo build -p rmm-agent --locked`) and for `x86_64-pc-windows-msvc` (`cargo xwin build ... -p rmm-agent --locked`). Building the agent alone matters: in a multi-package build Cargo unifies features and rmm-trust would be compiled with `sign` for the agent too.
2. It fails if `target/debug/rmm-agent` or `target/x86_64-pc-windows-msvc/debug/rmm-agent.exe` contains the string `RMM_TRUST_SIGN_MODULE_PRESENT`, the `#[used]` marker static of `rmm_trust::sign`.
3. As a positive control it builds `rmm-sign` and fails if that binary does not contain the marker, which proves the search can find signing code.

The script prints one PASS or FAIL line per binary and exits 1 on any FAIL. It runs in the windows-cross job (needs cargo-xwin, libpcsclite-dev) and in `scripts/ci-local.sh windows-cross`. It complements the dependency-level `sign` rule in `scripts/check-layering.sh`.

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
