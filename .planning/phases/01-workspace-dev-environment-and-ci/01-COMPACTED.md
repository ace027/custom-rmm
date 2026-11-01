---
phase: 01-workspace-dev-environment-and-ci
compacted: 2026-10-31
original_summaries: [01-01-SUMMARY.md, 01-02-SUMMARY.md, 01-03-SUMMARY.md]
requirements_satisfied: [REQ-01, REQ-23, REQ-02, REQ-03]
---

# Phase 1: Workspace, dev environment and CI — Compacted Summary

## Deliverables
- 01-01 Workspace skeleton, layering and Windows cross-build (Complete): .gitignore, Cargo.lock, Cargo.toml, README.md, clippy.toml, crates/rmm-agent-core/Cargo.toml, crates/rmm-agent-core/src/lib.rs, crates/rmm-agent/Cargo.toml, crates/rmm-agent/src/main.rs, crates/rmm-api/Cargo.toml, crates/rmm-api/src/lib.rs, crates/rmm-db/Cargo.toml, crates/rmm-db/src/lib.rs, crates/rmm-platform/Cargo.toml, crates/rmm-platform/src/lib.rs, crates/rmm-platform/src/linux.rs, crates/rmm-platform/src/macos.rs, crates/rmm-platform/src/windows.rs, crates/rmm-proto/Cargo.toml, crates/rmm-proto/src/lib.rs, crates/rmm-recipe/Cargo.toml, crates/rmm-recipe/src/lib.rs, crates/rmm-server/Cargo.toml, crates/rmm-server/src/main.rs, crates/rmm-session/Cargo.toml, crates/rmm-session/src/main.rs, crates/rmm-sign/Cargo.toml, crates/rmm-sign/src/main.rs, crates/rmm-trust/Cargo.toml, crates/rmm-trust/src/lib.rs, crates/rmm-trust/src/sign.rs, crates/rmm-trust/src/verify.rs, crates/rmm-watchdog/Cargo.toml, crates/rmm-watchdog/src/main.rs, deny.toml, docs/openapi.json, docs/spec.md, rust-toolchain.toml, rustfmt.toml, scripts/check-layering.sh, scripts/test-layering.sh, xtask/Cargo.toml, xtask/src/main.rs
- 01-02 Docker compose dev environment and server stubs (Complete): .dockerignore, .sqlx/query-f61dc00355ecce647118e4a86632d0d38741871a17a7737e24fc1d53428323c9.json, Cargo.lock, Cargo.toml, crates/rmm-db/Cargo.toml, crates/rmm-db/migrations/0001_init.sql, crates/rmm-db/src/lib.rs, crates/rmm-server/Cargo.toml, crates/rmm-server/src/main.rs, deploy/.env.example, deploy/compose.yaml, deploy/nats/nats.conf, deploy/nginx/nginx.conf, deploy/server.Dockerfile, docs/dev-environment.md, scripts/dev-certs.sh, scripts/dev-up.sh, scripts/smoke-dev.sh
- 01-03 GitHub Actions CI (Complete)

## Decisions
- 01-01: Workspace-wide `cargo build` unifies features, so `rmm-trust` gets `sign` there because `rmm-sign` is a member. The sign rule is checked per package with `cargo
- 01-01: Dependency versions not given in the plan: async-nats 0.42, windows 0.62, thiserror 2, tower 0.5 (util, dev-dependency of `rmm-api`). tower is needed for the `o
- 01-01: `rmm-server healthcheck <url>` is a minimal std TCP client for `http://` URLs only. The plan lists the subcommand but not its behaviour.
- 01-02: Compose v5 routes builds through buildx bake, which refuses `network: host` and the CA secret file without `--allow` flags. `COMPOSE_BAKE=false` had no effect.
- 01-02: `dev-up.sh` therefore runs `docker build --network host --secret id=extra_ca ...` itself, then `compose up -d --wait`. The compose `build:` block stays for docu
- 01-02: `pull_policy: never` is set on the server services so compose does not try to pull `rmm-server:dev`.
- 01-03: The sqlx check step sets SQLX_OFFLINE=false and builds DATABASE_URL from RMM_PG_PASSWORD in deploy/.env.example, using localhost:5432.
- 01-03: The xwin cache key is cargo-xwin-<version>-<hash of rust-toolchain.toml>-xwin-v1.

## Conventions and Open Questions
- 01-01 convention: The first toolchain use ran rustup and downloaded 1.97.0 plus both Windows `rust-std` targets. CI needs network for that too.
- 01-01 convention: cargo-xwin needs `XWIN_ACCEPT_LICENSE=1` in non-interactive runs, and clang and lld-link, which are present on this box. CI will need them as well.
- 01-01 convention: Regenerate the spec with `cargo run -p xtask -- openapi` whenever `rmm-api` routes change. The xtask shells out to `cargo run -p rmm-server -- openapi`.
- 01-02 convention: `dev-up.sh` builds `rmm-server:dev` outside compose. CI's test-linux job must do the same, or pass `--allow` to bake.
- 01-02 convention: Rerun `cargo sqlx prepare --workspace` against the running stack whenever queries change, then commit `.sqlx/`.
- 01-02 convention: `deploy/dev/` and `deploy/.env` are gitignored and created by `dev-up.sh`.
- 01-03 convention: Only the host's own checks were run. The "all four jobs green on GitHub" criterion needs a push.
- 01-03 convention: test-linux depends on scripts/smoke-dev.sh, which calls dev-up.sh. dev-up.sh builds rmm-server:dev with plain docker build, so the CI job needs no bake flags.

## Files Modified
| File | Change |
|------|--------|
| `.gitignore` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `Cargo.lock` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `README.md` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `clippy.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-agent-core/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-agent-core/src/lib.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-agent/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-agent/src/main.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-api/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-api/src/lib.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-db/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-db/src/lib.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-platform/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-platform/src/lib.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-platform/src/linux.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-platform/src/macos.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-platform/src/windows.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-proto/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-proto/src/lib.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-recipe/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-recipe/src/lib.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-server/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-server/src/main.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-session/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-session/src/main.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-sign/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-sign/src/main.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-trust/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-trust/src/lib.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-trust/src/sign.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-trust/src/verify.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-watchdog/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `crates/rmm-watchdog/src/main.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `deny.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `docs/openapi.json` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `docs/spec.md` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `rust-toolchain.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `rustfmt.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `scripts/check-layering.sh` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `scripts/test-layering.sh` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `xtask/Cargo.toml` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `xtask/src/main.rs` | 01-01: Workspace skeleton, layering and Windows cross-build |
| `.dockerignore` | 01-02: Docker compose dev environment and server stubs |
| `.sqlx/query-f61dc00355ecce647118e4a86632d0d38741871a17a7737e24fc1d53428323c9.json` | 01-02: Docker compose dev environment and server stubs |
| `Cargo.lock` | 01-02: Docker compose dev environment and server stubs |
| `Cargo.toml` | 01-02: Docker compose dev environment and server stubs |
| `crates/rmm-db/Cargo.toml` | 01-02: Docker compose dev environment and server stubs |
| `crates/rmm-db/migrations/0001_init.sql` | 01-02: Docker compose dev environment and server stubs |
| `crates/rmm-db/src/lib.rs` | 01-02: Docker compose dev environment and server stubs |
| `crates/rmm-server/Cargo.toml` | 01-02: Docker compose dev environment and server stubs |
| `crates/rmm-server/src/main.rs` | 01-02: Docker compose dev environment and server stubs |
| `deploy/.env.example` | 01-02: Docker compose dev environment and server stubs |
| `deploy/compose.yaml` | 01-02: Docker compose dev environment and server stubs |
| `deploy/nats/nats.conf` | 01-02: Docker compose dev environment and server stubs |
| `deploy/nginx/nginx.conf` | 01-02: Docker compose dev environment and server stubs |
| `deploy/server.Dockerfile` | 01-02: Docker compose dev environment and server stubs |
| `docs/dev-environment.md` | 01-02: Docker compose dev environment and server stubs |
| `scripts/dev-certs.sh` | 01-02: Docker compose dev environment and server stubs |
| `scripts/dev-up.sh` | 01-02: Docker compose dev environment and server stubs |
| `scripts/smoke-dev.sh` | 01-02: Docker compose dev environment and server stubs |

## Verification
- 01-01 (REQ-01, REQ-23): 17/17 verification commands passed
- 01-02 (REQ-02): 13/13 verification commands passed
- 01-03 (REQ-03, REQ-23): 10/10 verification commands passed

## Agents
- 01-01: engineering-backend-architect
- 01-02: engineering-infrastructure-devops
- 01-03: engineering-infrastructure-devops

## Also Covered
- RMM Platform Spec.md
- .github/workflows/ci.yml
- scripts/ci-local.sh
- docs/ci.md
