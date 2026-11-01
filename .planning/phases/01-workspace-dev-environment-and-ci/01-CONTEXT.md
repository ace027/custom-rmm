# Phase 1: Workspace, dev environment and CI -- Context

## Phase Goal
A compiling workspace skeleton with all 12 crates, enforced layering, a healthy docker compose stack and green CI including Windows cross-compile

## Requirements Covered
- REQ-01
- REQ-02
- REQ-03
- REQ-23

## What Already Exists (from prior phases)
- Nothing: the repo holds only README.md, 'RMM Platform Spec.md', 'RMM Technician Console.html' and .planning/
- Design source of truth: .planning/explorations/2026-10-31-rmm-backend-phase1-design.md (Technical Direction: workspace layout, dev environment, CI)

## Key Design Decisions
- Rust toolchain pinned to 1.97.0, edition 2024, resolver 3; targets x86_64-pc-windows-msvc and aarch64-pc-windows-msvc listed in rust-toolchain.toml
- rustls everywhere; openssl, openssl-sys and native-tls are banned in deny.toml so Windows cross-compile stays clean
- Workspace lints: unsafe_code = forbid; rmm-platform is the only crate with its own [lints] table allowing unsafe, with clippy::undocumented_unsafe_blocks = deny
- Dependency direction: proto <- trust <- recipe; platform standalone; agent-core uses proto, trust, recipe, platform; server-side crates (rmm-db, rmm-api, rmm-server) never depend on rmm-platform or rmm-agent-core; agent-side crates never enable rmm-trust feature 'sign'; rmm-watchdog never depends on tokio. Enforced by scripts/check-layering.sh with a negative self-test
- Phase 1 NATS config uses static accounts/users (RMM, SYS) with JetStream and WebSocket; the auth_callout block is added in phase 3 when authd can sign JWTs
- Dev TLS: self-signed dev CA from scripts/dev-certs.sh (openssl), nginx terminates TLS on host port ${RMM_HTTPS_PORT:-443}
- Server image: multi-stage rust:1.97.0-bookworm -> debian:bookworm-slim, non-root user, SQLX_OFFLINE=true; healthchecks use a built-in `rmm-server healthcheck <url>` subcommand (no curl in image)
- OpenAPI: rmm-api exposes utoipa ApiDoc; `rmm-server openapi` prints it; docs/openapi.json is committed and `cargo run -p xtask -- openapi --check` fails on drift; CI uploads it as an artifact
- Board quick-assess and architecture proposals skipped by user (design already settles the layout)
- Docker images verified to exist: rust:1.97.0-bookworm, timescale/timescaledb:latest-pg17, nats:2.11-alpine, nginx:1.27-alpine, debian:bookworm-slim

## Plan Structure
- **Plan 01-01 (Wave 1)**: Workspace skeleton, layering and Windows cross-build -- Create the Cargo workspace with all 12 crates plus xtask, pinned toolchain, lints, cargo-deny and an enforced layering check; agent-side crates build for x86_64-pc-windows-msvc with cargo-xwin; the OpenAPI spec is exported and drift-checked; the spec moves to docs/spec.md.
- **Plan 01-02 (Wave 2)**: Docker compose dev environment and server stubs -- Bring up Timescale, NATS (JetStream + WebSocket), nginx TLS on 443 and the api/ingest/authd/migrate server processes with health checks, plus the first migration and committed sqlx offline data.
- **Plan 01-03 (Wave 3)**: GitHub Actions CI -- Add the CI workflow with lint, windows-cross, test-linux (including the dev-stack smoke test and sqlx check) and test-windows jobs, lint it with actionlint, and provide a local runner that reproduces the Linux jobs.
