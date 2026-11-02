#!/usr/bin/env bash
# Reproduce the Linux CI jobs locally, in the same order as .github/workflows/ci.yml.
# Usage: scripts/ci-local.sh [lint|windows-cross|test-linux|all]
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-always}
export SQLX_OFFLINE=true
export XWIN_ACCEPT_LICENSE=${XWIN_ACCEPT_LICENSE:-1}

run() { echo "+ $*"; "$@"; }

job_lint() {
  run cargo fmt --all --check
  run cargo clippy --workspace --all-targets --locked -- -D warnings
  run cargo deny check
  run scripts/check-layering.sh
  run scripts/test-layering.sh
  run cargo run -q -p xtask -- openapi --check
}

job_windows_cross() {
  run cargo xwin clippy --target x86_64-pc-windows-msvc \
    -p rmm-proto -p rmm-trust -p rmm-recipe -p rmm-platform -p rmm-agent-core \
    -p rmm-agent -p rmm-watchdog -p rmm-session -p rmm-sign \
    --all-targets --locked -- -D warnings
  # rmm-agent is built alone so the `sign` feature of rmm-sign is not unified in.
  run cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked
  run cargo xwin build --target x86_64-pc-windows-msvc \
    -p rmm-watchdog -p rmm-session -p rmm-sign --locked
  run scripts/check-agent-no-sign.sh
  # The aarch64 Windows check runs only in CI's test-windows job (native MSVC).
  test -f target/x86_64-pc-windows-msvc/debug/rmm-agent.exe
}

job_test_linux() {
  export RMM_HTTPS_PORT=${RMM_HTTPS_PORT:-8443}
  trap 'docker compose -f deploy/compose.yaml down -v' EXIT
  local pw
  pw=$(sed -n 's/^RMM_PG_PASSWORD=//p' deploy/.env.example)
  # Database-backed tests (#[sqlx::test]) need the stack, so start it first.
  if ! run scripts/smoke-dev.sh; then
    docker compose -f deploy/compose.yaml logs --no-color || true
    exit 1
  fi
  DATABASE_URL="postgres://rmm:${pw}@localhost:5432/rmm" run cargo test --workspace --locked
  if ! run scripts/e2e-enroll.sh; then
    docker compose -f deploy/compose.yaml logs --no-color || true
    exit 1
  fi
  if ! run scripts/e2e-telemetry.sh; then
    docker compose -f deploy/compose.yaml logs --no-color || true
    exit 1
  fi
  if ! run scripts/e2e-offline.sh; then
    docker compose -f deploy/compose.yaml logs --no-color || true
    exit 1
  fi
  if ! run scripts/e2e-actions.sh; then
    docker compose -f deploy/compose.yaml logs --no-color || true
    exit 1
  fi
  if ! run scripts/e2e-shell.sh; then
    docker compose -f deploy/compose.yaml logs --no-color || true
    exit 1
  fi
  if ! run scripts/e2e-update.sh; then
    docker compose -f deploy/compose.yaml logs --no-color || true
    exit 1
  fi
  DATABASE_URL="postgres://rmm:${pw}@localhost:5432/rmm" SQLX_OFFLINE=false \
    run cargo sqlx prepare --workspace --check
}

case "${1:-all}" in
  lint) job_lint ;;
  windows-cross) job_windows_cross ;;
  test-linux) job_test_linux ;;
  all) job_lint; job_windows_cross; job_test_linux ;;
  *) echo "usage: $0 [lint|windows-cross|test-linux|all]" >&2; exit 2 ;;
esac
