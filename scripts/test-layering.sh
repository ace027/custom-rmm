#!/usr/bin/env bash
# Negative self-test for check-layering.sh, run on throwaway copies of the repo.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo/target}"
export CARGO_NET_OFFLINE=true

fresh_copy() { # dir
  mkdir -p "$1"
  tar -C "$repo" --exclude=./target --exclude=./.git -cf - . | tar -C "$1" -xf -
}

run_check() { (cd "$1" && ./scripts/check-layering.sh >"$1/out.txt" 2>&1); }
# A violation must be reported as a FAIL rule, not as a crash.
saw_fail() { grep -q '^FAIL ' "$1/out.txt"; }

# (a) server crate depends on rmm-platform
fresh_copy "$work/a"
sed -i '/^\[dependencies\]/a rmm-platform = { path = "../rmm-platform" }' "$work/a/crates/rmm-api/Cargo.toml"
if run_check "$work/a"; then echo "FAIL: server->platform violation not detected"; exit 1; fi
saw_fail "$work/a" || { echo "FAIL: no rule FAIL line for (a)"; exit 1; }
echo "PASS: server->platform violation detected"

# (b) agent-side crate enables rmm-trust sign
fresh_copy "$work/b"
sed -E -i 's#^rmm-trust(\.workspace)? = .*#rmm-trust = { workspace = true, features = ["sign"] }#' "$work/b/crates/rmm-agent-core/Cargo.toml"
grep -q 'features = \["sign"\]' "$work/b/crates/rmm-agent-core/Cargo.toml" \
  || { echo "FAIL: could not inject the sign feature into rmm-agent-core"; exit 1; }
if run_check "$work/b"; then echo "FAIL: agent sign violation not detected"; exit 1; fi
saw_fail "$work/b" || { echo "FAIL: no rule FAIL line for (b)"; exit 1; }
echo "PASS: agent sign violation detected"

# (d) server crate depends on rmm-platform (rmm-server)
fresh_copy "$work/d"
sed -i '/^\[dependencies\]/a rmm-platform = { path = "../rmm-platform" }' "$work/d/crates/rmm-server/Cargo.toml"
if run_check "$work/d"; then echo "FAIL: rmm-server->platform violation not detected"; exit 1; fi
saw_fail "$work/d" || { echo "FAIL: no rule FAIL line for (d)"; exit 1; }
echo "PASS: rmm-server->platform violation detected"

# (e) rmm-watchdog depends on tokio
fresh_copy "$work/e"
sed -i '/^\[dependencies\]/a tokio.workspace = true' "$work/e/crates/rmm-watchdog/Cargo.toml"
if run_check "$work/e"; then echo "FAIL: watchdog->tokio violation not detected"; exit 1; fi
saw_fail "$work/e" || { echo "FAIL: no rule FAIL line for (e)"; exit 1; }
echo "PASS: watchdog->tokio violation detected"

# (c) unmodified copy passes
fresh_copy "$work/c"
if ! run_check "$work/c"; then echo "FAIL: clean copy rejected"; exit 1; fi
echo "PASS: clean copy accepted"
