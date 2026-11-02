#!/usr/bin/env bash
# Enforce crate layering rules. Exits 1 if any rule fails.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
report() { # status message
  printf '%s %s\n' "$1" "$2"
  if [ "$1" = FAIL ]; then fail=1; fi
}

required="rmm-proto rmm-trust rmm-recipe rmm-platform rmm-agent-core rmm-agent rmm-watchdog rmm-session rmm-db rmm-api rmm-server rmm-sign"
members=$(cargo metadata --format-version 1 --no-deps | python3 -c \
  'import json,sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))')
for c in $required; do
  if grep -qx "$c" <<<"$members"; then
    report PASS "crate $c exists in workspace"
  else
    report FAIL "crate $c missing from cargo metadata"
  fi
done
[ "$fail" -eq 0 ] || exit 1

tree() { cargo tree -p "$1" -e normal,build --target all --prefix none "${@:2}"; }

for c in rmm-db rmm-api rmm-server; do
  out=$(tree "$c")
  if grep -qE '^(rmm-platform|rmm-agent-core) ' <<<"$out"; then
    report FAIL "$c must not depend on rmm-platform or rmm-agent-core"
  else
    report PASS "$c does not depend on rmm-platform or rmm-agent-core"
  fi
done

for c in rmm-agent rmm-agent-core rmm-watchdog rmm-session; do
  if ! out=$(cargo tree -p "$c" -e features --target all -i rmm-trust 2>&1); then
    if grep -q 'did not match any packages' <<<"$out"; then
      out=""   # crate does not depend on rmm-trust at all
    else
      report FAIL "cargo tree failed for $c: $out"
      continue
    fi
  fi
  if grep -q 'feature "sign"' <<<"$out"; then
    report FAIL "$c enables rmm-trust feature sign"
  else
    report PASS "$c does not enable rmm-trust feature sign"
  fi
done

# The watchdog must survive a bad agent build: no async runtime, no network.
wd_tree=$(cargo tree -p rmm-watchdog --target all --prefix none)
for dep in tokio reqwest async-nats hyper; do
  if grep -qE "^$dep " <<<"$wd_tree"; then
    report FAIL "rmm-watchdog must not depend on $dep"
  else
    report PASS "rmm-watchdog does not depend on $dep"
  fi
done

for c in rmm-proto rmm-trust rmm-recipe; do
  if tree "$c" | grep -qE '^rmm-platform '; then
    report FAIL "$c must not depend on rmm-platform"
  else
    report PASS "$c does not depend on rmm-platform"
  fi
done

# deny.toml ignores two advisories that only `age` brings in; keep it off endpoints.
for c in rmm-agent rmm-agent-core rmm-watchdog rmm-session; do
  if tree "$c" | grep -qE '^age '; then
    report FAIL "$c must not depend on age"
  else
    report PASS "$c does not depend on age"
  fi
done

exit "$fail"
