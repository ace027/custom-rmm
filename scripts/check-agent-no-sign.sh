#!/usr/bin/env bash
# Prove at binary level that the agent contains no signing code.
#
# rmm-trust's `sign` module carries the marker RMM_TRUST_SIGN_MODULE_PRESENT.
# The agent is built on its own (so the sign feature enabled by rmm-sign is not
# unified in) for Linux and Windows and the binaries are searched for it.
# rmm-sign is built last as a positive control: its binary must contain the
# marker, otherwise this check could not detect anything.
# Usage: scripts/check-agent-no-sign.sh
set -euo pipefail
cd "$(dirname "$0")/.."

MARKER=RMM_TRUST_SIGN_MODULE_PRESENT
export XWIN_ACCEPT_LICENSE=${XWIN_ACCEPT_LICENSE:-1}

has_marker() { # file
  local n
  n=$(grep -a -c "$MARKER" "$1" || true)
  [ "${n:-0}" -gt 0 ]
}

fail=0
check_absent() { # file
  if [ ! -f "$1" ]; then
    echo "FAIL $1 was not built"
    fail=1
  elif has_marker "$1"; then
    echo "FAIL $1 contains $MARKER"
    fail=1
  else
    echo "PASS $1 has no signing code"
  fi
}

linux_agent=target/debug/rmm-agent
windows_agent=target/x86_64-pc-windows-msvc/debug/rmm-agent.exe
signer=target/debug/rmm-sign

# Remove stale binaries so that only the isolated builds below are inspected.
rm -f "$linux_agent" "$windows_agent" "$signer"

echo "+ cargo build -p rmm-agent --locked"
cargo build -p rmm-agent --locked
echo "+ cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked"
cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked

check_absent "$linux_agent"
check_absent "$windows_agent"

echo "+ cargo build -p rmm-sign --locked"
cargo build -p rmm-sign --locked
if [ -f "$signer" ] && has_marker "$signer"; then
  echo "PASS $signer contains $MARKER (the check can detect signing code)"
else
  echo "FAIL $signer lacks $MARKER; the check is not trustworthy"
  fail=1
fi

exit "$fail"
