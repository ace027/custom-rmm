#!/usr/bin/env bash
# MANUAL hardware check (not run in CI): a YubiKey 5 OpenPGP Ed25519 signature
# with touch must verify in rmm-trust.
#
# Requirements: a YubiKey 5 holding an Ed25519 key in the OpenPGP signature
# slot with touch policy `fixed` (see docs/runbooks/yubikey-setup.md), pcscd
# running, and the card user PIN.
#
# Usage: scripts/yubikey-smoke.sh [card-ident]
# Environment: RMM_CARD_PIN (otherwise prompted), RMM_SIGN_BIN (default: built
# from this checkout).
set -euo pipefail
cd "$(dirname "$0")/.."

ident=${1:-}
backend=card${ident:+:$ident}

if [ -n "${RMM_SIGN_BIN:-}" ]; then
  sign=$RMM_SIGN_BIN
else
  cargo build -p rmm-sign --locked
  sign=target/debug/rmm-sign
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Throwaway root: never a real key, passphrase only lives in this process.
RMM_SIGN_PASSPHRASE=$(head -c 24 /dev/urandom | base64)
export RMM_SIGN_PASSPHRASE

field() { awk -v k="$1:" '$1 == k { print $2 }'; }

echo "== card public key"
card_out=$("$sign" pubkey --backend "$backend")
echo "$card_out"
card_pub=$(field public_key <<<"$card_out")
card_id=$(field key_id <<<"$card_out")

echo "== throwaway root"
root_out=$("$sign" keygen-root --out "$tmp/root.age")
root_pub=$(field public_key <<<"$root_out")

now=$(date +%s)
from=$((now - 60))
until=$((now + 30 * 86400))

cat >"$tmp/manifest.json" <<JSON
{
  "seq": 1,
  "issued_at": $from,
  "expires_at": $until,
  "root_keys": ["$root_pub"],
  "root_threshold": 1,
  "certs": [{
    "key_id": "$card_id",
    "pubkey": "$card_pub",
    "alg": "ed25519",
    "roles": ["techlist"],
    "not_before": $from,
    "not_after": $until,
    "label": "yubikey smoke test"
  }],
  "thresholds": {"techlist": 1},
  "revoked_keys": [],
  "console_rp_id": "smoke.invalid",
  "console_origins": ["https://smoke.invalid"],
  "capability_ceiling": [],
  "revocation_mirrors": []
}
JSON

cat >"$tmp/techlist.json" <<JSON
{
  "seq": 1,
  "issued_at": $from,
  "expires_at": $until,
  "techs": [{"tech_id": "smoke", "client_scope": ["*"], "perms": [], "creds": []}]
}
JSON

echo "== sign manifest with the throwaway root"
"$sign" sign --type manifest --in "$tmp/manifest.json" \
  --backend "file:$tmp/root.age" --out "$tmp/manifest.env" --yes

echo "== sign techlist with the card (touch the key when it blinks)"
"$sign" sign --type techlist --in "$tmp/techlist.json" \
  --backend "$backend" --expect-key-id "$card_id" --out "$tmp/techlist.env" --yes

echo "== verify"
"$sign" verify --roots "$root_pub" --root-threshold 1 \
  --manifest "$tmp/manifest.env" --now "$now" "$tmp/techlist.env" >"$tmp/verify.txt"
grep -q "signer: $card_id" "$tmp/verify.txt"

echo "PASS key_id=$card_id"
