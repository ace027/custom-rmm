#!/usr/bin/env bash
# Bootstrap the dev trust chain with rmm-sign (file backend, throwaway keys).
#
# Creates under deploy/dev/trust (gitignored):
#   root.age, catalog.age   age-encrypted keys, passphrase "dev-only"
#   command.seed            the API's online command key (hex seed)
#   manifest.env            root-signed manifest: catalog key (catalog,
#                           artifact-revoke, techlist), command key (command),
#                           capability ceiling [service, files.write]
#   revocations.env         catalog-signed, empty, 45-day expiry
#   printing.spooler-restart.env   catalog-signed spooler definition
# and, next to it, for the dev co-signed shell:
#   deploy/dev/webauthn     dev FIDO attestation root + AAGUID of the fake
#                           authenticator (cargo run -p xtask -- fake-authn ca);
#                           the API container mounts it read-only. Dev only.
#   deploy/dev/recordings   where the API container writes shell recordings
# and prints ROOT_PUBKEYS=<hex> on stdout (everything else goes to stderr).
#
# Idempotent: keys are created once and nothing is re-signed unless --force.
# Sequence numbers are nanosecond timestamps so a re-sign always supersedes
# whatever the dev database already stores.
set -euo pipefail
cd "$(dirname "$0")/.."

force=
case "${1:-}" in
  --force) force=1 ;;
  "") ;;
  *) echo "usage: $0 [--force]" >&2; exit 2 ;;
esac

dir=deploy/dev/trust
export RMM_SIGN_PASSPHRASE=dev-only
sign() { cargo run -q --locked -p rmm-sign -- "$@"; }
log() { echo "dev-trust: $*" >&2; }

mkdir -p "$dir"
chmod 755 "$dir"

# Key id and public key of an age key file.
pubkey_of() { sign pubkey --backend "file:$1"; }
field() { sed -n "s/^$1: //p" <<<"$2"; }

if [[ ! -f $dir/root.age ]]; then
  sign keygen-root --out "$dir/root.age" >/dev/null 2>&1
  log "created root key"
fi
if [[ ! -f $dir/catalog.age ]]; then
  sign keygen-root --out "$dir/catalog.age" >/dev/null 2>&1
  log "created catalog key"
fi
if [[ ! -f $dir/command.seed ]]; then
  out=$(sign keygen-command --out "$dir/command.seed" 2>/dev/null)
  printf '%s\n' "$out" >"$dir/command.pub"
  # The API container runs as uid 10001. Keep 0600 by handing the file to that
  # uid when we can; otherwise (dev, non-root) make it world-readable.
  if [[ $(id -u) -eq 0 ]]; then
    chown 10001:10001 "$dir/command.seed"
    chmod 600 "$dir/command.seed"
  else
    chmod 644 "$dir/command.seed"
    log "command.seed is mode 0644 (not root, cannot chown to uid 10001); dev only"
  fi
  log "created command key"
fi
[[ -f $dir/command.pub ]] || { echo "error: $dir/command.pub missing; remove $dir/command.seed and rerun" >&2; exit 1; }

# Dev fake authenticator CA (idempotent) and the recordings directory. The API
# container runs as uid 10001 and must be able to write the latter; both live
# under the gitignored deploy/dev and are never used outside dev.
web=deploy/dev/webauthn
cargo run -q --locked -p xtask -- fake-authn ca --out "$web" >/dev/null
chmod 755 "$web"
mkdir -p deploy/dev/recordings
chmod 777 deploy/dev/recordings

root=$(pubkey_of "$dir/root.age")
cat=$(pubkey_of "$dir/catalog.age")
root_pub=$(field public_key "$root")
cat_pub=$(field public_key "$cat")
cat_id=$(field key_id "$cat")
cmd_pub=$(sed -n 's/^public=//p' "$dir/command.pub")
cmd_id=$(sed -n 's/^key_id=//p' "$dir/command.pub")
[[ -n $root_pub && -n $cat_pub && -n $cmd_pub && -n $cmd_id ]] || { echo "error: cannot read key material" >&2; exit 1; }

if [[ -z $force && -f $dir/manifest.env && -f $dir/revocations.env && -f $dir/printing.spooler-restart.env ]]; then
  log "trust documents already signed (use --force to re-sign)"
  echo "ROOT_PUBKEYS=$root_pub"
  exit 0
fi

seq=$(date +%s%N)
now=$(date +%s)
day=86400
cat >"$dir/manifest.json" <<JSON
{
  "seq": $seq,
  "issued_at": $((now - 60)),
  "expires_at": $((now + 90 * day)),
  "root_keys": ["$root_pub"],
  "root_threshold": 1,
  "certs": [
    {
      "key_id": "$cat_id",
      "pubkey": "$cat_pub",
      "alg": "ed25519",
      "roles": ["catalog", "artifact-revoke", "techlist"],
      "not_before": $((now - 60)),
      "not_after": $((now + 90 * day)),
      "label": "dev catalog key"
    },
    {
      "key_id": "$cmd_id",
      "pubkey": "$cmd_pub",
      "alg": "ed25519",
      "roles": ["command"],
      "not_before": $((now - 60)),
      "not_after": $((now + 90 * day)),
      "label": "dev command key"
    }
  ],
  "thresholds": {"catalog": 1, "artifact-revoke": 1, "techlist": 1, "command": 1},
  "revoked_keys": [],
  "console_rp_id": "localhost",
  "console_origins": ["https://localhost"],
  "capability_ceiling": ["service", "files.write"],
  "revocation_mirrors": []
}
JSON
cat >"$dir/revocations.json" <<JSON
{
  "seq": $seq,
  "issued_at": $((now - 60)),
  "expires_at": $((now + 45 * day)),
  "revoked_hashes": []
}
JSON

sign sign --type manifest --in "$dir/manifest.json" --backend "file:$dir/root.age" \
  --out "$dir/manifest.env" --yes --force >/dev/null 2>&1
sign sign --type revocations --in "$dir/revocations.json" --backend "file:$dir/catalog.age" \
  --out "$dir/revocations.env" --yes --force >/dev/null 2>&1
sign sign --type definition --in catalog/printing.spooler-restart.json --backend "file:$dir/catalog.age" \
  --out "$dir/printing.spooler-restart.env" --yes --force >/dev/null 2>&1
log "signed manifest, revocations and printing.spooler-restart (seq $seq)"
echo "ROOT_PUBKEYS=$root_pub"
