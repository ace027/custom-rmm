#!/usr/bin/env bash
# End-to-end A/B update against the dev stack. A debug Linux agent built as
# 0.1.0 is the watchdog's bootstrap agent; a second build (0.1.1) is the
# release artifact. rmm-watchdog supervises the agent in a private mount
# namespace with a fake /sys/class/dmi (same conventions as
# scripts/e2e-shell.sh). Releases are signed with the dev release key
# (deploy/dev/trust/release.age, rmm-sign file backend) and published through
# the API. The agent refreshes every 5 s (RMM_AGENT_REFRESH_INTERVAL_SECS,
# debug builds only).
#
# Checks:
#   (1) a signed 0.1.1 release is downloaded, staged, installed and promoted:
#       state.json shows active_version 0.1.1 within 120 s, health.json names
#       0.1.1 and the running agent's pid, and the server keeps receiving
#       heartbeats afterwards (last_seen advances; the server does not store
#       the agent version, so the version itself is read from health.json,
#       which the agent writes only after a heartbeat went out)
#   (2) a signed 0.1.2 whose artifact sleeps forever never reports healthy: the
#       watchdog rolls back to 0.1.1 within 60 s + 30 s of the install, puts
#       the hash into bad_hashes, and the agent does not stage it again
#   (3) a signed 0.1.0 release with a higher seq is skipped by the agent
#       (downgrade, nothing staged); planted directly in pending/ the watchdog
#       rejects it with downgrade
#   (4) a release whose stored artifact bytes differ from the signed hash is
#       rejected by the agent (hash_mismatch, no READY); a pending/ whose
#       artifact differs from the signed hash is rejected by the watchdog
#       (hash_mismatch)
#   (5) kill -9 of the agent child: the watchdog starts a new agent (new pid)
#       within 10 s
#
# (4) needs bytes the server would never serve: the stored artifact file is
# altered in deploy/dev/artifacts (same size) after it was uploaded. Needs
# root or passwordless sudo, docker, cargo, curl and python3. Dev and CI only.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=${RMM_HTTPS_PORT:-443}
export RMM_HTTPS_PORT=$PORT
COMPOSE=(docker compose -f deploy/compose.yaml)
CA=$ROOT/deploy/dev/certs/ca.pem
TRUST=$ROOT/deploy/dev/trust
ARTIFACTS=$ROOT/deploy/dev/artifacts
SERVER=https://localhost:$PORT
SUDO=()
[[ $(id -u) -eq 0 ]] || SUDO=(sudo)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/rmm-e2e-update.XXXXXX")
RDIR=$WORK/root       # the watchdog root
STATE=$WORK/state     # the agent state dir (also the watchdog's)
LOG=$WORK/run.log     # watchdog and agent stderr
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
BG_PID=
ADMIN=
UPLOADED=()
ROLLBACK_BUDGET=90    # 60 s health timeout + 30 s margin
PROMOTE_BUDGET=120
RESTART_BUDGET=10

q() {
  "${COMPOSE[@]}" exec -T timescale psql -U rmm -d rmm -v ON_ERROR_STOP=1 -tAq \
    -c "SET rmm.service = 'on'; $1"
}
curl_api() { curl -sS --noproxy '*' --cacert "$CA" "$@"; }
jget() { python3 -I -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[k]
print(v if v is not None else "")' "$@"; }
fail() { echo "FAIL $*" >&2; [[ ! -f $LOG ]] || tail -n 25 "$LOG" >&2; exit 1; }
pass() { echo "PASS $*"; }

wd_pid() { # the rmm-watchdog process of this run
  local p
  for p in $(pgrep -f "run --root $RDIR" || true); do
    [[ $(cat "/proc/$p/comm" 2>/dev/null) == rmm-watchdog ]] && { echo "$p"; return 0; }
  done
  return 1
}
child_pid() { # the agent: the watchdog's child
  local w
  w=$(wd_pid) || return 1
  pgrep -P "$w" | head -n 1
}
stop_all() {
  local w c
  if w=$(wd_pid); then
    for c in $(pgrep -P "$w" || true); do "${SUDO[@]}" kill -9 "$c" 2>/dev/null || true; done
    "${SUDO[@]}" kill -9 "$w" 2>/dev/null || true
  fi
  if [[ -n $BG_PID ]]; then
    wait "$BG_PID" 2>/dev/null || true
    BG_PID=
  fi
}
cleanup() {
  local rc=$?
  stop_all
  # Leave the dev database with a release no agent acts on, and no artifacts.
  if [[ -n $ADMIN && -n ${NEUTRAL_READY:-} ]]; then
    (publish_neutral) >/dev/null 2>&1 || true
  fi
  local h
  for h in "${UPLOADED[@]}"; do "${SUDO[@]}" rm -f "$ARTIFACTS/$h" 2>/dev/null || true; done
  "${SUDO[@]}" rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

scripts/dev-up.sh

# A stack started before deploy/nats/nats.conf allowed the svc.* request
# subjects keeps refusing the API's subscriptions: recreate it (fresh logs).
if "${COMPOSE[@]}" logs --no-color api 2>&1 | grep -q 'Permissions Violation for Subscription to "svc\.'; then
  echo "notice: running NATS predates nats.conf; recreating nats, api, authd and ingest" >&2
  "${COMPOSE[@]}" up -d --force-recreate nats api authd ingest
  "${COMPOSE[@]}" exec -T nginx nginx -s reload >/dev/null 2>&1 || true
  "${COMPOSE[@]}" up -d --wait
fi

ROOT_PUBKEYS=$(sed -n 's/^RMM_ROOT_PUBKEYS=//p' deploy/.env)
[[ -f $TRUST/release.age ]] || fail "no dev release key: run scripts/dev-trust.sh --force"
export RMM_ROOT_PUBKEYS=$ROOT_PUBKEYS

mkdir -p "$RDIR/bootstrap" "$STATE"
# Debug binaries are ~180 MB; stripped they are small enough to be copied a few
# times (and stay far below the 256 MiB artifact limit).
copy_agent() { # <src> <dest>
  if command -v strip >/dev/null; then strip -o "$2" "$1"; else cp "$1" "$2"; fi
  chmod 755 "$2"
}
# Two builds of the agent: 0.1.0 is the installed bootstrap, 0.1.1 the update.
RMM_AGENT_VERSION=0.1.0 cargo build -q --locked -p rmm-agent
copy_agent target/debug/rmm-agent "$RDIR/bootstrap/rmm-agent"
RMM_AGENT_VERSION=0.1.1 cargo build -q --locked -p rmm-agent
copy_agent target/debug/rmm-agent "$WORK/agent-0.1.1"
cargo build -q --locked -p rmm-watchdog
cargo build -q --locked -p rmm-sign
WATCHDOG=$ROOT/target/debug/rmm-watchdog
SIGN=$ROOT/target/debug/rmm-sign
BOOT=$RDIR/bootstrap/rmm-agent
[[ $("$BOOT" --version) == "rmm-agent 0.1.0" ]] || fail "bootstrap reports '$("$BOOT" --version)'"
[[ $("$WORK/agent-0.1.1" --version) == "rmm-agent 0.1.1" ]] || fail "update build reports '$("$WORK/agent-0.1.1" --version)'"

ADMIN=$("${COMPOSE[@]}" exec -T api rmm-server dev-token --role RMM.Admin --sub e2e-update-admin)
[[ -n $ADMIN ]] || fail "dev-token"

# ---------------------------------------------------------------- helpers

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

upload_artifact() { # <file>: sets UP_HASH to the sha256 the server computed
  local code
  code=$(curl_api -o "$WORK/up.json" -w '%{http_code}' -X POST "$SERVER/api/v1/admin/artifacts" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/octet-stream' --data-binary "@$1")
  [[ $code == 201 ]] || fail "upload $1: HTTP $code $(cat "$WORK/up.json")"
  UP_HASH=$(jget sha256_hex <"$WORK/up.json")
  [[ $UP_HASH == "$(sha_of "$1")" ]] || fail "server hash $UP_HASH differs from $(sha_of "$1")"
  UPLOADED+=("$UP_HASH")
}

# sign_release <name> <version> <sha256hex> <size>: signs with the dev release
# key into $WORK/<name>.env.
sign_release() {
  local now seq
  now=$(date +%s)
  seq=$(date +%s%N)
  cat >"$WORK/$1.json" <<JSON
{
  "seq": $seq,
  "version": "$2",
  "issued_at": $((now - 60)),
  "expires_at": $((now + 30 * 86400)),
  "artifacts": [
    {"platform": "$PLATFORM", "sha256": "$3", "size": $4, "name": "rmm-agent"}
  ]
}
JSON
  RMM_SIGN_PASSPHRASE=dev-only "$SIGN" sign --type release --in "$WORK/$1.json" \
    --backend "file:$TRUST/release.age" --out "$WORK/$1.env" --yes --force >/dev/null 2>"$WORK/sign.err" \
    || fail "sign release $1: $(cat "$WORK/sign.err")"
}
publish_env() { # <name>
  local code
  code=$(curl_api -o "$WORK/put.out" -w '%{http_code}' -X PUT "$SERVER/api/v1/trust/release" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/$1.env")
  [[ $code == 204 ]] || fail "publish release $1: HTTP $code $(cat "$WORK/put.out")"
}
# A release older than every agent: acted on by nobody, replaces the latest.
publish_neutral() {
  NEUTRAL_N=$((${NEUTRAL_N:-0} + 1))
  sign_release "neutral$NEUTRAL_N" 0.0.1 "$(printf '00%.0s' $(seq 1 32))" 1
  publish_env "neutral$NEUTRAL_N"
}
# release <name> <version> <file>: upload, sign and publish.
release() {
  upload_artifact "$3"
  REL_HASH=$UP_HASH
  sign_release "$1" "$2" "$REL_HASH" "$(stat -c %s "$3")"
  publish_env "$1"
}

# plant <release-env-name> <artifact-file>: a complete pending/ appears at once.
plant() {
  rm -rf "$WORK/plant"
  mkdir -p "$WORK/plant"
  cp "$TRUST/manifest.env" "$WORK/plant/manifest.env"
  cp "$WORK/$1.env" "$WORK/plant/release.env"
  cp "$2" "$WORK/plant/artifact"
  : >"$WORK/plant/READY"
  local i
  for i in $(seq 1 30); do
    mv -T "$WORK/plant" "$RDIR/pending" 2>/dev/null && return 0
    sleep 0.5
  done
  fail "could not place pending/"
}

plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$LOG"; }
log_count() { plain_log | grep -Ec -- "$1" || true; }
await_log() { # <regex> <seconds> <what>
  local deadline=$((SECONDS + $2))
  until plain_log | grep -Eq -- "$1"; do
    ((SECONDS < deadline)) || fail "$3: no log line matching '$1' after $2 s"
    sleep 0.5
  done
}
st() { python3 -I -c 'import json,sys
s=json.load(open(sys.argv[1]))
print(eval(sys.argv[2]))' "$RDIR/state.json" "$1" 2>/dev/null || true; }
await_state() { # <python-expr that must print True> <seconds> <what>
  local deadline=$((SECONDS + $2))
  until [[ $(st "$1") == True ]]; do
    ((SECONDS < deadline)) || fail "$3: state.json never satisfied '$1' in $2 s: $(cat "$RDIR/state.json" 2>/dev/null)"
    sleep 1
  done
}
health() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$STATE/health.json" "$1" 2>/dev/null || true; }
last_seen() { q "select coalesce(extract(epoch from last_seen)::bigint, 0) from tenant.agent where id = '$AG'"; }

# ns <machine> <cmd...>: sets CMD running cmd with the fake DMI mounted.
ns() {
  local m=$1
  shift
  # shellcheck disable=SC2016 # expanded by the inner sh
  CMD=("${SUDO[@]}" env RMM_AGENT_EXTRA_CA="$CA" RUST_LOG="${RUST_LOG:-info}" NO_PROXY='*'
    RMM_AGENT_TELEMETRY_INTERVALS="hb=5,metric=30,inv=60" RMM_AGENT_REFRESH_INTERVAL_SECS=5
    RMM_AGENT_TEST_PLATFORM=1 RMM_INDICATOR_SOCKET="$WORK/indicator.sock" RMM_WATCHDOG_ROOT="$RDIR"
    unshare --mount --propagation private
    sh -c 'mount --bind "$1" /sys/class && shift && exec "$@"' sh "$WORK/$m-machine" "$@")
}

# --------------------------------------------------------- stack and agent

# Whatever an earlier run left as the latest release must not be acted on.
publish_neutral
NEUTRAL_READY=1

tag=$RANDOM$RANDOM
C1=$(q "insert into tenant.client (name) values ('e2e-update-$tag') returning id")
S1=$(q "insert into tenant.site (client_id, name) values ('$C1', 'site-a') returning id")
[[ -n $C1 && -n $S1 ]] || fail "create client and site"

mkdir -p "$WORK/m-machine/dmi/id"
python3 -c 'import uuid; print(uuid.uuid4())' >"$WORK/m-machine/dmi/id/product_uuid"
echo "E2E-SYS-$RANDOM$RANDOM" >"$WORK/m-machine/dmi/id/product_serial"
echo "E2E-BRD-$RANDOM$RANDOM" >"$WORK/m-machine/dmi/id/board_serial"
echo "RMM e2e" >"$WORK/m-machine/dmi/id/sys_vendor"
echo "Simulated" >"$WORK/m-machine/dmi/id/product_name"

body=$(curl_api -f -X POST "$SERVER/api/v1/enrollment-tokens" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"$C1\",\"site_id\":\"$S1\",\"expires_in_hours\":1,\"max_uses\":1,\"allow_reattach\":false}") \
  || fail "create enrollment token"
ns m "$BOOT" enroll --server "$SERVER" --token "$(jget token <<<"$body")" --state-dir "$STATE"
out=$("${CMD[@]}") || fail "enroll"
AG=$(sed -n 's/^enrolled: agent_id=\([^ ]*\) status=\(.*\)$/\1/p' <<<"$out")
[[ -n $AG ]] || fail "no agent id in enroll output: $out"

: >"$LOG"
ns m "$WATCHDOG" run --root "$RDIR" --state-dir "$STATE" --health-timeout 60 -- run --state-dir "$STATE"
"${CMD[@]}" >"$LOG" 2>&1 &
BG_PID=$!
await_log 'nats connected' 60 "start"
await_log 'updates enabled' 10 "start"
await_log '"event":"agent_started".*"version":"0.1.0"|"version":"0.1.0".*"event":"agent_started"' 10 "start"
pass "agent 0.1.0 runs under the watchdog and has updates enabled"

# ------------------------------------------------------------------- (1)

release rel011 0.1.1 "$WORK/agent-0.1.1"
T0=$SECONDS
await_state "s['active_version'] == '0.1.1' and s['trial'] is None and s['active'] != 'bootstrap'" "$PROMOTE_BUDGET" "(1)"
PROMOTED_AT=$(date +%s)
pass "(1) 0.1.1 was downloaded, staged, installed and promoted $((SECONDS - T0)) s after publishing (slot $(st "s['active']"), budget $PROMOTE_BUDGET s)"
# The new agent signals health with its own version and pid, after a heartbeat.
deadline=$((SECONDS + 60))
until [[ $(health version) == 0.1.1 && $(health pid) == "$(child_pid || true)" ]]; do
  ((SECONDS < deadline)) || fail "(1) health.json is '$(cat "$STATE/health.json" 2>/dev/null)', want version 0.1.1 and pid $(child_pid || true)"
  sleep 1
done
deadline=$((SECONDS + 60))
until (($(last_seen) >= PROMOTED_AT)); do
  ((SECONDS < deadline)) || fail "(1) no heartbeat reached the server after the update"
  sleep 1
done
[[ ! -e $RDIR/pending ]] || fail "(1) pending/ was not cleaned up"
pass "(1) the updated agent reports 0.1.1 in health.json (own pid) and the server still sees heartbeats"

# ------------------------------------------------------------------- (2)

printf '#!/bin/sh\nexec sleep 100000\n' >"$WORK/agent-0.1.2"
chmod +x "$WORK/agent-0.1.2"
INSTALLED=$(log_count '"event":"release_installed"')
release rel012 0.1.2 "$WORK/agent-0.1.2"
BAD=$REL_HASH
deadline=$((SECONDS + 60))
until [[ $(st "s['trial'] is not None and s['trial']['version'] == '0.1.2'") == True ]]; do
  ((SECONDS < deadline)) || fail "(2) the 0.1.2 trial never started: $(cat "$RDIR/state.json")"
  sleep 1
done
T1=$SECONDS
await_state "s['trial'] is None and s['active_version'] == '0.1.1' and '$BAD' in s['bad_hashes']" "$ROLLBACK_BUDGET" "(2)"
pass "(2) the silent 0.1.2 was rolled back to 0.1.1 $((SECONDS - T1)) s after install (budget $ROLLBACK_BUDGET s); its hash is in bad_hashes"
await_log '"event":"trial_rolled_back"' 5 "(2)"
await_log "update skipped.*KnownBad" 60 "(2)"
sleep 12 # at least two more refreshes
[[ $(log_count '"event":"release_installed"') -eq $((INSTALLED + 1)) ]] || fail "(2) the bad release was installed again"
[[ ! -e $RDIR/pending ]] || fail "(2) the bad release was staged again"
[[ $(st "s['active_version']") == 0.1.1 && $(st "s['trial']") == None ]] || fail "(2) state changed: $(cat "$RDIR/state.json")"
pass "(2) the agent skipped the known-bad release (KnownBad) on later refreshes"

# ------------------------------------------------------------------- (3)

sign_release rel010 0.1.0 "$(sha_of "$BOOT")" "$(stat -c %s "$BOOT")"
publish_env rel010
await_log 'update skipped: downgrade.*version=0\.1\.0|version=0\.1\.0.*update skipped: downgrade' 60 "(3)"
sleep 7
[[ ! -e $RDIR/pending ]] || fail "(3) a downgrade was staged"
pass "(3) the agent logged the 0.1.0 release as a downgrade and staged nothing"
plant rel010 "$BOOT"
await_log '"event":"release_rejected".*"reason":"downgrade"|"reason":"downgrade".*"event":"release_rejected"' 30 "(3)"
[[ $(st "s['active_version']") == 0.1.1 && $(st "s['trial']") == None ]] || fail "(3) state changed: $(cat "$RDIR/state.json")"
pass "(3) a downgrade planted in pending/ was rejected by the watchdog with downgrade"

# ------------------------------------------------------------------- (4)

printf '#!/bin/sh\n# tampered %s\nexec sleep 100000\n' "$tag" >"$WORK/agent-0.1.3"
chmod +x "$WORK/agent-0.1.3"
release rel013 0.1.3 "$WORK/agent-0.1.3"
"${SUDO[@]}" python3 -I - "$ARTIFACTS/$REL_HASH" <<'PY' || fail "(4) cannot alter the stored artifact"
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[-1] ^= 1
open(p, "wb").write(bytes(b))
PY
await_log 'update failed.*version=0\.1\.3.*hash_mismatch' 60 "(4)"
sleep 1
[[ ! -e $RDIR/pending/READY ]] || fail "(4) a tampered artifact was staged"
pass "(4) the agent rejected an artifact whose bytes do not match the signed hash: hash_mismatch, no READY"
# Stop the agent's retries, then alter an artifact in a complete pending/.
publish_neutral
sleep 8
printf '#!/bin/sh\n# planted %s\nexec sleep 100000\n' "$tag" >"$WORK/agent-0.1.4"
sign_release rel014 0.1.4 "$(sha_of "$WORK/agent-0.1.4")" "$(stat -c %s "$WORK/agent-0.1.4")"
python3 -I - "$WORK/agent-0.1.4" "$WORK/agent-0.1.4.bad" <<'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read())
b[-1] ^= 1
open(sys.argv[2], "wb").write(bytes(b))
PY
plant rel014 "$WORK/agent-0.1.4.bad"
await_log '"event":"release_rejected".*"reason":"hash_mismatch"|"reason":"hash_mismatch".*"event":"release_rejected"' 30 "(4)"
[[ $(st "s['active_version']") == 0.1.1 && $(st "s['trial']") == None ]] || fail "(4) state changed: $(cat "$RDIR/state.json")"
[[ ! -e $RDIR/pending ]] || fail "(4) pending/ was not discarded"
pass "(4) a pending/ artifact altered after signing was rejected by the watchdog: hash_mismatch"

# ------------------------------------------------------------------- (5)

OLD=$(child_pid) || fail "(5) no agent process"
kill -9 "$OLD"
T5=$SECONDS
NEW=
until [[ -n $NEW && $NEW != "$OLD" ]]; do
  ((SECONDS - T5 <= RESTART_BUDGET)) || fail "(5) no new agent within $RESTART_BUDGET s of kill -9 $OLD"
  NEW=$(child_pid || true)
  sleep 0.2
done
[[ $(cat "/proc/$NEW/comm") == rmm-agent ]] || fail "(5) new child $NEW is '$(cat "/proc/$NEW/comm")'"
pass "(5) kill -9 of agent $OLD: new agent $NEW started $((SECONDS - T5)) s later (budget $RESTART_BUDGET s)"

echo "e2e update: all checks passed"
