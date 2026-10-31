#!/usr/bin/env bash
# End-to-end enrollment against the dev stack: a debug Linux agent enrolls
# through nginx, connects to NATS over WSS with an authd-issued JWT, and the
# negative cases (token reuse, cross-tenant subjects, plain TCP, revocation,
# static users over the public WebSocket)
# fail as they should. Reattach and clone flagging are checked last.
#
# The agent runs as root in a private mount namespace with a fake
# /sys/class/dmi per simulated machine so each fingerprint is strong and unique
# (CI runners and containers either hide or lack DMI data). Needs root or
# passwordless sudo, docker, cargo, curl and python3. Tears nothing down.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=${RMM_HTTPS_PORT:-443}
export RMM_HTTPS_PORT=$PORT
COMPOSE=(docker compose -f deploy/compose.yaml)
CA=$ROOT/deploy/dev/certs/ca.pem
SERVER=https://localhost:$PORT
NATS_WSS=wss://localhost:$PORT/nats
SUDO=()
[[ $(id -u) -eq 0 ]] || SUDO=(sudo)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/rmm-e2e.XXXXXX")
BG_PID=
cleanup() {
  if [[ -n $BG_PID ]]; then "${SUDO[@]}" kill "$BG_PID" 2>/dev/null || true; fi
  "${SUDO[@]}" rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

scripts/dev-up.sh

cargo build -q --locked -p rmm-agent
AGENT=$ROOT/target/debug/rmm-agent

# Fake DMI for simulated machines: each gets its own strong fingerprint.
machine() {
  local dir=$WORK/machine-$1
  mkdir -p "$dir/dmi/id"
  python3 -c 'import uuid; print(uuid.uuid4())' >"$dir/dmi/id/product_uuid"
  echo "E2E-SYS-$RANDOM$RANDOM" >"$dir/dmi/id/product_serial"
  echo "E2E-BRD-$RANDOM$RANDOM" >"$dir/dmi/id/board_serial"
  echo "RMM e2e" >"$dir/dmi/id/sys_vendor"
  echo "Simulated" >"$dir/dmi/id/product_name"
}
machine a
machine b

# agent_cmd <machine>: the debug agent as root with that machine's fake DMI.
agent_cmd() {
  # shellcheck disable=SC2016 # expanded by the inner sh
  CMD=("${SUDO[@]}" env RMM_AGENT_EXTRA_CA="$CA" RUST_LOG="${RUST_LOG:-info}" NO_PROXY='*'
    unshare --mount --propagation private
    sh -c 'mount --bind "$1" /sys/class && shift && exec "$@"' sh "$WORK/machine-$1" "$AGENT")
}
agent_cmd a; AGENT_CMD_A=("${CMD[@]}")
agent_cmd b; AGENT_CMD_B=("${CMD[@]}")
agent() { "${AGENT_CMD_A[@]}" "$@"; }

q() {
  "${COMPOSE[@]}" exec -T timescale psql -U rmm -d rmm -v ON_ERROR_STOP=1 -tAq \
    -c "SET rmm.service = 'on'; $1"
}

curl_api() { curl -sS --noproxy '*' --cacert "$CA" "$@"; }

ADMIN=$("${COMPOSE[@]}" exec -T api rmm-server dev-token --role RMM.Admin --sub e2e)
[[ -n $ADMIN ]] || fail "dev-token"

# new_token <client> <site> <allow_reattach>
new_token() {
  local body
  body=$(curl_api -f -X POST "$SERVER/api/v1/enrollment-tokens" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$1\",\"site_id\":\"$2\",\"expires_in_hours\":1,\"max_uses\":1,\"allow_reattach\":$3}") \
    || fail "create enrollment token"
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$body"
}

# enroll <state-dir> <token> [machine]: prints "<agent_id> <status>".
enroll() {
  local out cmd=("${AGENT_CMD_A[@]}")
  [[ ${3:-a} == b ]] && cmd=("${AGENT_CMD_B[@]}")
  out=$("${cmd[@]}" enroll --server "$SERVER" --token "$2" --state-dir "$1") || return $?
  sed -n 's/^enrolled: agent_id=\([^ ]*\) status=\(.*\)$/\1 \2/p' <<<"$out"
}

device_of() { q "select device_id from tenant.agent where id = '$1'"; }

# nats_box <seed-file> <args...>: nats CLI as the agent in the seed file.
nats_box() {
  local seed=$1
  shift
  docker run --rm --network host -v "$CA:/ca.pem:ro" -v "$seed:/agent.nk:ro" \
    natsio/nats-box:latest nats --tlsca /ca.pem --nkey /agent.nk --timeout 3s "$@" 2>&1
}

tag=$RANDOM$RANDOM
CA_ID=$(q "insert into tenant.client (name) values ('e2e-a-$tag') returning id")
CB_ID=$(q "insert into tenant.client (name) values ('e2e-b-$tag') returning id")
SA_ID=$(q "insert into tenant.site (client_id, name) values ('$CA_ID', 'site-a') returning id")
SB_ID=$(q "insert into tenant.site (client_id, name) values ('$CB_ID', 'site-b') returning id")
[[ -n $SA_ID && -n $SB_ID ]] || fail "create clients and sites"

# (1) Enroll and connect through nginx.
DIR_A=$WORK/agent-a
TOKEN_A=$(new_token "$CA_ID" "$SA_ID" false)
read -r AG_A STATUS_A < <(enroll "$DIR_A" "$TOKEN_A") || fail "enroll agent A"
[[ $STATUS_A == active ]] || fail "agent A status $STATUS_A"
timeout 30 "${AGENT_CMD_A[@]}" run --once --state-dir "$DIR_A" \
  || fail "agent A run --once"
[[ $(q "select count(*) from msp.audit_event where action = 'nats.auth.allow' and target = 'agent:$AG_A'") -ge 1 ]] \
  || fail "no nats.auth.allow audit row for agent A"
pass "(1) agent enrolls and connects through nginx $NATS_WSS"

# (2) A single-use token cannot be reused.
set +e
agent enroll --server "$SERVER" --token "$TOKEN_A" --state-dir "$WORK/agent-reuse" >/dev/null 2>&1
rc=$?
set -e
[[ $rc -eq 3 ]] || fail "token reuse exited $rc, want 3"
pass "(2) reusing a single-use token exits 3"

# (3) Agent of client A cannot touch client B's subjects.
DIR_B=$WORK/agent-b
read -r AG_B STATUS_B < <(enroll "$DIR_B" "$(new_token "$CB_ID" "$SB_ID" false)" b) || fail "enroll agent B"
[[ $STATUS_B == active ]] || fail "agent B (own machine) status $STATUS_B, want active"
read -r _ STATUS_X < <(enroll "$WORK/agent-x" "$(new_token "$CB_ID" "$SB_ID" false)" a) || fail "enroll agent X"
[[ $STATUS_X == flagged ]] || fail "agent X (machine A, other client) status $STATUS_X, want flagged"
SEED_A=$WORK/agent-a.nk
"${SUDO[@]}" python3 scripts/nkey-seed.py "$DIR_A/agent.key" >"$SEED_A"
chmod 644 "$SEED_A"
out=$(nats_box "$SEED_A" --server "$NATS_WSS" pub "telemetry.$CA_ID.$AG_A.hb" ok) \
  || fail "agent A publish to its own subject: $out"
grep -qi 'violation' <<<"$out" && fail "agent A own subject denied: $out"
out=$(nats_box "$SEED_A" --server "$NATS_WSS" pub "telemetry.$CB_ID.$AG_B.hb" x || true)
grep -qi 'permissions violation' <<<"$out" || fail "cross-tenant publish not denied: $out"
out=$(timeout 15 docker run --rm --network host -v "$CA:/ca.pem:ro" -v "$SEED_A:/agent.nk:ro" \
  natsio/nats-box:latest timeout 4 nats --tlsca /ca.pem --nkey /agent.nk --server "$NATS_WSS" \
  sub "shell.$AG_B.*.in" 2>&1 || true)
grep -qi 'permissions violation' <<<"$out" || fail "cross-tenant subscribe not denied: $out"
pass "(3) agent A cannot publish to or subscribe on agent B's subjects"

# (4) The agent key is refused over plain TCP.
# No --tlsca here: with a CA the CLI insists on TLS and never reaches auth.
out=$(docker run --rm --network host -v "$SEED_A:/agent.nk:ro" natsio/nats-box:latest \
  nats --nkey /agent.nk --timeout 3s --server nats://127.0.0.1:4222 \
  pub "telemetry.$CA_ID.$AG_A.hb" x 2>&1 || true)
grep -qi 'authorization violation' <<<"$out" || fail "plain TCP not refused: $out"
pass "(4) agent key over nats://127.0.0.1:4222 fails authorization"

# (5) Revocation kicks a connected agent within 5 s and blocks reconnects.
LOG_A=$WORK/agent-a.log
# Not via the agent() function: $! must be the agent process itself.
"${AGENT_CMD_A[@]}" run --state-dir "$DIR_A" >"$LOG_A" 2>&1 &
BG_PID=$!
for _ in $(seq 1 60); do
  grep -q 'nats connected' "$LOG_A" && break
  sleep 0.5
done
grep -q 'nats connected' "$LOG_A" || fail "agent A did not connect: $(cat "$LOG_A")"
code=$(curl_api -o /dev/null -w '%{http_code}' -X POST "$SERVER/api/v1/agents/$AG_A/revoke" \
  -H "Authorization: Bearer $ADMIN")
[[ $code == 204 ]] || fail "revoke returned $code"
kicked=
for _ in $(seq 1 50); do
  if grep -qE 'nats disconnected|connection closed' "$LOG_A"; then kicked=1; break; fi
  sleep 0.1
done
[[ -n $kicked ]] || fail "agent A not disconnected within 5 s: $(cat "$LOG_A")"
"${SUDO[@]}" kill "$BG_PID" 2>/dev/null || true
wait "$BG_PID" 2>/dev/null || true
BG_PID=
set +e
timeout 15 "${AGENT_CMD_A[@]}" run --once --state-dir "$DIR_A" >/dev/null 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]] || fail "revoked agent connected again"
[[ $(q "select count(*) from msp.audit_event where action = 'nats.auth.deny' and target = 'agent:$AG_A'") -ge 1 ]] \
  || fail "no nats.auth.deny audit row for revoked agent A"
pass "(5) revoked agent is kicked within 5 s and refused on reconnect"

# (6) Reinstall after 25 h of silence reattaches to the same device.
DEV_B=$(device_of "$AG_B")
"${SUDO[@]}" rm -rf "$DIR_B"
q "update tenant.agent set last_seen = now() - interval '25 hours' where id = '$AG_B'" >/dev/null
DIR_B2=$WORK/agent-b2
read -r AG_B2 STATUS_B2 < <(enroll "$DIR_B2" "$(new_token "$CB_ID" "$SB_ID" true)" b) || fail "re-enroll agent B"
[[ $(device_of "$AG_B2") == "$DEV_B" ]] || fail "reattach gave a new device"
[[ $(q "select status from tenant.agent where id = '$AG_B'") == superseded ]] || fail "old agent not superseded"
pass "(6) reinstall reattaches to device $DEV_B (status $STATUS_B2)"

# (7) A second copy while the reattached agent is fresh is held for review.
timeout 30 "${AGENT_CMD_B[@]}" run --once --state-dir "$DIR_B2" \
  || fail "agent B2 run --once"
read -r AG_B3 STATUS_B3 < <(enroll "$WORK/agent-b3" "$(new_token "$CB_ID" "$SB_ID" true)" b) || fail "clone enroll"
[[ $STATUS_B3 == pending_review ]] || fail "clone status $STATUS_B3, want pending_review"
[[ $(q "select status from tenant.agent where id = '$AG_B3'") == suspect_clone ]] || fail "clone agent not suspect_clone"
pass "(7) clone of a fresh agent is pending_review"

# (8) The static `api` user must not authenticate over the public WebSocket.
API_PW=$("${COMPOSE[@]}" exec -T api printenv RMM_NATS_PASSWORD)
[[ -n $API_PW ]] || fail "api NATS password not found"
out=$(docker run --rm --network host -v "$CA:/ca.pem:ro" natsio/nats-box:latest \
  nats --tlsca /ca.pem --user api --password "$API_PW" --timeout 3s --server "$NATS_WSS" \
  pub "e2e.static.user" x 2>&1 || true)
grep -qi 'authorization violation' <<<"$out" || fail "static user api not refused over $NATS_WSS: $out"
pass "(8) static user api over $NATS_WSS fails authorization"

echo "e2e enrollment: all checks passed"
