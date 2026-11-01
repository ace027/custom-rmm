#!/usr/bin/env bash
# End-to-end offline sync against the dev stack: a debug Linux agent enrolls and
# publishes metrics, then nginx (the only way to the broker) is stopped for
# 60 s. The agent keeps sampling into its encrypted outbox; when nginx returns
# the outbox drains. Checks:
#   (1) every sample taken during the outage lands within 60 s of reconnect
#   (2) no duplicates in ts_private.metrics (durable msg_id dedupe in ingest)
#   (3) an agent killed and restarted while offline still delivers what it had
#       queued, exactly once
#   (4) agent-store.db and its WAL hold no metric name in clear
#
# Scale-down: the success criterion is a 1 hour outage; this script uses a 60 s
# outage at a 1 s metric interval (about 60 batches). It does not cover a
# backlog above MAX_IN_FLIGHT (200), inventory queued during an outage, or
# command results (not implemented yet). Those paths are covered only by unit
# tests with a fake sink.
#
# Same conventions as scripts/e2e-telemetry.sh: the agent runs as root in a
# private mount namespace with a fake /sys/class/dmi. Needs root or
# passwordless sudo, docker, cargo, curl and python3.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=${RMM_HTTPS_PORT:-443}
export RMM_HTTPS_PORT=$PORT
COMPOSE=(docker compose -f deploy/compose.yaml)
CA=$ROOT/deploy/dev/certs/ca.pem
SERVER=https://localhost:$PORT
SUDO=()
[[ $(id -u) -eq 0 ]] || SUDO=(sudo)
INTERVALS="hb=2,metric=1,inv=5"
OUTAGE=60

WORK=$(mktemp -d "${TMPDIR:-/tmp}/rmm-e2e-offline.XXXXXX")
BG_PID=
stop_agent() {
  if [[ -n $BG_PID ]]; then
    "${SUDO[@]}" kill "$BG_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$BG_PID" 2>/dev/null || break
      sleep 0.1
    done
    "${SUDO[@]}" kill -9 "$BG_PID" 2>/dev/null || true
    wait "$BG_PID" 2>/dev/null || true
    BG_PID=
  fi
}
kill_agent_hard() {
  "${SUDO[@]}" kill -9 "$BG_PID" 2>/dev/null || true
  wait "$BG_PID" 2>/dev/null || true
  BG_PID=
}
nginx_start() {
  "${COMPOSE[@]}" start nginx >/dev/null
  # nginx resolves upstream names at start; reload as dev-up.sh does.
  "${COMPOSE[@]}" exec -T nginx nginx -s reload >/dev/null 2>&1 || true
}
cleanup() {
  stop_agent
  "${COMPOSE[@]}" start nginx >/dev/null 2>&1 || true
  "${SUDO[@]}" rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

scripts/dev-up.sh

RMM_ROOT_PUBKEYS=$(sed -n 's/^RMM_ROOT_PUBKEYS=//p' deploy/.env) cargo build -q --locked -p rmm-agent
AGENT=$ROOT/target/debug/rmm-agent

# One simulated machine with a fake DMI so its fingerprint is strong and unique.
mkdir -p "$WORK/machine/dmi/id"
python3 -c 'import uuid; print(uuid.uuid4())' >"$WORK/machine/dmi/id/product_uuid"
echo "E2E-SYS-$RANDOM$RANDOM" >"$WORK/machine/dmi/id/product_serial"
echo "E2E-BRD-$RANDOM$RANDOM" >"$WORK/machine/dmi/id/board_serial"
echo "RMM e2e" >"$WORK/machine/dmi/id/sys_vendor"
echo "Simulated" >"$WORK/machine/dmi/id/product_name"

# agent_cmd <intervals>: sets CMD to the debug agent as root with the fake DMI.
agent_cmd() {
  # shellcheck disable=SC2016 # expanded by the inner sh
  CMD=("${SUDO[@]}" env RMM_AGENT_EXTRA_CA="$CA" RUST_LOG="${RUST_LOG:-info}" NO_PROXY='*'
    RMM_AGENT_TELEMETRY_INTERVALS="$1"
    unshare --mount --propagation private
    sh -c 'mount --bind "$1" /sys/class && shift && exec "$@"' sh "$WORK/machine" "$AGENT")
}

# launch_agent: run in the background ($! must be the agent process).
launch_agent() {
  LOG=$WORK/agent.log
  : >"$LOG"
  agent_cmd "$INTERVALS"
  "${CMD[@]}" run --state-dir "$DIR" >"$LOG" 2>&1 &
  BG_PID=$!
}
wait_connected() {
  for _ in $(seq 1 120); do
    grep -q 'nats connected' "$LOG" && return 0
    sleep 0.5
  done
  fail "agent did not connect: $(cat "$LOG")"
}

q() {
  "${COMPOSE[@]}" exec -T timescale psql -U rmm -d rmm -v ON_ERROR_STOP=1 -tAq \
    -c "SET rmm.service = 'on'; $1"
}

# wait_for <seconds> <description> <sql>: poll until the query prints 't'.
wait_for() {
  local deadline=$((SECONDS + $1))
  while ((SECONDS < deadline)); do
    [[ $(q "$3") == t ]] && return 0
    sleep 0.5
  done
  fail "$2 (within $1 s)"
}

curl_api() { curl -sS --noproxy '*' --cacert "$CA" "$@"; }

# Rows still queued in the agent's outbox (the row count is not secret).
outbox_len() {
  "${SUDO[@]}" python3 -I -c '
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=10)
print(c.execute("select count(*) from outbox where priority >= ?", (int(sys.argv[2]),)).fetchone()[0])' \
    "$DIR/agent-store.db" "${1:-0}"
}
wait_outbox_empty() {
  local deadline=$((SECONDS + $1))
  until [[ $(outbox_len) == 0 ]]; do
    ((SECONDS < deadline)) || fail "agent outbox still holds $(outbox_len) rows after $1 s"
    sleep 0.5
  done
}

pending() {
  curl -sS --noproxy '*' 'http://127.0.0.1:8222/jsz?accounts=true&streams=true&consumers=true' |
    python3 -I -c '
import json, sys
d = json.load(sys.stdin)
n = None
for acc in d.get("account_details", []):
    for st in acc.get("stream_detail", []):
        for c in st.get("consumer_detail", []):
            if st.get("name") == "TELEM" and c.get("name") == "ingest":
                n = c["num_pending"] + c["num_ack_pending"]
print("none" if n is None else n)'
}
wait_drained() {
  local deadline=$((SECONDS + $1))
  until [[ $(pending) == 0 ]]; do
    ((SECONDS < deadline)) || fail "TELEM consumer ingest still has $(pending) pending messages after $1 s"
    sleep 0.5
  done
}

# Distinct cpu.usage_pct sample times (one per batch) in (<from>, <to>).
batches_between() {
  q "select count(distinct time) from ts_private.metrics where device_id = '$DEV' and metric = 'cpu.usage_pct' and time > '$1'::timestamptz and time < '$2'::timestamptz"
}
# Duplicate (time, metric) rows for the device; must be 0.
duplicates() {
  q "select count(*) - count(distinct (time, metric)) from ts_private.metrics where device_id = '$DEV'"
}
db_now() { q "select clock_timestamp()"; }

ADMIN=$("${COMPOSE[@]}" exec -T api rmm-server dev-token --role RMM.Admin --sub e2e-offline)
[[ -n $ADMIN ]] || fail "dev-token"

tag=$RANDOM$RANDOM
C1=$(q "insert into tenant.client (name) values ('e2e-off-$tag') returning id")
S1=$(q "insert into tenant.site (client_id, name) values ('$C1', 'site-a') returning id")
[[ -n $C1 && -n $S1 ]] || fail "create client and site"

body=$(curl_api -f -X POST "$SERVER/api/v1/enrollment-tokens" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"$C1\",\"site_id\":\"$S1\",\"expires_in_hours\":1,\"max_uses\":1,\"allow_reattach\":false}") \
  || fail "create enrollment token"
TOKEN=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$body")
DIR=$WORK/agent-state
agent_cmd "$INTERVALS"
out=$("${CMD[@]}" enroll --server "$SERVER" --token "$TOKEN" --state-dir "$DIR") \
  || fail "enroll"
AG=$(sed -n 's/^enrolled: agent_id=\([^ ]*\) status=\(.*\)$/\1/p' <<<"$out")
[[ -n $AG ]] || fail "no agent id in enroll output: $out"
DEV=$(q "select device_id from tenant.agent where id = '$AG'")
[[ -n $DEV ]] || fail "device of agent $AG"

launch_agent
wait_connected
wait_for 20 "no cpu.usage_pct rows while online" \
  "select count(*) >= 3 from ts_private.metrics where device_id = '$DEV' and metric = 'cpu.usage_pct'"
echo "agent $AG online, outage of $OUTAGE s starts now"

# Outage 1: the agent stays up and keeps sampling into its outbox.
T0=$(db_now)
"${COMPOSE[@]}" stop nginx >/dev/null
sleep "$OUTAGE"
QUEUED=$(outbox_len 2)
T1=$(db_now)
nginx_start

# (1) The outbox drains and every sample taken during the outage landed.
wait_outbox_empty 60
wait_drained 30
N=$(batches_between "$T0" "$T1")
[[ $QUEUED -ge 20 ]] || fail "only $QUEUED metric batches were queued in a ${OUTAGE} s outage, want at least 20"
[[ $N -ge $QUEUED ]] || fail "only $N batches between $T0 and $T1 landed, $QUEUED were queued"
pass "(1) $QUEUED queued metric batches drained after reconnect; $N batches in the outage window landed, 0 pending"

# (2) No duplicates, although the agent re-publishes unacknowledged rows.
D=$(duplicates)
[[ $D -eq 0 ]] || fail "$D duplicate (time, metric) rows for device $DEV"
pass "(2) no duplicate (time, metric) rows for device $DEV"

# (3) Restart while offline: the queue survives a hard kill of the agent.
S2=$(db_now)
"${COMPOSE[@]}" stop nginx >/dev/null
sleep 15
Q2=$(outbox_len 2)
[[ $Q2 -ge 8 ]] || fail "only $Q2 metric batches queued in 15 s offline, want at least 8"

# (4) Checked while rows are queued. The queued subjects hold the agent id in
# clear (the control proves the files are being searched); no metric name may
# appear anywhere in the database file or its WAL.
# The state dir is root-only, so the glob must expand inside sudo.
store_bytes() { "${SUDO[@]}" sh -c 'cat "$1"/agent-store.db*' sh "$DIR"; }
control=$(store_bytes | grep -a -F -c -- "$AG" || true)
[[ $control -gt 0 ]] || fail "control: agent id not found in the store files, grep proves nothing"
names=$(q "select distinct metric from ts_private.metrics where device_id = '$DEV'")
[[ -n $names ]] || fail "no metric names for device $DEV"
while IFS= read -r name; do
  hits=$(store_bytes | grep -a -F -c -- "$name" || true)
  [[ $hits -eq 0 ]] || fail "metric name '$name' appears in clear in agent-store.db ($hits lines)"
done <<<"$names"
pass "(4) none of $(wc -l <<<"$names") metric names appear in clear in agent-store.db (control: $control lines with the agent id)"

kill_agent_hard
T3=$(db_now)
Q3=$(outbox_len 2)
[[ $Q3 -ge $Q2 ]] || fail "outbox shrank across the kill: $Q2 -> $Q3"
launch_agent
sleep 2
nginx_start
wait_connected
wait_outbox_empty 60
wait_drained 30
N3=$(batches_between "$S2" "$T3")
[[ $N3 -ge $Q3 ]] || fail "only $N3 batches between $S2 and $T3 landed, $Q3 were queued at the kill"
D=$(duplicates)
[[ $D -eq 0 ]] || fail "$D duplicate (time, metric) rows after the restart"
pass "(3) $Q3 batches queued before the kill landed exactly once after the restart ($N3 in window, 0 duplicates)"

echo "e2e offline: all checks passed"
