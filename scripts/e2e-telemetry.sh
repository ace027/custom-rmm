#!/usr/bin/env bash
# End-to-end telemetry against the dev stack: a debug Linux agent enrolls,
# publishes heartbeat, inventory and metrics over WSS, and ingest lands them
# in Postgres under client scoping. Checks: heartbeat advances last_seen,
# inventory columns and one inventory.changed event, cpu metrics, tenant
# isolation of tenant.metrics_v, a RAM change turning into an event, and the
# ingest consumer keeping up with a fast metric stream.
#
# The agent runs as root in a private mount namespace with a fake
# /sys/class/dmi (same conventions as scripts/e2e-enroll.sh). Needs root or
# passwordless sudo, docker, cargo, curl and python3. Tears nothing down.
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/rmm-e2e-telemetry.XXXXXX")
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
cleanup() {
  stop_agent
  "${SUDO[@]}" rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

scripts/dev-up.sh

cargo build -q --locked -p rmm-agent
AGENT=$ROOT/target/debug/rmm-agent

# One simulated machine with a fake DMI so its fingerprint is strong and unique.
mkdir -p "$WORK/machine/dmi/id"
python3 -c 'import uuid; print(uuid.uuid4())' >"$WORK/machine/dmi/id/product_uuid"
echo "E2E-SYS-$RANDOM$RANDOM" >"$WORK/machine/dmi/id/product_serial"
echo "E2E-BRD-$RANDOM$RANDOM" >"$WORK/machine/dmi/id/board_serial"
echo "RMM e2e" >"$WORK/machine/dmi/id/sys_vendor"
echo "Simulated" >"$WORK/machine/dmi/id/product_name"

# agent_cmd <intervals>: sets CMD to the debug agent as root with the fake DMI.
# Not run through a function in the background: $! must be the agent process.
agent_cmd() {
  # shellcheck disable=SC2016 # expanded by the inner sh
  CMD=("${SUDO[@]}" env RMM_AGENT_EXTRA_CA="$CA" RUST_LOG="${RUST_LOG:-info}" NO_PROXY='*'
    RMM_AGENT_TELEMETRY_INTERVALS="$1"
    unshare --mount --propagation private
    sh -c 'mount --bind "$1" /sys/class && shift && exec "$@"' sh "$WORK/machine" "$AGENT")
}

# start_agent <intervals>: run in the background and wait for the connection.
start_agent() {
  local log=$WORK/agent.log
  : >"$log"
  agent_cmd "$1"
  "${CMD[@]}" run --state-dir "$DIR" >"$log" 2>&1 &
  BG_PID=$!
  for _ in $(seq 1 60); do
    grep -q 'nats connected' "$log" && return 0
    sleep 0.5
  done
  fail "agent did not connect: $(cat "$log")"
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

ADMIN=$("${COMPOSE[@]}" exec -T api rmm-server dev-token --role RMM.Admin --sub e2e-telemetry)
[[ -n $ADMIN ]] || fail "dev-token"

tag=$RANDOM$RANDOM
C1=$(q "insert into tenant.client (name) values ('e2e-tel-a-$tag') returning id")
C2=$(q "insert into tenant.client (name) values ('e2e-tel-b-$tag') returning id")
S1=$(q "insert into tenant.site (client_id, name) values ('$C1', 'site-a') returning id")
[[ -n $C1 && -n $C2 && -n $S1 ]] || fail "create clients and site"

body=$(curl_api -f -X POST "$SERVER/api/v1/enrollment-tokens" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"$C1\",\"site_id\":\"$S1\",\"expires_in_hours\":1,\"max_uses\":1,\"allow_reattach\":false}") \
  || fail "create enrollment token"
TOKEN=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$body")
DIR=$WORK/agent-state
agent_cmd "hb=2,metric=3,inv=5"
out=$("${CMD[@]}" enroll --server "$SERVER" --token "$TOKEN" --state-dir "$DIR") \
  || fail "enroll"
AG=$(sed -n 's/^enrolled: agent_id=\([^ ]*\) status=\(.*\)$/\1/p' <<<"$out")
[[ -n $AG ]] || fail "no agent id in enroll output: $out"
DEV=$(q "select device_id from tenant.agent where id = '$AG'")
[[ -n $DEV ]] || fail "device of agent $AG"

start_agent "hb=2,metric=3,inv=5"

# (1) The heartbeat advances tenant.agent.last_seen.
L0=$(q "select coalesce(last_seen, 'epoch'::timestamptz) from tenant.agent where id = '$AG'")
wait_for 10 "last_seen did not advance past $L0" \
  "select coalesce(last_seen, 'epoch'::timestamptz) > '$L0'::timestamptz from tenant.agent where id = '$AG'"
pass "(1) tenant.agent.last_seen advances (agent $AG)"

# (2) Inventory fills the typed columns and writes one inventory.changed event.
wait_for 15 "inventory columns not set" \
  "select ram_bytes is not null and os_version is not null and cpu_cores is not null from tenant.device where id = '$DEV'"
EVENTS=$(q "select count(*) from tenant.device_event where device_id = '$DEV' and client_id = '$C1' and type = 'inventory.changed'")
[[ $EVENTS -ge 1 ]] || fail "no inventory.changed event for device $DEV"
pass "(2) inventory columns set and $EVENTS inventory.changed event(s) for device $DEV"

# (3) cpu.usage_pct samples land in ts_private.metrics.
wait_for 15 "no cpu.usage_pct rows" \
  "select count(*) > 0 from ts_private.metrics where device_id = '$DEV' and client_id = '$C1' and metric = 'cpu.usage_pct'"
pass "(3) ts_private.metrics has cpu.usage_pct rows for device $DEV"

# (4) tenant.metrics_v honours client scope, as rmm_api.
scoped_count() {
  "${COMPOSE[@]}" exec -T timescale psql -U rmm -d rmm -v ON_ERROR_STOP=1 -tAq -c \
    "BEGIN; SET LOCAL ROLE rmm_api; SET LOCAL rmm.service = 'off'; SET LOCAL rmm.client_ids = '{$1}'; \
     SELECT count(*) FROM tenant.metrics_v WHERE device_id = '$DEV'; COMMIT;"
}
OTHER=$(scoped_count "$C2")
OWN=$(scoped_count "$C1")
[[ $OTHER -eq 0 ]] || fail "client $C2 sees $OTHER rows of device $DEV"
[[ $OWN -gt 0 ]] || fail "client $C1 sees no rows of its own device"
pass "(4) metrics_v: other client sees 0 rows, owner sees $OWN"

# (5) A RAM change becomes an inventory.changed event end to end.
stop_agent
ram_events() {
  q "select count(*) from tenant.device_event where device_id = '$DEV' and type = 'inventory.changed' and after ? 'ram_bytes'"
}
N0=$(ram_events)
q "update tenant.device set ram_bytes = ram_bytes - 1, inventory_hash = NULL where id = '$DEV'" >/dev/null
start_agent "hb=2,metric=3,inv=5"
deadline=$((SECONDS + 15))
while [[ $(ram_events) -le $N0 ]]; do
  ((SECONDS < deadline)) || fail "no new inventory.changed event with ram_bytes within 15 s"
  sleep 0.5
done
pass "(5) RAM change wrote a new inventory.changed event with ram_bytes"

# (6) Throughput. First the real agent publishes metric batches as fast as it
# can for 20 s (collecting one sample blocks it for 200 ms, so about 5 batches
# per second); then 1000 batches of 10 samples (10000 rows) are published on the
# agent's own subject through nats-box. In both cases the TELEM consumer
# `ingest` must drain (0 pending) within the budget and every sample must land.
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
cpu_rows() { q "select count(*) from ts_private.metrics where device_id = '$DEV' and metric = 'cpu.usage_pct'"; }

stop_agent
R0=$(cpu_rows)
start_agent "hb=2,metric=0.05,inv=60"
sleep 20
stop_agent
wait_drained 30
R1=$(cpu_rows)
[[ $((R1 - R0)) -ge 40 ]] || fail "only $((R1 - R0)) cpu.usage_pct rows landed from the agent in 20 s, want at least 40"
pass "(6a) agent at 50 ms metric interval: $((R1 - R0)) batches landed, 0 pending"

# Hand-encoded CBOR MetricBatches (rmm_proto::telemetry): v, msg_id, sent_at and
# ten "e2e.burst" samples each. Identity comes from the subject only. Every
# batch has its own msg_id, because ingest deduplicates by msg_id; batches are
# newline-separated for `nats pub --send-on newline`, so no encoded byte may be
# 0x0a.
python3 -I - >"$WORK/burst.cbor" <<'PY'
import os, struct, sys, time

def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)

def text(s):
    b = s.encode()
    return head(3, len(b)) + b

now = int(time.time() * 1000)
while b"\n" in struct.pack(">Q", now):
    now += 1
sample = (head(5, 3) + text("t") + head(0, now) + text("metric") + text("e2e.burst")
          + text("value") + b"\xfb" + struct.pack(">d", 1.0))
run_id = bytes(b if b != 0x0a else 0x0b for b in os.urandom(14))
out = sys.stdout.buffer
for i in range(1000):
    # 14 random-per-run bytes (so reruns are not deduplicated) plus two
    # counter bytes in 0x10..0xd7; no byte is 0x0a.
    msg_id = run_id + bytes([0x10 + i // 200, 0x10 + i % 200])
    body = (head(5, 4) + text("v") + head(0, 1)
            + text("msg_id") + head(2, 16) + msg_id
            + text("sent_at") + head(0, now)
            + text("samples") + head(4, 10) + sample * 10)
    assert b"\n" not in body
    out.write(body + b"\n")
PY
SEED=$WORK/agent.nk
"${SUDO[@]}" python3 scripts/nkey-seed.py "$DIR/agent.key" >"$SEED"
chmod 644 "$SEED"
B0=$(q "select count(*) from ts_private.metrics where device_id = '$DEV' and metric = 'e2e.burst'")
docker run --rm -i --network host -v "$CA:/ca.pem:ro" -v "$SEED:/agent.nk:ro" \
  natsio/nats-box:latest nats --tlsca /ca.pem --nkey /agent.nk --timeout 10s \
  --server "wss://localhost:$PORT/nats" pub "telemetry.$C1.$AG.metric" --send-on newline \
  <"$WORK/burst.cbor" >/dev/null 2>"$WORK/burst.err" || fail "burst publish: $(cat "$WORK/burst.err")"
deadline=$((SECONDS + 60))
while :; do
  B=$(q "select count(*) from ts_private.metrics where device_id = '$DEV' and metric = 'e2e.burst'")
  [[ $((B - B0)) -ge 10000 ]] && break
  ((SECONDS < deadline)) || fail "only $((B - B0)) of 10000 burst samples landed within 60 s"
  sleep 0.5
done
wait_drained 30
pass "(6b) 10000 burst samples landed within 60 s, 0 pending"

echo "e2e telemetry: all checks passed"
