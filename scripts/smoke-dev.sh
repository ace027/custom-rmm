#!/usr/bin/env bash
# Bring up the dev stack and assert TLS, NATS WebSocket, JetStream and the database.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${RMM_HTTPS_PORT:-443}
export RMM_HTTPS_PORT=$PORT
COMPOSE=(docker compose -f deploy/compose.yaml)

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

scripts/dev-up.sh

body=$(curl -fsS --noproxy '*' --cacert deploy/dev/certs/ca.pem "https://localhost:$PORT/healthz") \
  || fail "https healthz"
grep -q '"status":"ok"' <<<"$body" || fail "healthz body: $body"
pass "TLS /healthz through nginx"

set +e
code=$(curl -sS --noproxy '*' --http1.1 --cacert deploy/dev/certs/ca.pem --max-time 3 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -o /dev/null -w '%{http_code}' "https://localhost:$PORT/nats")
rc=$?
set -e
if [[ $rc -ne 0 && $rc -ne 28 ]]; then fail "websocket curl exit $rc"; fi
[[ $code == 101 ]] || fail "websocket upgrade returned $code"
pass "NATS WebSocket upgrade via nginx (101)"

code=$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' \
  'http://127.0.0.1:8222/healthz?js-enabled-only=true') || fail "nats monitor"
[[ $code == 200 ]] || fail "nats jetstream health returned $code"
pass "NATS JetStream healthy"

q() { "${COMPOSE[@]}" exec -T timescale psql -U rmm -d rmm -tAc "$1"; }
[[ $(q "select count(*) from pg_extension where extname='timescaledb'") == 1 ]] \
  || fail "timescaledb extension missing"
pass "timescaledb extension"
n=$(q "select count(*) from pg_namespace where nspname in ('tenant','msp','ts_private','rmm')")
[[ $n == 4 ]] || fail "expected 4 schemas, found $n"
pass "schemas tenant, msp, ts_private, rmm"

for svc in ingest authd; do
  health=$("${COMPOSE[@]}" ps --format json "$svc" | python3 -c \
    "import sys,json;print(json.loads(sys.stdin.readline()).get('Health'))")
  [[ $health == healthy ]] || fail "$svc is $health"
  pass "$svc healthy"
done
