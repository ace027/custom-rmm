#!/usr/bin/env bash
# End-to-end co-signed remote shell against the dev stack. A debug Linux agent
# (RMM_AGENT_TEST_PLATFORM=1, RMM_INDICATOR_SOCKET set) runs next to
# rmm-session; a software authenticator (cargo run -p xtask -- fake-authn)
# plays the technician's hardware key. Dev and CI only.
#
# Setup: the stack runs with the dev attestation root and AAGUID configured; a
# technician registers a credential with a packed attestation, is assigned the
# test client, and the techlist draft is exported, signed with rmm-sign
# (--allow-aaguid <dev aaguid>, file backend) and published.
#
# Checks:
#   (1) a techlist entry whose key does not match what the API stored makes the
#       agent refuse an otherwise valid ShellOpen: reason bad_assertion, and no
#       shell starts. (The API itself refuses a bad assertion with 400, so the
#       agent's own check is reached with a techlist the agent disagrees with.)
#   (2) a valid grant opens an 'sh' session over the WebSocket relay and
#       'echo e2e-shell-ok' round-trips; the shell exits with its code
#   (3) rmm-session printed state connected while the session was open, idle after
#   (4) printing 1 GiB completes while the agent's VmRSS, sampled every second,
#       and its VmHWM (peak resident set since start) stay under 50 MB
#   (5) a grant with max_duration 5 is closed with reason max_duration
#   (6) a browser that dies without a close frame makes the agent close the
#       session with reason liveness within 60 s (default 45 s timeout)
#   (7) while an agent keeps running, the techlist is re-signed without the
#       technician and published: the server pushes a signed TrustUpdate, the
#       live session is closed with reason tech_removed, and a new grant is
#       refused with unknown_tech
#   (8) the recording of check (2) exists, is valid asciicast v2, contains
#       e2e-shell-ok and matches the hash stored on the session
#
# The WebSocket goes straight to the API's loopback port (RMM_API_PORT):
# deploy/nginx/nginx.conf does not forward upgrades on /api/ yet.
#
# The agent runs as root in a private mount namespace with a fake /sys/class/dmi
# (same conventions as scripts/e2e-actions.sh). Needs root or passwordless
# sudo, docker, cargo, curl and python3.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=${RMM_HTTPS_PORT:-443}
export RMM_HTTPS_PORT=$PORT
COMPOSE=(docker compose -f deploy/compose.yaml)
CA=$ROOT/deploy/dev/certs/ca.pem
TRUST=$ROOT/deploy/dev/trust
WEBAUTHN=$ROOT/deploy/dev/webauthn
SERVER=https://localhost:$PORT
SUDO=()
[[ $(id -u) -eq 0 ]] || SUDO=(sudo)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/rmm-e2e-shell.XXXXXX")
BG_PID=
SESSION_PID=
ADMIN=
TECH_TOKEN=
TECH=
C1=
LIVENESS_BUDGET=60
RSS_LIMIT_KB=51200
BIG_BYTES=1073741824 # 1 GiB

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
q() {
  "${COMPOSE[@]}" exec -T timescale psql -U rmm -d rmm -v ON_ERROR_STOP=1 -tAq \
    -c "SET rmm.service = 'on'; $1"
}
cleanup() {
  local rc=$?
  stop_agent
  [[ -z $SESSION_PID ]] || kill "$SESSION_PID" 2>/dev/null || true
  # Leave the dev database without this run's technician: the techlist stored
  # last (check 7) already excludes it, and its sessions and recordings go.
  if [[ -n $TECH && -n $C1 ]]; then
    q "delete from tenant.shell_session where tech_id = '$TECH';
       delete from msp.webauthn_credential where tech_id = '$TECH';
       delete from msp.technician_client where tech_id = '$TECH';
       delete from msp.technician where tech_id = '$TECH'" >/dev/null 2>&1 || true
    "${SUDO[@]}" rm -rf "$ROOT/deploy/dev/recordings/$C1" 2>/dev/null || true
  fi
  "${SUDO[@]}" rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

# The dev stack must know the dev attestation root and AAGUID (deploy/.env may
# predate them).
[[ -f deploy/.env ]] || cp deploy/.env.example deploy/.env
for k in RMM_WEBAUTHN_ATTESTATION_ROOTS RMM_WEBAUTHN_AAGUIDS RMM_RECORDING_RETENTION_DAYS RMM_API_PORT; do
  grep -q "^$k=" deploy/.env || grep "^$k=" deploy/.env.example >>deploy/.env
done
API_PORT=$(sed -n 's/^RMM_API_PORT=//p' deploy/.env)
API_PORT=${API_PORT:-8080}

scripts/dev-up.sh

AAGUID=$(cat "$WEBAUTHN/aaguid.hex")
[[ ${#AAGUID} -eq 32 ]] || fail "no dev AAGUID in $WEBAUTHN/aaguid.hex"
[[ $(sed -n 's/^RMM_WEBAUTHN_AAGUIDS=//p' deploy/.env) == "$AAGUID" ]] \
  || fail "deploy/.env RMM_WEBAUTHN_AAGUIDS is not the dev AAGUID $AAGUID"

RMM_ROOT_PUBKEYS=$(sed -n 's/^RMM_ROOT_PUBKEYS=//p' deploy/.env) cargo build -q --locked -p rmm-agent
cargo build -q --locked -p rmm-session -p xtask -p rmm-sign
AGENT=$ROOT/target/debug/rmm-agent
RMM_SESSION=$ROOT/target/debug/rmm-session
XTASK=$ROOT/target/debug/xtask

curl_api() { curl -sS --noproxy '*' --cacert "$CA" "$@"; }
jget() { python3 -I -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[k]
print(v if v is not None else "")' "$@"; }

ADMIN=$("${COMPOSE[@]}" exec -T api rmm-server dev-token --role RMM.Admin --sub e2e-shell-admin)
tag=$RANDOM$RANDOM
TECH=e2e-tech-$tag
TECH_TOKEN=$("${COMPOSE[@]}" exec -T api rmm-server dev-token --role RMM.Technician --sub "$TECH")
[[ -n $ADMIN && -n $TECH_TOKEN ]] || fail "dev-token"

C1=$(q "insert into tenant.client (name) values ('e2e-shell-$tag') returning id")
S1=$(q "insert into tenant.site (client_id, name) values ('$C1', 'site-a') returning id")
[[ -n $C1 && -n $S1 ]] || fail "create client and site"

# ---------------------------------------------------------------- helpers

# A tiny RFC 6455 client (stdlib only; websocat/websockets are not required).
# Usage: wsclient.py URL STEP...   where a step is one of
#   send:TEXT   binary frame (\n, \r, \x03 escapes)      expect:REGEX  wait for output
#   resize:CxR  text frame                               close         send a close frame
#   hold        write READY and sleep (to be killed)     drain         read until the peer closes
#   touch:FILE  create FILE                              waitfile:FILE wait for FILE to exist
# Output of the shell is searched as latin-1; control frames show up as
# "[ctl] {json}". Exit: 0 ok, 3 timeout, 4 peer closed early, 5 handshake refused.
cat >"$WORK/wsclient.py" <<'PY'
import base64, codecs, json, os, re, socket, struct, sys, time, urllib.parse

url, steps = sys.argv[1], sys.argv[2:]
TIMEOUT = float(os.environ.get("WS_TIMEOUT", "30"))
u = urllib.parse.urlparse(url)
sock = socket.create_connection((u.hostname, u.port or 80), timeout=10)
key = base64.b64encode(os.urandom(16)).decode()
path = u.path + ("?" + u.query if u.query else "")
sock.sendall(("GET %s HTTP/1.1\r\nHost: %s:%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
              % (path, u.hostname, u.port or 80, key)).encode())
raw = b""
while b"\r\n\r\n" not in raw:
    chunk = sock.recv(4096)
    if not chunk:
        break
    raw += chunk
head, _, rest = raw.partition(b"\r\n\r\n")
status = head.split(b"\r\n")[0].decode("latin-1", "replace")
if " 101 " not in status:
    print("HANDSHAKE", status, file=sys.stderr)
    sys.exit(5)
inbuf = bytearray(rest)
sock.settimeout(1.0)
rx_bytes = 0
window = b""
closed = False

def need(n):
    global closed
    while len(inbuf) < n:
        try:
            chunk = sock.recv(1 << 16)
        except socket.timeout:
            return False
        except OSError:
            closed = True
            return False
        if not chunk:
            closed = True
            return False
        inbuf.extend(chunk)
    return True

def send(opcode, payload=b""):
    mask = os.urandom(4)
    n = len(payload)
    hdr = bytes([0x80 | opcode])
    if n < 126:
        hdr += bytes([0x80 | n])
    elif n < 65536:
        hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(hdr + mask + body)

def frame():
    """Next complete message: (opcode, payload), or None on timeout/close."""
    global inbuf
    msg_op, msg = None, b""
    while True:
        if not need(2):
            return None
        b0, b1 = inbuf[0], inbuf[1]
        n, off = b1 & 0x7F, 2
        if n == 126:
            if not need(4): return None
            n, off = struct.unpack(">H", bytes(inbuf[2:4]))[0], 4
        elif n == 127:
            if not need(10): return None
            n, off = struct.unpack(">Q", bytes(inbuf[2:10]))[0], 10
        if not need(off + n):
            return None
        payload = bytes(inbuf[off:off + n])
        del inbuf[:off + n]
        op = b0 & 0x0F
        if op == 0x9:
            send(0xA, payload)
            continue
        if op == 0xA:
            continue
        if op != 0:
            msg_op = op
        msg += payload
        if b0 & 0x80:
            return msg_op, msg

def pump(deadline):
    """Read one message into the search window; False on timeout/close."""
    global window, rx_bytes
    while time.time() < deadline:
        f = frame()
        if f is None:
            if closed:
                return False
            continue
        op, payload = f
        if op == 0x8:
            window += b"\n[ctl] {\"type\": \"closed-frame\"}\n"
            return False
        if op == 0x2:
            rx_bytes += len(payload)
            window += payload
        elif op == 0x1:
            window += b"\n[ctl] " + payload + b"\n"
        window = window[-(1 << 16):]
        return True
    return False

for step in steps:
    kind, _, arg = step.partition(":")
    deadline = time.time() + TIMEOUT
    if kind == "send":
        send(0x2, codecs.decode(arg, "unicode_escape").encode("latin-1"))
    elif kind == "resize":
        c, r = arg.split("x")
        send(0x1, json.dumps({"type": "resize", "cols": int(c), "rows": int(r)}).encode())
    elif kind == "expect":
        rx = re.compile(arg.encode(), re.S)
        while True:
            m = rx.search(window)
            if m:
                window = window[m.end():]
                break
            if not pump(deadline):
                print("EXPECT failed (%s): %r" % ("closed" if closed or b"closed-frame" in window else "timeout", arg),
                      file=sys.stderr)
                print("TAIL", window[-600:], file=sys.stderr)
                sys.exit(4 if closed or b"closed-frame" in window else 3)
    elif kind == "close":
        send(0x8, struct.pack(">H", 1000))
        pump(time.time() + 3)
    elif kind == "drain":
        while pump(deadline):
            pass
    elif kind == "hold":
        print("READY", flush=True)
        time.sleep(3600)
    elif kind == "touch":
        open(arg, "w").close()
    elif kind == "waitfile":
        while not os.path.exists(arg):
            if time.time() > deadline:
                sys.exit(3)
            pump(time.time() + 0.5)
    else:
        sys.exit("unknown step " + step)
print("RX_BYTES", rx_bytes)
PY

new_machine() {
  local m=$WORK/$1-machine
  mkdir -p "$m/dmi/id"
  python3 -c 'import uuid; print(uuid.uuid4())' >"$m/dmi/id/product_uuid"
  echo "E2E-SYS-$RANDOM$RANDOM" >"$m/dmi/id/product_serial"
  echo "E2E-BRD-$RANDOM$RANDOM" >"$m/dmi/id/board_serial"
  echo "RMM e2e" >"$m/dmi/id/sys_vendor"
  echo "Simulated" >"$m/dmi/id/product_name"
}

agent_cmd() { # <name> [ENV=value...]: sets CMD
  local name=$1
  shift
  # shellcheck disable=SC2016 # expanded by the inner sh
  CMD=("${SUDO[@]}" env RMM_AGENT_EXTRA_CA="$CA" RUST_LOG="${RUST_LOG:-info}" NO_PROXY='*'
    RMM_AGENT_TELEMETRY_INTERVALS="hb=5,metric=30,inv=60" RMM_AGENT_TEST_PLATFORM=1
    RMM_INDICATOR_SOCKET="$WORK/indicator.sock" "$@"
    unshare --mount --propagation private
    sh -c 'mount --bind "$1" /sys/class && shift && exec "$@"' sh "$WORK/$name-machine" "$AGENT")
}

enroll() { # <name>: sets AG and DIR
  new_machine "$1"
  local body token out
  body=$(curl_api -f -X POST "$SERVER/api/v1/enrollment-tokens" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$C1\",\"site_id\":\"$S1\",\"expires_in_hours\":1,\"max_uses\":1,\"allow_reattach\":false}") \
    || fail "create enrollment token"
  token=$(jget token <<<"$body")
  DIR=$WORK/$1-state
  agent_cmd "$1"
  out=$("${CMD[@]}" enroll --server "$SERVER" --token "$token" --state-dir "$DIR") || fail "enroll $1"
  AG=$(sed -n 's/^enrolled: agent_id=\([^ ]*\) status=\(.*\)$/\1/p' <<<"$out")
  [[ -n $AG ]] || fail "no agent id in enroll output: $out"
  [[ $(q "select status from tenant.agent where id = '$AG'") == active ]] || fail "agent $AG is not active"
}

AGENT_LOG=$WORK/agent.log
start_agent() { # <name>
  : >"$AGENT_LOG"
  agent_cmd "$1"
  "${CMD[@]}" run --state-dir "$DIR" >"$AGENT_LOG" 2>&1 &
  BG_PID=$!
  for _ in $(seq 1 60); do
    grep -q 'nats connected' "$AGENT_LOG" && return 0
    sleep 0.5
  done
  fail "agent did not connect: $(cat "$AGENT_LOG")"
}

agent_pid() { # the rmm-agent process of the current state dir
  local p
  for p in $(pgrep -f "run --state-dir $DIR" || true); do
    [[ $(cat "/proc/$p/comm" 2>/dev/null) == rmm-agent ]] && { echo "$p"; return 0; }
  done
  return 1
}
rss_kb() { awk '/^VmRSS:/ {print $2}' "/proc/$1/status"; }
# The agent log carries ANSI colour codes; strip them before matching fields.
plain_log() { sed 's/\x1b\[[0-9;]*m//g' "$AGENT_LOG"; }
log_count() { grep -c -- "$1" "$AGENT_LOG" || true; }
await_log() { # <regex> <seconds> <what>
  local deadline=$((SECONDS + $2))
  until grep -Eq -- "$1" <<<"$(plain_log)"; do
    ((SECONDS < deadline)) || fail "$3: no agent log line matching '$1' after $2 s; agent log: $(tail -n 15 "$AGENT_LOG")"
    sleep 0.5
  done
}

put_trust() { # <kind> <file>: prints the HTTP status
  curl_api -o "$WORK/put.out" -w '%{http_code}' -X PUT "$SERVER/api/v1/trust/$1" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/octet-stream' --data-binary "@$2"
}

# publish_techlist <name> [python-edit]: export the draft, optionally edit it
# (python reads the JSON on stdin as `d` and my tech as `t`), sign with the
# dev catalog key and publish.
publish_techlist() {
  curl_api -f "$SERVER/api/v1/admin/techlist-draft" -H "Authorization: Bearer $ADMIN" \
    -o "$WORK/$1.draft.json" || fail "export techlist draft"
  TECH=$TECH EDIT=${2:-} python3 -I - "$WORK/$1.draft.json" <<'PY' || fail "edit techlist draft"
import json, os, sys
path = sys.argv[1]
d = json.load(open(path))
t = next((x for x in d["techs"] if x["tech_id"] == os.environ["TECH"]), None)
edit = os.environ["EDIT"]
if edit == "wrong-key":
    # A key the API never stored: the agent cannot parse or match it.
    c = t["creds"][0]
    c["cose_pubkey"] = c["cose_pubkey"][:-2] + ("00" if c["cose_pubkey"][-2:] != "00" else "01")
elif edit == "remove-tech":
    d["techs"] = [x for x in d["techs"] if x["tech_id"] != os.environ["TECH"]]
elif edit:
    sys.exit("unknown edit " + edit)
json.dump(d, open(path, "w"))
PY
  RMM_SIGN_PASSPHRASE=dev-only cargo run -q --locked -p rmm-sign -- sign --type techlist \
    --in "$WORK/$1.draft.json" --backend "file:$TRUST/catalog.age" --allow-aaguid "$AAGUID" \
    --out "$WORK/$1.env" --yes --force >/dev/null 2>"$WORK/sign.err" \
    || fail "sign techlist $1: $(cat "$WORK/sign.err")"
  [[ $(put_trust techlist "$WORK/$1.env") == 204 ]] || fail "publish techlist $1: $(cat "$WORK/put.out")"
}

# open_shell <agent> <shell> [max_duration_secs]: grant, co-sign with the fake
# key, open. Sets GRANT_HTTP/OPEN_HTTP, SID and WS_URL (a ws:// URL).
open_shell() {
  local body=\{\"shell\":\"$2\"
  [[ -z ${3:-} ]] || body+=,\"max_duration_secs\":$3
  body+=\}
  GRANT_HTTP=$(curl_api -o "$WORK/grant.json" -w '%{http_code}' -X POST "$SERVER/api/v1/agents/$1/shell" \
    -H "Authorization: Bearer $TECH_TOKEN" -H 'Content-Type: application/json' -d "$body")
  [[ $GRANT_HTTP == 201 ]] || fail "grant: HTTP $GRANT_HTTP $(cat "$WORK/grant.json")"
  "$XTASK" fake-authn assert --grant-response "$WORK/grant.json" --dir "$WORK/authn" >"$WORK/open-req.json" \
    || fail "fake-authn assert"
  OPEN_HTTP=$(curl_api -o "$WORK/open.json" -w '%{http_code}' -X POST \
    "$SERVER/api/v1/shell-sessions/$(jget grant_id_b64url <"$WORK/grant.json")/open" \
    -H "Authorization: Bearer $TECH_TOKEN" -H 'Content-Type: application/json' --data-binary "@$WORK/open-req.json")
  [[ $OPEN_HTTP == 200 ]] || fail "open: HTTP $OPEN_HTTP $(cat "$WORK/open.json")"
  SID=$(jget session_id <"$WORK/open.json")
  WS_URL="ws://127.0.0.1:$API_PORT$(jget ws_url <"$WORK/open.json")"
}

ws() { python3 -I "$WORK/wsclient.py" "$@"; }
session_state() { # last indicator state line seen by rmm-session
  grep -E '"state": ?"' "$WORK/session.log" | tail -n 1 | sed -n 's/.*"state": \?"\([a-z]*\)".*/\1/p'
}
await_state() { # <state> <seconds>
  local deadline=$((SECONDS + $2))
  until [[ $(session_state) == "$1" ]]; do
    ((SECONDS < deadline)) || fail "rmm-session never showed '$1' (last '$(session_state)'); log: $(cat "$WORK/session.log")"
    sleep 0.5
  done
}
close_reason() { q "select coalesce(close_reason, '') from tenant.shell_session where grant_id = decode('$1', 'hex')"; }
await_closed() { # <sid> <seconds>: prints the close reason
  local deadline=$((SECONDS + $2)) r
  while :; do
    r=$(close_reason "$1")
    [[ -z $r ]] || { echo "$r"; return 0; }
    ((SECONDS < deadline)) || fail "session $1 not closed in the database after $2 s"
    sleep 0.5
  done
}

# ------------------------------------------------- technician and techlist

mkdir -p "$WORK/authn"
reg=$("$XTASK" fake-authn register --api "$SERVER" --token "$TECH_TOKEN" --dir "$WORK/authn" \
  --ca "$WEBAUTHN" --cacert "$CA") || fail "register the fake credential"
[[ $(jget aaguid_hex <<<"$reg") == "$AAGUID" ]] || fail "registered AAGUID differs: $reg"
q "insert into msp.technician_client (tech_id, client_id) values ('$TECH', '$C1')" >/dev/null

RMM_INDICATOR_SOCKET="$WORK/indicator.sock" "$RMM_SESSION" >"$WORK/session.log" 2>&1 </dev/null &
SESSION_PID=$!

# ------------------------------------------------------------------- (1)

publish_techlist bad wrong-key
enroll agent-bad
start_agent agent-bad
STARTED=$(log_count "shell session started")
open_shell "$AG" sh
await_log 'shell open rejected' 30 "(1)"
grep -Eq 'reason="?bad_assertion"?' <<<"$(plain_log)" \
  || fail "(1) agent did not refuse with bad_assertion: $(grep 'shell open' "$AGENT_LOG")"
sleep 1
[[ $(log_count "shell session started") -eq $STARTED ]] || fail "(1) a shell started although the assertion could not be verified"
[[ $(session_state) != connected ]] || fail "(1) the indicator shows connected"
pass "(1) agent refused the ShellOpen with bad_assertion; no shell started"
stop_agent

# ---------------------------------------------------- the good techlist

publish_techlist good
enroll agent-good
start_agent agent-good
AGENT_PID=$(agent_pid) || fail "cannot find the agent process"
BASE_RSS=$(rss_kb "$AGENT_PID")

# (2) and (3): round trip, indicator, exit.
STARTED=$(log_count "shell session started")
open_shell "$AG" sh
S1_ID=$SID
S1_URL=$WS_URL
WS_TIMEOUT=60 ws "$S1_URL" "resize:100x30" 'send:echo e2e-shell-ok\n' 'expect:(^|\n)e2e-shell-ok\r?\n' \
  "touch:$WORK/s1.ready" "waitfile:$WORK/s1.go" 'send:exit\n' 'expect:\[ctl\].*"type":"exit"' \
  >"$WORK/ws1.out" 2>"$WORK/ws1.err" &
WS1=$!
for _ in $(seq 1 80); do
  [[ -e $WORK/s1.ready ]] && break
  kill -0 "$WS1" 2>/dev/null || fail "(2) the WebSocket client ended early: $(cat "$WORK/ws1.err")"
  sleep 0.5
done
[[ -e $WORK/s1.ready ]] || fail "(2) 'echo e2e-shell-ok' never came back: $(cat "$WORK/ws1.err")"
[[ $(log_count "shell session started") -eq $((STARTED + 1)) ]] || fail "(2) the agent did not log a started session"
await_state connected 20
grep -Eq "\"tech\": ?\"$TECH\"" "$WORK/session.log" || fail "(3) the indicator did not name $TECH: $(cat "$WORK/session.log")"
touch "$WORK/s1.go"
wait "$WS1" || fail "(2) exiting the shell: $(cat "$WORK/ws1.err")"
pass "(2) 'echo e2e-shell-ok' round-tripped through the relay; the shell exited"
await_state idle 20
pass "(3) rmm-session showed connected for $TECH while the session was open, idle after"
[[ $(await_closed "$S1_ID" 20) == exit ]] || fail "(2) close reason is '$(close_reason "$S1_ID")', want exit"
# The ticket was single use.
set +e
WS_TIMEOUT=10 ws "$S1_URL" "send:x" >/dev/null 2>"$WORK/reuse.err"
rc=$?
set -e
[[ $rc -eq 5 ]] && grep -q ' 401 ' "$WORK/reuse.err" || fail "(2) a used WebSocket ticket was not refused with 401 (rc $rc): $(cat "$WORK/reuse.err")"
pass "(2) the WebSocket ticket cannot be used twice (401)"

# (8) The recording of that session.
curl_api -f "$SERVER/api/v1/shell-sessions/$S1_ID/recording" -H "Authorization: Bearer $ADMIN" \
  -D "$WORK/rec.headers" -o "$WORK/rec.cast" || fail "(8) download the recording"
grep -qi '^content-type: application/x-asciicast' "$WORK/rec.headers" || fail "(8) wrong content type: $(cat "$WORK/rec.headers")"
curl_api -s -o /dev/null -w '%{http_code}' "$SERVER/api/v1/shell-sessions/$S1_ID/recording" \
  -H "Authorization: Bearer $TECH_TOKEN" | grep -q 403 || fail "(8) a technician token could download the recording"
python3 -I - "$WORK/rec.cast" <<'PY' || fail "(8) the recording is not valid asciicast v2 with the session in it"
import json, re, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
head = json.loads(lines[0])
assert head["version"] == 2 and head["width"] > 0 and head["height"] > 0 and head["timestamp"] > 1_600_000_000, head
out, last, kinds = "", 0.0, set()
for l in lines[1:]:
    t, kind, data = json.loads(l)
    assert isinstance(t, (int, float)) and t >= last and kind in ("o", "i", "r") and isinstance(data, str), l
    last = t
    kinds.add(kind)
    if kind == "o":
        out += data
assert re.search(r"(^|\n)e2e-shell-ok\r?\n", out), "no e2e-shell-ok in the output events"
assert kinds >= {"o", "i", "r"}, kinds
PY
want=$(sha256sum "$WORK/rec.cast" | cut -d' ' -f1)
got=$(q "select encode(recording_sha256, 'hex') || ' ' || recording_bytes from tenant.shell_session where grant_id = decode('$S1_ID', 'hex')")
[[ $got == "$want $(stat -c %s "$WORK/rec.cast")" ]] || fail "(8) stored hash/size '$got' differ from the file ($want)"
pass "(8) recording is valid asciicast v2 with e2e-shell-ok; its hash and size match the database"

# (4) 1 GiB of output.
open_shell "$AG" sh
LINE=$(printf 'a%.0s' $(seq 1 100))
: >"$WORK/rss.txt"
(while :; do rss_kb "$AGENT_PID" >>"$WORK/rss.txt" 2>/dev/null || break; sleep 1; done) &
SAMPLER=$!
set +e
WS_TIMEOUT=1800 ws "$WS_URL" "send:yes $LINE | head -c $BIG_BYTES; echo BIG-DONE-\$((40+2))\n" 'expect:BIG-DONE-42' \
  'send:exit\n' 'expect:\[ctl\].*"type":"exit"' >"$WORK/ws4.out" 2>"$WORK/ws4.err"
rc=$?
set -e
kill "$SAMPLER" 2>/dev/null || true
wait "$SAMPLER" 2>/dev/null || true
[[ $rc -eq 0 ]] || fail "(4) printing 1 GiB did not complete (rc $rc): $(tail -c 600 "$WORK/ws4.err")"
rx=$(sed -n 's/^RX_BYTES //p' "$WORK/ws4.out")
[[ ${rx:-0} -ge $BIG_BYTES ]] || fail "(4) only ${rx:-0} bytes arrived, want at least $BIG_BYTES"
MAX_RSS=$(sort -n "$WORK/rss.txt" | tail -n 1)
[[ -n $MAX_RSS ]] || fail "(4) no RSS samples"
((MAX_RSS < RSS_LIMIT_KB)) || fail "(4) agent VmRSS reached $MAX_RSS kB (limit $RSS_LIMIT_KB kB, idle $BASE_RSS kB)"
# VmHWM is the kernel's own peak, so a spike between two samples still counts.
HWM_KB=$(awk '/^VmHWM:/ {print $2}' "/proc/$AGENT_PID/status")
[[ -n $HWM_KB ]] || fail "(4) cannot read the agent's VmHWM"
((HWM_KB < RSS_LIMIT_KB)) || fail "(4) agent VmHWM reached $HWM_KB kB (limit $RSS_LIMIT_KB kB)"
pass "(4) 1 GiB ($rx bytes) printed; agent VmRSS peaked at $MAX_RSS kB, VmHWM $HWM_KB kB (idle $BASE_RSS kB, limit $RSS_LIMIT_KB kB, $(wc -l <"$WORK/rss.txt") samples)"

# (5) max_duration.
open_shell "$AG" sh 5
S5_ID=$SID
WS_TIMEOUT=30 ws "$WS_URL" 'expect:\[ctl\].*max_duration' >/dev/null 2>"$WORK/ws5.err" \
  || fail "(5) no max_duration close within 30 s: $(cat "$WORK/ws5.err")"
[[ $(await_closed "$S5_ID" 20) == max_duration ]] || fail "(5) close reason is '$(close_reason "$S5_ID")', want max_duration"
pass "(5) a 5 s grant was closed with reason max_duration"

# (6) A browser that dies without a close frame: the agent's liveness timer ends it.
open_shell "$AG" sh
S6_ID=$SID
# Run the client directly (not through the ws function) so $! is the client
# itself and kill -9 really drops the socket without a close frame.
python3 -I "$WORK/wsclient.py" "$WS_URL" 'send:echo alive-$((1+1))\n' 'expect:alive-2' hold >"$WORK/ws6.out" 2>"$WORK/ws6.err" &
WS6=$!
for _ in $(seq 1 60); do
  grep -q READY "$WORK/ws6.out" && break
  kill -0 "$WS6" 2>/dev/null || fail "(6) the WebSocket client ended early: $(cat "$WORK/ws6.err")"
  sleep 0.5
done
grep -q READY "$WORK/ws6.out" || fail "(6) the session never answered: $(cat "$WORK/ws6.err")"
CLOSED_BEFORE=$(log_count "shell session closed")
kill -9 "$WS6"
wait "$WS6" 2>/dev/null || true
T0=$SECONDS
await_log "shell session closed.*liveness" "$LIVENESS_BUDGET" "(6)"
[[ $(log_count "shell session closed") -eq $((CLOSED_BEFORE + 1)) ]] || fail "(6) unexpected number of closed sessions"
[[ $(await_closed "$S6_ID" 20) == browser_disconnect ]] || fail "(6) close reason is '$(close_reason "$S6_ID")', want browser_disconnect"
pass "(6) the agent closed the abandoned session with liveness $((SECONDS - T0)) s after the browser died (budget $LIVENESS_BUDGET s)"
await_state idle 20

# (7) The technician leaves the techlist while the agent keeps running: the
# server pushes a signed TrustUpdate, the agent closes the live session with
# tech_removed and refuses a new grant with unknown_tech.
open_shell "$AG" sh
S7_ID=$SID
python3 -I "$WORK/wsclient.py" "$WS_URL" 'send:echo alive-$((3+4))\n' 'expect:alive-7' hold >"$WORK/ws7.out" 2>"$WORK/ws7.err" &
WS7=$!
for _ in $(seq 1 60); do
  grep -q READY "$WORK/ws7.out" && break
  kill -0 "$WS7" 2>/dev/null || fail "(7) the WebSocket client ended early: $(cat "$WORK/ws7.err")"
  sleep 0.5
done
grep -q READY "$WORK/ws7.out" || fail "(7) the session never answered: $(cat "$WORK/ws7.err")"
[[ -z $(close_reason "$S7_ID") ]] || fail "(7) the session was closed before the techlist changed"
publish_techlist gone remove-tech
[[ $(await_closed "$S7_ID" 30) == tech_removed ]] || fail "(7) close reason is '$(close_reason "$S7_ID")', want tech_removed"
kill -9 "$WS7" 2>/dev/null || true
wait "$WS7" 2>/dev/null || true
pass "(7) removing $TECH from the published techlist closed the live session of the running agent: tech_removed"
STARTED=$(log_count "shell session started")
open_shell "$AG" sh
await_log 'shell open rejected' 30 "(7)"
grep -Eq 'reason="?unknown_tech"?' <<<"$(plain_log)" \
  || fail "(7) agent did not refuse with unknown_tech: $(grep 'shell open' "$AGENT_LOG")"
sleep 1
[[ $(log_count "shell session started") -eq $STARTED ]] || fail "(7) a shell started for a removed technician"
pass "(7) the running agent refuses a new grant for the removed technician: unknown_tech"

echo "e2e shell: all checks passed"
