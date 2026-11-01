#!/usr/bin/env bash
# End-to-end signed commands against the dev stack. A debug Linux agent on the
# test platform (RMM_AGENT_TEST_PLATFORM=1: fake service manager, spool root
# <state_dir>/test-spool) enrolls, receives server-signed commands over NATS
# and reports agent-signed results. Checks:
#   (1) the spooler action succeeds: stages precheck/snapshot/steps/verify ok in
#       order, the signed result was verified server-side (audit row
#       action.result), the spool files moved into the agent's quarantine dir
#   (2) with RMM_AGENT_FAKE_FAIL_START=Spooler the service never comes back, the
#       action ends rolled_back, rollback ran and the spool files are restored
#   (3) a definition on the revocation list is rejected (reason revoked) by the
#       agent, which touches nothing
#   (4) a result with a forged signature published on the agent's result subject
#       changes nothing
#
# Check (3) needs an agent that knows the revocation while the server's issue
# path does not (the API itself refuses to issue a revoked definition). So the
# revocations are uploaded, a second agent enrolls (its trust bundle carries
# them), and then the just-uploaded revocations row is deleted from the
# database, as if the server had missed it.
#
# The agent runs as root in a private mount namespace with a fake /sys/class/dmi
# (same conventions as scripts/e2e-telemetry.sh). Needs root or passwordless
# sudo, docker, cargo, curl and python3. On exit an empty revocations document
# with a higher seq is uploaded so a rerun starts with nothing revoked.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=${RMM_HTTPS_PORT:-443}
export RMM_HTTPS_PORT=$PORT
COMPOSE=(docker compose -f deploy/compose.yaml)
CA=$ROOT/deploy/dev/certs/ca.pem
TRUST=$ROOT/deploy/dev/trust
SERVER=https://localhost:$PORT
SUDO=()
[[ $(id -u) -eq 0 ]] || SUDO=(sudo)
RUN_BUDGET=120

WORK=$(mktemp -d "${TMPDIR:-/tmp}/rmm-e2e-actions.XXXXXX")
BG_PID=
ADMIN=
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

# Upload a revocations document that revokes nothing, with a seq above every
# earlier one (nanosecond timestamps), so reruns do not inherit a revocation.
sign_revocations() { # <out> <hash-or-empty>
  local now hashes=
  now=$(date +%s)
  [[ -z $2 ]] || hashes="\"$2\""
  cat >"$WORK/rev.json" <<JSON
{"seq": $(date +%s%N), "issued_at": $((now - 60)), "expires_at": $((now + 45 * 86400)), "revoked_hashes": [$hashes]}
JSON
  RMM_SIGN_PASSPHRASE=dev-only cargo run -q --locked -p rmm-sign -- sign --type revocations \
    --in "$WORK/rev.json" --backend "file:$TRUST/catalog.age" --out "$1" --yes --force >/dev/null 2>&1
}
put_trust() { # <kind> <file>: prints the HTTP status
  curl -sS --noproxy '*' --cacert "$CA" -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    "$SERVER/api/v1/trust/$1" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$2"
}
cleanup() {
  local rc=$?
  stop_agent
  if [[ -n $ADMIN ]]; then
    if sign_revocations "$WORK/clear.env" "" && [[ $(put_trust revocations "$WORK/clear.env") == 204 ]]; then
      echo "cleared revocations" >&2
    else
      echo "warning: could not upload a clearing revocations document: $(cat "$WORK/put.out" 2>/dev/null)" >&2
    fi
  fi
  "${SUDO[@]}" rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
pass() { echo "PASS $*"; }

scripts/dev-up.sh

RMM_ROOT_PUBKEYS=$(sed -n 's/^RMM_ROOT_PUBKEYS=//p' deploy/.env) cargo build -q --locked -p rmm-agent
AGENT=$ROOT/target/debug/rmm-agent

q() {
  "${COMPOSE[@]}" exec -T timescale psql -U rmm -d rmm -v ON_ERROR_STOP=1 -tAq \
    -c "SET rmm.service = 'on'; $1"
}
curl_api() { curl -sS --noproxy '*' --cacert "$CA" "$@"; }
jget() { python3 -I -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[k]
print(v if v is not None else "")' "$@"; }

ADMIN=$("${COMPOSE[@]}" exec -T api rmm-server dev-token --role RMM.Admin --sub e2e-actions)
[[ -n $ADMIN ]] || fail "dev-token"

# The signed spooler definition is loaded by dev-up.sh; re-upload for its content id.
body=$(curl_api -f -X PUT "$SERVER/api/v1/catalog" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary "@$TRUST/printing.spooler-restart.env") || fail "upload spooler definition"
CID=$(jget content_id <<<"$body")
[[ ${#CID} -eq 64 ]] || fail "no content id in catalog response: $body"

tag=$RANDOM$RANDOM
C1=$(q "insert into tenant.client (name) values ('e2e-act-$tag') returning id")
S1=$(q "insert into tenant.site (client_id, name) values ('$C1', 'site-a') returning id")
[[ -n $C1 && -n $S1 ]] || fail "create client and site"

# new_machine <name>: a fake DMI tree so the fingerprint is strong and unique.
new_machine() {
  local m=$WORK/$1-machine
  mkdir -p "$m/dmi/id"
  python3 -c 'import uuid; print(uuid.uuid4())' >"$m/dmi/id/product_uuid"
  echo "E2E-SYS-$RANDOM$RANDOM" >"$m/dmi/id/product_serial"
  echo "E2E-BRD-$RANDOM$RANDOM" >"$m/dmi/id/board_serial"
  echo "RMM e2e" >"$m/dmi/id/sys_vendor"
  echo "Simulated" >"$m/dmi/id/product_name"
}

# agent_cmd <name> [ENV=value...]: sets CMD to the debug agent as root with the
# machine's fake DMI. Not run through a function in the background: $! must be
# the agent process.
agent_cmd() {
  local name=$1
  shift
  # shellcheck disable=SC2016 # expanded by the inner sh
  CMD=("${SUDO[@]}" env RMM_AGENT_EXTRA_CA="$CA" RUST_LOG="${RUST_LOG:-info}" NO_PROXY='*'
    RMM_AGENT_TELEMETRY_INTERVALS="hb=5,metric=30,inv=60" RMM_AGENT_TEST_PLATFORM=1 "$@"
    unshare --mount --propagation private
    sh -c 'mount --bind "$1" /sys/class && shift && exec "$@"' sh "$WORK/$name-machine" "$AGENT")
}

# enroll <name>: sets AG, DEV and DIR for the new agent.
enroll() {
  new_machine "$1"
  local body token out
  body=$(curl_api -f -X POST "$SERVER/api/v1/enrollment-tokens" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$C1\",\"site_id\":\"$S1\",\"expires_in_hours\":1,\"max_uses\":1,\"allow_reattach\":false}") \
    || fail "create enrollment token"
  token=$(jget token <<<"$body")
  DIR=$WORK/$1-state
  agent_cmd "$1"
  out=$("${CMD[@]}" enroll --server "$SERVER" --token "$token" --state-dir "$DIR") \
    || fail "enroll $1"
  AG=$(sed -n 's/^enrolled: agent_id=\([^ ]*\) status=\(.*\)$/\1/p' <<<"$out")
  [[ -n $AG ]] || fail "no agent id in enroll output: $out"
  [[ $(q "select status from tenant.agent where id = '$AG'") == active ]] \
    || fail "agent $AG is not active after enrolling"
}

# start_agent <name> [ENV=value...]: run in the background, wait for NATS.
start_agent() {
  local log=$WORK/agent.log
  : >"$log"
  agent_cmd "$@"
  "${CMD[@]}" run --state-dir "$DIR" >"$log" 2>&1 &
  BG_PID=$!
  for _ in $(seq 1 60); do
    grep -q 'nats connected' "$log" && return 0
    sleep 0.5
  done
  fail "agent did not connect: $(cat "$log")"
}

# issue: POST the spooler action to $AG; sets CMD_ID and CMD_HEX.
issue() {
  local resp
  resp=$(curl_api -f -X POST "$SERVER/api/v1/agents/$AG/actions" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"definition_content_id\":\"$CID\",\"params\":{}}") || fail "issue action: $resp"
  CMD_ID=$(jget cmd_id <<<"$resp")
  [[ -n $CMD_ID ]] || fail "no cmd_id in: $resp"
  CMD_HEX=${CMD_ID//-/}
}

# await_run: wait up to RUN_BUDGET s for the run to leave 'queued'; sets RUN (JSON).
await_run() {
  local deadline=$((SECONDS + RUN_BUDGET))
  while :; do
    RUN=$(curl_api -f "$SERVER/api/v1/action-runs/$CMD_ID" -H "Authorization: Bearer $ADMIN") \
      || fail "read action run $CMD_ID"
    [[ $(jget status <<<"$RUN") != queued ]] && return 0
    ((SECONDS < deadline)) || fail "run $CMD_ID still queued after $RUN_BUDGET s; agent log: $(tail -n 20 "$WORK/agent.log")"
    sleep 1
  done
}

audit_count() { q "select count(*) from msp.audit_event where action = 'action.result' and target = 'action_run:$CMD_ID'"; }

# seed_spool: three files with distinct content in the agent's spool root.
seed_spool() {
  "${SUDO[@]}" mkdir -p "$DIR/test-spool"
  for i in 1 2 3; do
    echo "job $tag $i $RANDOM" | "${SUDO[@]}" tee "$DIR/test-spool/$1-$i.spl" >/dev/null
  done
  SPOOL_SUM=$("${SUDO[@]}" sh -c "cd '$DIR/test-spool' && sha256sum *.spl")
}
spool_files() { "${SUDO[@]}" sh -c "ls '$DIR/test-spool' 2>/dev/null | wc -l"; }
spool_sum() { "${SUDO[@]}" sh -c "cd '$DIR/test-spool' && sha256sum *.spl 2>/dev/null"; }
quarantine_dirs() { "${SUDO[@]}" sh -c "ls '$DIR/quarantine' 2>/dev/null | wc -l"; }
quarantine_files() { "${SUDO[@]}" sh -c "find '$DIR/quarantine/$CMD_HEX' -type f 2>/dev/null | wc -l"; }

# stage_summary: "stage:ok" for each reported stage, in order.
stage_summary() {
  python3 -I -c '
import json, sys
st = json.load(sys.stdin)["stages"]
print(" ".join("%s:%s" % (s["stage"], "ok" if s["ok"] else "FAILED") for s in st))' <<<"$RUN"
}

enroll agent-a
start_agent agent-a

# (1) Success path.
seed_spool a
issue
await_run
status=$(jget status <<<"$RUN")
[[ $status == succeeded ]] || fail "(1) status $status, want succeeded; stages: $(stage_summary); run: $RUN; agent log: $(tail -n 20 "$WORK/agent.log")"
want="precheck:ok snapshot:ok steps:ok verify:ok"
[[ $(stage_summary) == "$want" ]] || fail "(1) stages '$(stage_summary)', want '$want'"
python3 -I -c '
import json, sys
st = json.load(sys.stdin)["stages"]
prev = 0
for s in st:
    assert s["started_at"] > 1_600_000_000 and s["started_at"] <= s["finished_at"], s
    assert s["started_at"] >= prev, "stages out of order: %r" % st
    prev = s["finished_at"]' <<<"$RUN" || fail "(1) stage timestamps are not sane: $RUN"
[[ $(audit_count) -eq 1 ]] || fail "(1) want exactly one action.result audit row for $CMD_ID, got $(audit_count)"
[[ $(q "select result_envelope is not null from tenant.action_run where cmd_id = '$CMD_ID'") == t ]] \
  || fail "(1) no result_envelope stored for $CMD_ID"
[[ $(spool_files) -eq 0 ]] || fail "(1) spool root still holds $(spool_files) file(s)"
[[ $(quarantine_files) -ge 3 ]] || fail "(1) quarantine dir $DIR/quarantine/$CMD_HEX holds $(quarantine_files) file(s), want 3"
RUN1_ID=$CMD_ID
RUN1_STATE=$(q "select status, finished_at, stages::text, md5(result_envelope) from tenant.action_run where cmd_id = '$RUN1_ID'")
RUN1_ENV=$(q "select encode(result_envelope, 'hex') from tenant.action_run where cmd_id = '$RUN1_ID'")
pass "(1) spooler action succeeded ($(stage_summary)); signed result audited; 3 spool files in quarantine"

# (2) Rollback: the Spooler never comes back after a start.
stop_agent
start_agent agent-a RMM_AGENT_FAKE_FAIL_START=Spooler
seed_spool b
BEFORE_SUM=$SPOOL_SUM
issue
await_run
status=$(jget status <<<"$RUN")
[[ $status == rolled_back ]] || fail "(2) status $status, want rolled_back; stages: $(stage_summary); run: $RUN"
summary=$(stage_summary)
[[ $summary == *"FAILED"* && $summary == *"rollback:ok"* ]] || fail "(2) want a failed stage and an ok rollback, got: $summary"
[[ $summary != *"rollback:FAILED"* ]] || fail "(2) rollback failed: $summary"
[[ $(audit_count) -eq 1 ]] || fail "(2) want one action.result audit row for $CMD_ID, got $(audit_count)"
[[ $(spool_sum) == "$BEFORE_SUM" ]] || fail "(2) spool files not restored; want:
$BEFORE_SUM
got:
$(spool_sum)"
pass "(2) failed start rolled back ($summary); spool files restored byte for byte"

# (4) A forged result changes nothing. The real result of run 1 with its last
# byte flipped (inside the signature) is published on the agent's own result
# subject; ingest must refuse it, leaving the run and its audit trail alone.
CMD_ID=$RUN1_ID
CMD_HEX=${CMD_ID//-/}
results_pending() {
  curl -sS --noproxy '*' 'http://127.0.0.1:8222/jsz?accounts=true&streams=true&consumers=true' |
    python3 -I -c '
import json, sys
d = json.load(sys.stdin)
n = None
for acc in d.get("account_details", []):
    for st in acc.get("stream_detail", []):
        for c in st.get("consumer_detail", []):
            if st.get("name") == "RESULT" and c.get("name") == "results":
                n = c["num_pending"] + c["num_ack_pending"]
print("none" if n is None else n)'
}
python3 -I -c '
import sys
b = bytearray(bytes.fromhex(sys.stdin.read().strip()))
b[-1] ^= 0x01
sys.stdout.buffer.write(bytes(b))' <<<"$RUN1_ENV" >"$WORK/forged.bin"
SEED=$WORK/agent.nk
"${SUDO[@]}" python3 scripts/nkey-seed.py "$DIR/agent.key" >"$SEED"
chmod 644 "$SEED"
docker run --rm -i --network host -v "$CA:/ca.pem:ro" -v "$SEED:/agent.nk:ro" \
  natsio/nats-box:latest nats --tlsca /ca.pem --nkey /agent.nk --timeout 10s \
  --server "wss://localhost:$PORT/nats" pub "result.$C1.$AG" --force-stdin \
  <"$WORK/forged.bin" >/dev/null 2>"$WORK/forged.err" || fail "(4) publish forged result: $(cat "$WORK/forged.err")"
deadline=$((SECONDS + 30))
until [[ $(results_pending) == 0 ]]; do
  ((SECONDS < deadline)) || fail "(4) RESULT consumer still has $(results_pending) pending message(s) 30 s after the forged publish"
  sleep 0.5
done
sleep 2
NOW_STATE=$(q "select status, finished_at, stages::text, md5(result_envelope) from tenant.action_run where cmd_id = '$RUN1_ID'")
[[ $NOW_STATE == "$RUN1_STATE" ]] || fail "(4) action_run $RUN1_ID changed after a forged result:
before: $RUN1_STATE
after:  $NOW_STATE"
[[ $(audit_count) -eq 1 ]] || fail "(4) audit rows for $RUN1_ID changed to $(audit_count) after a forged result"
pass "(4) forged result left action_run $RUN1_ID and its audit trail unchanged"

# (3) Revoked definition. Revoke the content id, enroll a second agent whose
# trust bundle carries the revocation, then delete the revocations row from the
# server's view so the API still issues the command.
stop_agent
REVSEQ=$(date +%s%N)
sign_revocations "$WORK/revoke.env" "$CID" || fail "(3) sign revocations"
[[ $(put_trust revocations "$WORK/revoke.env") == 204 ]] || fail "(3) upload revocations: $(cat "$WORK/put.out")"
code=$(curl_api -s -o /dev/null -w '%{http_code}' -X PUT "$SERVER/api/v1/catalog" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$TRUST/printing.spooler-restart.env")
[[ $code == 422 ]] || fail "(3) server accepted a revoked definition upload (HTTP $code)"
enroll agent-b
start_agent agent-b
[[ $(q "delete from msp.trust_artifact where kind = 'revocations' and seq >= $REVSEQ returning 1" | wc -l) -ge 1 ]] \
  || fail "(3) could not remove the uploaded revocations row"
seed_spool c
QDIRS=$(quarantine_dirs)
issue
await_run
status=$(jget status <<<"$RUN")
reason=$(jget reason <<<"$RUN")
[[ $status == rejected && $reason == revoked ]] || fail "(3) status $status reason '$reason', want rejected/revoked; run: $RUN"
[[ $(quarantine_dirs) -eq $QDIRS ]] || fail "(3) a quarantine dir appeared for the revoked definition"
[[ $(spool_sum) == "$SPOOL_SUM" ]] || fail "(3) spool files changed although the command was rejected"
[[ $(audit_count) -eq 1 ]] || fail "(3) want one action.result audit row for $CMD_ID, got $(audit_count)"
pass "(3) revoked definition rejected by the agent (reason revoked); nothing quarantined"

echo "e2e actions: all checks passed"
