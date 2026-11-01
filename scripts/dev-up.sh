#!/usr/bin/env bash
# Bring up the dev stack and wait until every service is healthy.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f deploy/.env ]]; then
  cp deploy/.env.example deploy/.env
  echo "notice: created deploy/.env from .env.example with default dev passwords; do not reuse outside throwaway dev" >&2
fi
# Set RMM_HTTPS_PORT (e.g. 8443) to avoid needing privileges for port 443.
# Set RMM_EXTRA_CA_FILE to a CA bundle path if builds need an extra CA.
scripts/dev-certs.sh
mkdir -p deploy/dev
[[ -f deploy/dev/empty-ca.pem ]] || : >deploy/dev/empty-ca.pem
# Build with plain docker build: compose v5 routes builds through bake, which
# demands --allow entitlements for network: host and the CA secret file.
ca=${RMM_EXTRA_CA_FILE:-deploy/dev/empty-ca.pem}
docker build --network host \
  --secret "id=extra_ca,src=$ca" \
  --build-arg "HTTPS_PROXY=${HTTPS_PROXY:-}" --build-arg "https_proxy=${HTTPS_PROXY:-}" \
  -f deploy/server.Dockerfile -t rmm-server:dev .

# Auth callout issuer: generate an account nkey once and keep it in deploy/.env.
if [[ -z $(sed -n 's/^RMM_AUTHD_ISSUER_SEED=//p' deploy/.env) ]]; then
  keys=$(docker run --rm rmm-server:dev gen-nkey --type account)
  seed=$(sed -n 's/^seed=//p' <<<"$keys")
  pub=$(sed -n 's/^public=//p' <<<"$keys")
  [[ $seed == SA* && $pub == A* ]] || { echo "error: gen-nkey failed" >&2; exit 1; }
  tmp=$(mktemp deploy/.env.XXXXXX)
  grep -v -e '^RMM_AUTHD_ISSUER_SEED=' -e '^RMM_AUTHD_ISSUER_PUBKEY=' deploy/.env >"$tmp" || true
  printf 'RMM_AUTHD_ISSUER_SEED=%s\nRMM_AUTHD_ISSUER_PUBKEY=%s\n' "$seed" "$pub" >>"$tmp"
  chmod 600 "$tmp"
  mv "$tmp" deploy/.env
  echo "generated auth callout issuer $pub in deploy/.env"
fi

# Dev technician-token issuer (RS256) used by `rmm-server dev-token`.
auth=deploy/dev/auth
if [[ ! -f $auth/dev-key.pem || ! -f $auth/dev-pub.pem ]]; then
  mkdir -p "$auth"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$auth/dev-key.pem" 2>/dev/null
  openssl rsa -in "$auth/dev-key.pem" -pubout -out "$auth/dev-pub.pem" 2>/dev/null
  # The server containers run as uid 10001; dev-only key, deploy/dev is gitignored.
  chmod 644 "$auth/dev-key.pem" "$auth/dev-pub.pem"
  echo "generated dev token issuer key in $auth"
fi

# Dev trust chain: keys, signed manifest, revocations and spooler definition.
roots=$(scripts/dev-trust.sh | sed -n 's/^ROOT_PUBKEYS=//p')
[[ -n $roots ]] || { echo "error: dev-trust.sh printed no ROOT_PUBKEYS" >&2; exit 1; }
if [[ $(sed -n 's/^RMM_ROOT_PUBKEYS=//p' deploy/.env) != "$roots" ]]; then
  tmp=$(mktemp deploy/.env.XXXXXX)
  grep -v -e '^RMM_ROOT_PUBKEYS=' deploy/.env >"$tmp" || true
  printf 'RMM_ROOT_PUBKEYS=%s\n' "$roots" >>"$tmp"
  chmod 600 "$tmp"
  mv "$tmp" deploy/.env
  echo "wrote RMM_ROOT_PUBKEYS to deploy/.env"
fi

compose=(docker compose -f deploy/compose.yaml)
"${compose[@]}" up -d
# nginx resolves upstream names once at start; reload it so a recreated api
# container (new image, new IP) does not leave it proxying to a dead address.
"${compose[@]}" exec -T nginx nginx -s reload >/dev/null 2>&1 || true
"${compose[@]}" up -d --wait

# Load the signed trust documents and the spooler definition through the API.
# A document already stored (or superseded by a newer seq) answers 409/422,
# which counts as success so reruns are idempotent.
port=$(sed -n 's/^RMM_HTTPS_PORT=//p' deploy/.env)
port=${RMM_HTTPS_PORT:-${port:-443}}
admin=$("${compose[@]}" exec -T api rmm-server dev-token --role RMM.Admin --sub dev-up)
[[ -n $admin ]] || { echo "error: dev-token failed" >&2; exit 1; }
upload() { # <path> <file>
  local code body
  body=$(mktemp)
  code=$(curl -sS --noproxy '*' --cacert deploy/dev/certs/ca.pem -o "$body" -w '%{http_code}' \
    -X PUT "https://localhost:$port$1" -H "Authorization: Bearer $admin" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$2")
  case $code in
    200 | 201 | 204) ;;
    409 | 422) echo "notice: $1 not changed ($code: $(head -c 200 "$body"))" >&2 ;;
    *) echo "error: PUT $1 returned $code: $(head -c 300 "$body")" >&2; rm -f "$body"; exit 1 ;;
  esac
  rm -f "$body"
}
upload /api/v1/trust/manifest deploy/dev/trust/manifest.env
upload /api/v1/trust/revocations deploy/dev/trust/revocations.env
upload /api/v1/catalog deploy/dev/trust/printing.spooler-restart.env
