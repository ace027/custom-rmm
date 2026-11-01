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
compose=(docker compose -f deploy/compose.yaml)
"${compose[@]}" up -d
# nginx resolves upstream names once at start; reload it so a recreated api
# container (new image, new IP) does not leave it proxying to a dead address.
"${compose[@]}" exec -T nginx nginx -s reload >/dev/null 2>&1 || true
exec "${compose[@]}" up -d --wait
