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
exec docker compose -f deploy/compose.yaml up -d --wait
