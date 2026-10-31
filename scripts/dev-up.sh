#!/usr/bin/env bash
# Bring up the dev stack and wait until every service is healthy.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f deploy/.env ]] || cp deploy/.env.example deploy/.env
scripts/dev-certs.sh
mkdir -p deploy/dev
[[ -f deploy/dev/empty-ca.pem ]] || : >deploy/dev/empty-ca.pem
if [[ -z "${RMM_EXTRA_CA_FILE:-}" && -f /root/.ccr/ca-bundle.crt ]]; then
  export RMM_EXTRA_CA_FILE=/root/.ccr/ca-bundle.crt
fi
# Build with plain docker build: compose v5 routes builds through bake, which
# demands --allow entitlements for network: host and the CA secret file.
ca=${RMM_EXTRA_CA_FILE:-deploy/dev/empty-ca.pem}
docker build --network host \
  --secret "id=extra_ca,src=$ca" \
  --build-arg "HTTPS_PROXY=${HTTPS_PROXY:-}" --build-arg "https_proxy=${HTTPS_PROXY:-}" \
  -f deploy/server.Dockerfile -t rmm-server:dev .
exec docker compose -f deploy/compose.yaml up -d --wait
