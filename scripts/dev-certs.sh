#!/usr/bin/env bash
# Generate a dev CA and server certificate under deploy/dev/certs.
# Idempotent: existing certs are kept unless --force is given.
set -euo pipefail
cd "$(dirname "$0")/.."
dir=deploy/dev/certs
if [[ "${1:-}" != "--force" && -f $dir/ca.pem && -f $dir/server.pem && -f $dir/server-key.pem ]]; then
  echo "dev certs already exist in $dir (use --force to regenerate)"
  exit 0
fi
mkdir -p "$dir"
openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca-key.pem"
openssl req -x509 -new -key "$dir/ca-key.pem" -sha256 -days 825 \
  -subj "/CN=rmm dev CA" -out "$dir/ca.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$dir/server-key.pem"
openssl req -new -key "$dir/server-key.pem" -subj "/CN=localhost" -out "$dir/server.csr"
printf 'subjectAltName=DNS:localhost,DNS:rmm.local,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' >"$dir/server.ext"
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca-key.pem" \
  -CAcreateserial -days 825 -sha256 -extfile "$dir/server.ext" -out "$dir/server.pem"
rm -f "$dir/server.csr" "$dir/server.ext" "$dir/ca.srl"
chmod 600 "$dir/ca-key.pem"
# The nginx container runs as a different uid, so the server key must be
# world-readable. This is acceptable only because deploy/dev is gitignored
# and the cert is for local development.
chmod 644 "$dir/server-key.pem" "$dir/server.pem" "$dir/ca.pem"
echo "generated dev certs in $dir"
