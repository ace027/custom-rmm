# Dev environment

A Docker Compose stack runs Timescale (Postgres 17), NATS (JetStream and
WebSocket), nginx with TLS, and the `rmm-server` processes `api`, `ingest`,
`authd` and `migrate`.

## Prerequisites

- Docker with the Compose plugin
- `openssl`, `curl`, `python3`
- Rust toolchain from `rust-toolchain.toml`
- `sqlx-cli` for refreshing offline query data:
  `cargo install sqlx-cli --no-default-features --features rustls,postgres --locked`

## Commands

- `scripts/dev-up.sh` creates `deploy/.env` from `deploy/.env.example` if
  missing, generates dev certificates, builds `rmm-server:dev` and starts the
  stack, waiting until every service is healthy.
- `scripts/smoke-dev.sh` runs `dev-up.sh` and asserts TLS, the NATS WebSocket
  upgrade through nginx, JetStream health, the timescaledb extension and the
  schemas `tenant`, `msp`, `ts_private`, `rmm`.
- `scripts/dev-certs.sh [--force]` regenerates the dev CA and server cert.
- Reset all data: `docker compose -f deploy/compose.yaml down -v`.

## Ports

| Port | Service | Bound to |
|------|---------|----------|
| 443 (`RMM_HTTPS_PORT`) | nginx TLS: `/healthz`, `/api/`, `/v1/enroll`, `/nats` (WebSocket) | all interfaces |
| 5432 | Timescale | 127.0.0.1 |
| 4222 | NATS client | 127.0.0.1 |
| 8222 | NATS monitoring | 127.0.0.1 |

## Environment variables

Defined in `deploy/.env` (dev-only values; never reuse them elsewhere):
`RMM_PG_PASSWORD`, `RMM_NATS_{API,INGEST,AUTHD,SYS}_PASSWORD`,
`RMM_HTTPS_PORT`, `RMM_DATABASE_URL`, `RMM_NATS_URL`.

Server processes read `RMM_API_LISTEN` (default `0.0.0.0:8080`),
`RMM_HEALTH_LISTEN` (ingest `0.0.0.0:8081`, authd `0.0.0.0:8082`),
`RMM_NATS_USER`, `RMM_NATS_PASSWORD`, `RMM_DATABASE_URL`, `RUST_LOG` and
`RMM_LOG_FORMAT=json`.

If port 443 is taken, set `RMM_HTTPS_PORT` (for example `8443`); the smoke test
honours it.

### Proxied networks

The image build passes `HTTPS_PROXY` through as a build argument. For a
TLS-intercepting proxy set `RMM_EXTRA_CA_FILE` to the CA bundle; it is mounted
as a build secret and installed before `cargo build`. Without a proxy nothing
is needed (an empty file is used). `dev-up.sh` defaults `RMM_EXTRA_CA_FILE` to
`/root/.ccr/ca-bundle.crt` when that file exists. The image is built with
`docker build --network host` because Compose v5 would otherwise require
explicit buildx entitlements.

## Trusting the dev CA

Certificates live in the gitignored `deploy/dev/certs`. Trust `ca.pem` in your
OS store, or pass `--cacert deploy/dev/certs/ca.pem` to curl. The server key is
mode 0644 so the nginx container can read it; this is acceptable only for the
gitignored local dev directory. The CA key is mode 0600.

## sqlx offline data

`rmm-db` uses `sqlx::query_scalar!`. With the stack up run:

```
DATABASE_URL=postgres://rmm:<RMM_PG_PASSWORD>@127.0.0.1:5432/rmm cargo sqlx prepare --workspace
```

and commit `.sqlx/`. Docker builds use `SQLX_OFFLINE=true`.

## NATS authentication

NATS uses static dev users per service. The auth callout arrives in phase 3.
