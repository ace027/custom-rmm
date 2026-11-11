# Phase 12: Production deployment profile -- Context

## Phase Goal
A production deployment cannot start with development shortcuts enabled.

## Requirements Covered
- REQ-26

## What Already Exists (from prior phases)
- deploy/compose.yaml is the only compose file and hardcodes RMM_AUTH_ALLOW_DEV: "1" for the api service; deploy/.env.example ships the fake authenticator's AAGUID 726d6d2d6465762d66616b652d6b6579 and a dev attestation root path
- crates/rmm-server/src/main.rs has subcommands api, ingest, authd, migrate, results, dev-token, gen-nkey; crates/rmm-server/src/api.rs reads RMM_ROOT_PUBKEYS (empty only warns), RMM_NATS_PUBLIC_URL (default wss://localhost/nats), Authenticator::from_env (RMM_ENTRA_TENANT_ID optional, RMM_AUTH_ALLOW_DEV)
- The API already disables WebAuthn registration when the dev AAGUID is listed without RMM_AUTH_ALLOW_DEV=1
- scripts/dev-up.sh, scripts/smoke-dev.sh and all e2e scripts run against deploy/compose.yaml; CI lint job runs static checks

## Key Design Decisions
- A profile is selected by RMM_PROFILE: `production` (the default when unset) or `dev`. The dev compose file sets RMM_PROFILE=dev explicitly for every server service, so nothing about the dev stack changes
- In the production profile every server subcommand that serves traffic (api, ingest, authd, results) refuses to start, listing every violation at once, when any of these holds: RMM_AUTH_ALLOW_DEV is set to 1; RMM_AUTH_DEV_PUBKEY_FILE is set; RMM_WEBAUTHN_AAGUIDS contains the dev AAGUID; RMM_ROOT_PUBKEYS is empty; RMM_ENTRA_TENANT_ID or RMM_ENTRA_AUDIENCE is empty (api only); RMM_NATS_PUBLIC_URL is unset, not wss://, or names localhost or 127.0.0.1 (api only); the database password in DATABASE_URL equals the one shipped in deploy/.env.example (checked against a constant of that example value compiled into the binary); RMM_RECORDING_KEY_FILE is unset (api only, once phase 11 has landed: the check is included only if that variable is read anywhere in the code base at build time of this phase, otherwise it is left out and noted in the summary)
- dev-token and gen-nkey subcommands refuse to run in the production profile
- A new subcommand `rmm-server check-config --role api|ingest|authd|results` runs the same checks without starting anything and exits 0 or 1; it is what CI and operators use
- Production deployment artefacts: deploy/compose.prod.yaml (standalone, not an override: pinned image tags, no build section, no dev mounts, RMM_PROFILE=production, every secret and site value from deploy/.env.production which is gitignored) and deploy/.env.production.example with placeholders only and no working defaults
- The check is a pure function over a map of variables so it is unit-tested without touching the process environment

## Plan Structure
- **Plan 12-01 (Wave 1)**: Server profile gate and check-config -- Add the production/dev profile to rmm-server with a startup refusal of development shortcuts and a check-config subcommand.
- **Plan 12-02 (Wave 2)**: Production compose, env template, CI check and deployment runbook -- Ship a production compose file and env template with no dev defaults, a CI check that the production profile rejects each dev shortcut, and a deployment runbook.
