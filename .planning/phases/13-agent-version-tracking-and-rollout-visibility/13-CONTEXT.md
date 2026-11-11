# Phase 13: Agent version tracking and rollout visibility -- Context

## Phase Goal
The server records which version every agent runs, so a release rollout can be followed from the API.

## Requirements Covered
- REQ-27

## What Already Exists (from prior phases)
- tenant.agent(id, client_id, device_id, version text NOT NULL (set once at enrollment), status, last_seen, enrolled_at) from migration 0002; RLS on client_id
- The heartbeat payload already carries agent_version (crates/rmm-proto/src/telemetry.rs); ingest validates it (crates/rmm-server/src/ingest.rs) but only calls rmm_db::telemetry::touch_heartbeat, which sets last_seen
- tenant.device_event is append-only and already receives inventory.changed events from ingest; rmm_ingest has column-level UPDATE grants (migration 0003)
- Releases are stored as trust documents (kind release) since migration 0007; ReleaseManifest has version and seq
- Admin routes live in crates/rmm-api/src/admin.rs behind RequireRole<Admin>; scripts/e2e-update.sh check 1 reads the new version from the agent's health.json because the server did not store it
- Migrations 0001-0007 exist; other pending phases add none, so this phase uses the next free number at build time (0008 unless another phase took it)

## Key Design Decisions
- New migration adds tenant.agent.version_reported_at timestamptz and grants rmm_ingest UPDATE on (version, version_reported_at); no new table
- On each heartbeat ingest writes last_seen as today and, in the same statement, sets version_reported_at; when the reported version differs from the stored one it also updates version and appends a device_event of type agent.version_changed with detail {from, to}. An unchanged version writes no event
- A reported version is accepted only if it parses as semver and is at most 64 bytes; otherwise the heartbeat still counts for last_seen but the version fields are left alone and a warning is logged (rate-limited per agent by only logging when the bad value changes is not required: one warn per heartbeat is acceptable at the 60 s default interval)
- API, both Admin only and read-only: GET /api/v1/admin/agents?client_id=&version=&status=&limit=&offset= returns agents with {agent_id, client_id, device_id, hostname, status, version, version_reported_at, last_seen} ordered by client then hostname, limit default 100 and max 500; GET /api/v1/admin/rollout returns {latest_release: {version, seq} or null, total_active, on_latest, behind, versions: [{version, count}]} computed over agents with status active
- Both endpoints run in a service scope (they are fleet-wide admin views) and are audited as reads are elsewhere in admin.rs: follow that file's existing convention and do not add audit rows for reads if it has none
- Technician-scoped agent listing is out of scope here; it belongs with the console work

## Plan Structure
- **Plan 13-01 (Wave 1)**: Store the reported agent version and record changes -- Persist the heartbeat's agent version per agent with the time it was reported, and write a device event when it changes.
- **Plan 13-02 (Wave 2)**: Agent and rollout API, end-to-end check and runbook -- Expose agent versions and rollout progress to admins, read them in the end-to-end update check, and update the release runbook.
