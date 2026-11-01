---
phase: 04-heartbeat-inventory-and-metrics
compacted: 2026-11-01
original_summaries: [04-01-SUMMARY.md, 04-02-SUMMARY.md, 04-03-SUMMARY.md]
requirements_satisfied: [REQ-11, REQ-12, REQ-13]
---

# Phase 4: Heartbeat, inventory and metrics — Compacted Summary

## Deliverables
- 04-01 Telemetry schema, roles, RLS and repositories (Complete): .sqlx/query-19aa185257ae3255f1a7f0f0ef38b9d31395259134795b4821bc427b911043ad.json, .sqlx/query-8147cc0ec8108603672d55fdb307e7c7a952c53f64e6a5ecc9acdef0075b4932.json, .sqlx/query-a1d905460892ce9a5f2cde37dd05b8593419300bca0112077e213f06977123c4.json, .sqlx/query-bd1a58ca0e88bd559396221feb135f72d7f5d16ab3265ad1eeaa974a900f6a81.json, .sqlx/query-d8c1905dfc3b5aa4d56a2e9a5e2033271a30c7ef4455ec0fe7791b17ddc78032.json, .sqlx/query-e10d5938075917a9dbdb0c15532d3f48047d6902e7ef92b28340e16d1f3e919d.json, .sqlx/query-f21e1c7469bd3b0d888a7367efd7d49880ebd35cc3bbc0edd244d72be7c479d3.json, crates/rmm-db/migrations/0003_telemetry.sql, crates/rmm-db/src/lib.rs, crates/rmm-db/src/telemetry.rs, crates/rmm-db/tests/telemetry_rls.rs
- 04-02 Telemetry wire types, collectors and agent publisher (Complete)
- 04-03 Ingest service and end-to-end telemetry (Complete)

## Decisions
- 04-01: `apply_inventory` returns `None` when the device is not visible for the given `client_id`. It also returns `None` when the hash is unchanged.
- 04-01: `rmm_api` gets SELECT on `device_event` and `metrics_v`. `rmm_ingest` gets column-level UPDATE on the inventory columns and `agent.last_seen`, plus INSERT on `d
- 04-01: `rmm_db` has no `serde` or `serde_json` dependency and I could not edit `Cargo.toml`. The before/after JSON is built from the `sqlx::types::JsonValue` re-export
- 04-03: The throughput check (6) is split into 6a and 6b, per the earlier recorded decision to accept the split phase 4 throughput check. 6a runs the agent at a 50 ms m

## Conventions and Open Questions
- 04-01 convention: Ingest must connect as the owner and `SET ROLE rmm_ingest` with `Scope::Service`. The service bypass now also requires membership in `rmm_service`, so the owner
- 04-01 convention: `insert_metrics` and `apply_inventory` need `rmm_ingest` or another `rmm_service` member under `Scope::Service`. The API reads events and metrics through `tenan
- 04-01 convention: The `.sqlx` prepare check needs a live database with migrations applied. Compose `timescale` is up on 127.0.0.1:5432.
- 04-02 convention: Ingest should expect subjects telemetry.<client>.<agent>.{hb,inv,metric}, with payloads encoded as canonical CBOR via rmm_proto::telemetry and no client or agen
- 04-03 convention: Ingest connects as the owner and runs `SET ROLE rmm_ingest` under `Scope::Service`. Metrics are read through `tenant.metrics_v` with `Scope::Clients`. The e2e s
- 04-03 convention: I did not touch it.

## Files Modified
| File | Change |
|------|--------|
| `.sqlx/query-19aa185257ae3255f1a7f0f0ef38b9d31395259134795b4821bc427b911043ad.json` | 04-01: Telemetry schema, roles, RLS and repositories |
| `.sqlx/query-8147cc0ec8108603672d55fdb307e7c7a952c53f64e6a5ecc9acdef0075b4932.json` | 04-01: Telemetry schema, roles, RLS and repositories |
| `.sqlx/query-a1d905460892ce9a5f2cde37dd05b8593419300bca0112077e213f06977123c4.json` | 04-01: Telemetry schema, roles, RLS and repositories |
| `.sqlx/query-bd1a58ca0e88bd559396221feb135f72d7f5d16ab3265ad1eeaa974a900f6a81.json` | 04-01: Telemetry schema, roles, RLS and repositories |
| `.sqlx/query-d8c1905dfc3b5aa4d56a2e9a5e2033271a30c7ef4455ec0fe7791b17ddc78032.json` | 04-01: Telemetry schema, roles, RLS and repositories |
| `.sqlx/query-e10d5938075917a9dbdb0c15532d3f48047d6902e7ef92b28340e16d1f3e919d.json` | 04-01: Telemetry schema, roles, RLS and repositories |
| `.sqlx/query-f21e1c7469bd3b0d888a7367efd7d49880ebd35cc3bbc0edd244d72be7c479d3.json` | 04-01: Telemetry schema, roles, RLS and repositories |
| `crates/rmm-db/migrations/0003_telemetry.sql` | 04-01: Telemetry schema, roles, RLS and repositories |
| `crates/rmm-db/src/lib.rs` | 04-01: Telemetry schema, roles, RLS and repositories |
| `crates/rmm-db/src/telemetry.rs` | 04-01: Telemetry schema, roles, RLS and repositories |
| `crates/rmm-db/tests/telemetry_rls.rs` | 04-01: Telemetry schema, roles, RLS and repositories |

## Verification
- 04-01 (REQ-11, REQ-12, REQ-13): 8/8 verification commands passed
- 04-02 (REQ-11): 10/10 verification commands passed
- 04-03 (REQ-11, REQ-12, REQ-13): 12/12 verification commands passed

## Agents
- 04-01: engineering-backend-architect
- 04-02: engineering-senior-developer
- 04-03: engineering-backend-architect

## Also Covered
- Cargo.lock
- crates/rmm-proto/src/lib.rs
- crates/rmm-proto/src/telemetry.rs
- crates/rmm-platform/Cargo.toml
- crates/rmm-platform/src/lib.rs
- crates/rmm-platform/src/collect.rs
- crates/rmm-agent-core/Cargo.toml
- crates/rmm-agent-core/src/lib.rs
- crates/rmm-agent-core/src/telemetry.rs
- crates/rmm-agent-core/tests/telemetry.rs
- crates/rmm-agent/src/main.rs
- crates/rmm-server/src/main.rs
- crates/rmm-server/src/ingest.rs
- crates/rmm-server/tests/ingest.rs
- crates/rmm-server/Cargo.toml
- deploy/compose.yaml
- scripts/e2e-telemetry.sh
- .github/workflows/ci.yml
- scripts/ci-local.sh
- docs/dev-environment.md
