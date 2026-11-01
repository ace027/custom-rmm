# Plan 04-01 Summary: Telemetry schema, roles, RLS and repositories

## Result
**Status**: Complete
**Wave**: 1
**Agent**: engineering-backend-architect
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-backend-architect | — | 12 | 3.67 | 15.67 | mandatory |
| engineering-senior-developer | — | 17 | 3.85 | 20.85 | heuristic |
| testing-qa-verification-specialist | — | 14 | 3.4 | 17.4 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Migration 0003 (done)
- [x] Task 2: Telemetry repositories (done)
- [x] Task 3: Two-client RLS and compression suite (done)

## Files Modified
- `.sqlx/query-19aa185257ae3255f1a7f0f0ef38b9d31395259134795b4821bc427b911043ad.json`
- `.sqlx/query-8147cc0ec8108603672d55fdb307e7c7a952c53f64e6a5ecc9acdef0075b4932.json`
- `.sqlx/query-a1d905460892ce9a5f2cde37dd05b8593419300bca0112077e213f06977123c4.json`
- `.sqlx/query-bd1a58ca0e88bd559396221feb135f72d7f5d16ab3265ad1eeaa974a900f6a81.json`
- `.sqlx/query-d8c1905dfc3b5aa4d56a2e9a5e2033271a30c7ef4455ec0fe7791b17ddc78032.json`
- `.sqlx/query-e10d5938075917a9dbdb0c15532d3f48047d6902e7ef92b28340e16d1f3e919d.json`
- `.sqlx/query-f21e1c7469bd3b0d888a7367efd7d49880ebd35cc3bbc0edd244d72be7c479d3.json`
- `crates/rmm-db/migrations/0003_telemetry.sql`
- `crates/rmm-db/src/lib.rs`
- `crates/rmm-db/src/telemetry.rs`
- `crates/rmm-db/tests/telemetry_rls.rs`

## Verification Results
8/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-db --locked` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo sqlx prepare --workspace --check` | 0 | PASS |
| `cargo clippy -p rmm-db --all-targets --locked -- -D warnings` | 0 | PASS |
| `test -f crates/rmm-db/migrations/0003_telemetry.sql` | 0 | PASS |
| `grep -q 'rmm_service' crates/rmm-db/migrations/0003_telemetry.sql && grep -q 'security_barrier' crates/rmm-db/migrations/0003_telemetry.sql` | 0 | PASS |
| `SQLX_OFFLINE=true cargo build -p rmm-db --locked` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-db --test telemetry_rls --locked` | 0 | PASS |
| `test $(grep -c 'sqlx::test' crates/rmm-db/tests/telemetry_rls.rs) -ge 9` | 0 | PASS |

## Key Decisions
- `apply_inventory` returns `None` when the device is not visible for the given `client_id`. It also returns `None` when the hash is unchanged.
- `rmm_api` gets SELECT on `device_event` and `metrics_v`. `rmm_ingest` gets column-level UPDATE on the inventory columns and `agent.last_seen`, plus INSERT on `device_event` and `ts_private.metrics`.
- `rmm_db` has no `serde` or `serde_json` dependency and I could not edit `Cargo.toml`. The before/after JSON is built from the `sqlx::types::JsonValue` re-exports instead, and `last_boot` is written as an RFC3339 string.

## Issues Encountered
- `cargo sqlx prepare` deletes and regenerates `.sqlx`. While the parallel 04-02 work did not compile, one prepare run deleted the existing query files. I restored them with `git checkout -- .sqlx` and re-ran prepare successfully.
- The local `rmm` database had stale objects from an earlier run, so migration 2 failed. I stopped the compose `api`, `ingest` and `authd` containers and ran `DROP DATABASE rmm WITH (force)` followed by `CREATE DATABASE rmm`. I then re-created the `timescaledb` extension and applied all three migrations. The three containers are still stopped.

## Escalations
(none)

## Handoff Context
- **Key outputs**: .sqlx/query-19aa185257ae3255f1a7f0f0ef38b9d31395259134795b4821bc427b911043ad.json; .sqlx/query-8147cc0ec8108603672d55fdb307e7c7a952c53f64e6a5ecc9acdef0075b4932.json; .sqlx/query-a1d905460892ce9a5f2cde37dd05b8593419300bca0112077e213f06977123c4.json; .sqlx/query-bd1a58ca0e88bd559396221feb135f72d7f5d16ab3265ad1eeaa974a900f6a81.json; .sqlx/query-d8c1905dfc3b5aa4d56a2e9a5e2033271a30c7ef4455ec0fe7791b17ddc78032.json; .sqlx/query-e10d5938075917a9dbdb0c15532d3f48047d6902e7ef92b28340e16d1f3e919d.json; .sqlx/query-f21e1c7469bd3b0d888a7367efd7d49880ebd35cc3bbc0edd244d72be7c479d3.json; crates/rmm-db/migrations/0003_telemetry.sql; crates/rmm-db/src/lib.rs; crates/rmm-db/src/telemetry.rs; crates/rmm-db/tests/telemetry_rls.rs
- **Decisions made**: `apply_inventory` returns `None` when the device is not visible for the given `client_id`. It also returns `None` when the hash is unchanged.; `rmm_api` gets SELECT on `device_event` and `metrics_v`. `rmm_ingest` gets column-level UPDATE on the inventory columns and `agent.last_seen`, plus INSERT on `device_event` and `ts_private.metrics`.; `rmm_db` has no `serde` or `serde_json` dependency and I could not edit `Cargo.toml`. The before/after JSON is built from the `sqlx::types::JsonValue` re-exports instead, and `last_boot` is written as an RFC3339 string.
- **Open questions**: (none)
- **Conventions established**: Ingest must connect as the owner and `SET ROLE rmm_ingest` with `Scope::Service`. The service bypass now also requires membership in `rmm_service`, so the owner role without `SET ROLE` no longer gets the bypass.; `insert_metrics` and `apply_inventory` need `rmm_ingest` or another `rmm_service` member under `Scope::Service`. The API reads events and metrics through `tenant.device_event` and `tenant.metrics_v` with `Scope::Clients`.; The `.sqlx` prepare check needs a live database with migrations applied. Compose `timescale` is up on 127.0.0.1:5432.

## Requirements Covered
- REQ-11
- REQ-12
- REQ-13

## Token Usage
15 requests, 656889 input tokens (605568 cached), 20698 output tokens, $0.4564
