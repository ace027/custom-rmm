# Phase 4: Heartbeat, inventory and metrics -- Context

## Phase Goal
Agents report heartbeat, inventory and metrics that land in Postgres/Timescale under enforced client scoping

## Requirements Covered
- REQ-11
- REQ-12
- REQ-13

## What Already Exists (from prior phases)
- Phase 1: workspace, compose stack (timescale, nats 2.11 JetStream+WebSocket, nginx, api/ingest/authd/migrate), CI with lint/windows-cross/test-linux/test-windows, scripts/dev-up.sh, smoke-dev.sh, ci-local.sh
- Phase 2: rmm-proto::canonical deterministic CBOR (to_canonical_vec/from_canonical_slice), rmm-trust
- Phase 3: migrations 0001_init and 0002_identity (tenant.client/site/device/agent/enrollment_token, msp.trust_artifact, msp.audit_event, rmm.scope() and rmm.is_service(), RLS ENABLE+FORCE on tenant tables, NOLOGIN roles rmm_api and rmm_authd, services SET ROLE via rmm_db::connect_as); rmm_db::{connect, connect_as, migrate, scope::{Scope, begin_scoped}, repo}; rmm_db::connect pins search_path=public; rmm_proto::subjects::{agent_cmd, telemetry(client, agent, kind)}; rmm_platform::Platform {hostname, hw_facts, os_info}; agent `enroll` and `run` (connects to NATS over WSS with its nkey; run --once); authd issues agent JWTs allowing pub telemetry.<client>.<agent>.> and sub _INBOX_<agent>.>; ingest is a stub that only connects to NATS and serves /healthz; scripts/e2e-enroll.sh (fake DMI per simulated machine, 8 checks) passes in CI
- Phase 3 security review INFO item for this phase: the RLS service bypass is a settable GUC (rmm.service); restrict it to service roles

## Key Design Decisions
- Wire format for telemetry: rmm_proto::telemetry types encoded with rmm_proto::canonical (deterministic CBOR), serde deny_unknown_fields, payloads carry NO client_id or agent_id: identity comes only from the NATS subject telemetry.<client_id>.<agent_id>.<kind>, which authd's per-agent JWT makes unforgeable; kinds are hb, inv, metric
- Agent cadence: heartbeat every 30 s (core NATS publish, no ack), metrics every 60 s (JetStream publish with ack), inventory at start and every 6 h and whenever its hash changes at a 5-minute check (JetStream publish with ack); every interval gets +-10% random jitter; debug builds only honour RMM_AGENT_TELEMETRY_INTERVALS="hb=2,metric=3,inv=5" (seconds) for tests
- Collectors use the sysinfo crate behind rmm_platform (OS APIs, no shelling out): CPU usage %, memory total/used, per-volume disk total/free, uptime/last boot, CPU model and core count; Windows-specific extras stay in the platform layer
- JetStream: ingest creates or updates stream TELEM (subjects telemetry.>, file storage, max_age 3 days, discard old, duplicate window 2 min, message ids = agent-generated UUIDv7) and a durable pull consumer 'ingest' (ack explicit, ack_wait 30 s, max_deliver 5); batches of up to 500 messages or 1 s
- Ingest processing: parse subject -> (client_id, agent_id, kind); look up the agent (cache 60 s) and require status active and agent.client_id == subject client_id, else term the message and count it; hb -> tenant.agent.last_seen; inv -> upsert typed inventory columns + inventory JSONB on tenant.device only when inventory_hash changes, and write one tenant.device_event of type inventory.changed with before/after of exactly the changed typed fields; metric -> batched insert into ts_private.metrics. Ack after commit; malformed payload -> term; database error -> nak with 5 s delay
- Schema (migration 0003_telemetry.sql): typed columns on tenant.device: os_version text, cpu_model text, cpu_cores int, ram_bytes bigint, disk_total_bytes bigint, disk_free_bytes bigint, last_boot timestamptz, inventory jsonb, inventory_hash bytea, inventory_at timestamptz; tenant.device_event(id bigserial, client_id uuid not null, device_id uuid not null, at timestamptz, type text, before jsonb, after jsonb) append-only with RLS; ts_private.metrics(time timestamptz, client_id uuid, device_id uuid, metric text, value double precision) hypertable with 1-day chunks, compression segmentby client_id, device_id orderby time desc, compression policy after 7 days, retention 90 days; tenant.metrics_v security_barrier view filtering client_id = ANY(rmm.scope()) (no service bypass) with SELECT granted to rmm_api only; no grants on ts_private to rmm_api
- Roles: new NOLOGIN role rmm_ingest (SELECT tenant.agent/tenant.device, UPDATE tenant.agent(last_seen) and the device inventory columns, INSERT tenant.device_event and ts_private.metrics, USAGE on schema ts_private); new NOLOGIN group role rmm_service granted to rmm_api, rmm_authd and rmm_ingest; every tenant RLS policy is rewritten so the service bypass requires both rmm.is_service() and pg_has_role(current_user, 'rmm_service', 'MEMBER') (addresses the phase 3 INFO finding; future read-only roles are not members). Separate login roles stay deferred: services keep connecting as the owner and SET ROLE
- Performance target (board): 1000 agents at 1 heartbeat/30 s and 10 metrics/60 s (about 200 msg/s); the e2e script publishes 10000 metric samples and requires ingest to land them within 60 s locally
- No new crates except sysinfo (agent side) and uuid v7 already present; nothing pulls openssl
- Board quick-assess ran pre-plan (3.3/10, all concerns about missing artifacts); its recommendations are adopted: server-derived identity, time-partitioned hypertable with compression and retention, batched writer with bounded queue, cross-tenant negative tests, idempotent hash-keyed inventory upserts, stated throughput target
- Spec skipped (no trigger); architecture proposals skipped (--auto)

## Plan Structure
- **Plan 04-01 (Wave 1)**: Telemetry schema, roles, RLS and repositories -- Add migration 0003 (typed inventory columns, device_event, the metrics hypertable with compression and retention, the scoped metrics view, rmm_ingest and rmm_service roles, role-gated service bypass) plus rmm-db telemetry repositories and a two-client RLS suite that includes compressed chunks.
- **Plan 04-02 (Wave 1)**: Telemetry wire types, collectors and agent publisher -- Define the telemetry wire types, collect inventory and metrics through rmm-platform with sysinfo, and make `rmm-agent run` publish heartbeat, metrics and inventory on its own subjects with jittered intervals.
- **Plan 04-03 (Wave 2)**: Ingest service and end-to-end telemetry -- Implement the ingest service (TELEM stream and durable consumer, subject-derived identity, batched writes, inventory change events) and prove heartbeat, inventory, metrics, identity enforcement and throughput end to end against the dev stack in CI.
