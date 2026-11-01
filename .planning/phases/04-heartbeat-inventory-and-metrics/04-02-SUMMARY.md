# Plan 04-02 Summary: Telemetry wire types, collectors and agent publisher

## Result
**Status**: Partial
**Wave**: 1
**Agent**: engineering-senior-developer
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 16 | 3.85 | 19.85 | heuristic |
| testing-qa-verification-specialist | — | 13 | 3.4 | 16.4 | heuristic |
| marketing-content-social-strategist | — | 14 | 0 | 14 | heuristic |

- **Task type detected**: implementation
- **Confidence**: HIGH
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Wire types and dependencies (done)
- [x] Task 2: Collectors (done)
- [x] Task 3: Agent publisher (done)

## Files Modified
- `Cargo.lock`
- `Cargo.toml`
- `crates/rmm-agent-core/Cargo.toml`
- `crates/rmm-agent-core/src/lib.rs`
- `crates/rmm-agent-core/src/telemetry.rs`
- `crates/rmm-agent-core/tests/telemetry.rs`
- `crates/rmm-agent/src/main.rs`
- `crates/rmm-platform/Cargo.toml`
- `crates/rmm-platform/src/collect.rs`
- `crates/rmm-platform/src/lib.rs`
- `crates/rmm-proto/src/lib.rs`
- `crates/rmm-proto/src/telemetry.rs`

## Verification Results
10/10 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-proto -p rmm-platform -p rmm-agent-core --locked` | 0 | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked` | 0 | PASS |
| `scripts/check-layering.sh` | 0 | PASS |
| `scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo deny check` | 0 | PASS |
| `cargo test -p rmm-proto --locked` | 0 | PASS |
| `cargo test -p rmm-platform --locked` | 0 | PASS |
| `cargo xwin clippy --target x86_64-pc-windows-msvc -p rmm-platform --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo test -p rmm-agent-core --locked` | 0 | PASS |

## Key Decisions
- encode/decode in telemetry.rs use plain `ciborium`, not `rmm_proto::canonical`, because canonical rejects floats and `Sample.value` is f64. `Inventory::hash` still uses canonical CBOR (no floats in that type).
- `Intervals` has exactly hb, metric and inv. The inventory change check runs every `min(inv, 5 min)`, so setting inv in the env makes the check use that value. The forced resend happens after `inv` has elapsed.
- Env format is `hb=2,metric=0.05,inv=5` (decimal seconds, clamped to 0.01..86400). Bad or unknown entries fall back to defaults.
- `run_telemetry` takes a `CancellationToken` (re-exported from rmm_agent_core::telemetry, so rmm-agent's Cargo.toml needed no change). It returns `Result<(), TelemetryError>`.
- Added `jetstream` to the workspace async-nats features, `tracing` and `ciborium` to rmm-agent-core, and `rmm_platform::collect::uptime_s()` for the heartbeat. None of these were named in the plan.
- The first metric batch goes out after one jittered interval. The heartbeat and inventory go out immediately.
- The `platform` argument overrides os_family, os_version and hostname in the inventory, so mock platforms work.

## Issues Encountered
- The workspace-wide clippy command cannot pass until 04-01's rmm-db sqlx cache and DATABASE_URL are sorted out.
- `cargo fmt --all` ran once; rmm-db/src/lib.rs only shows 04-01's `pub mod telemetry` line.
- `run_telemetry` itself has no NATS-backed test; the pure helpers are covered. Plan 04-03's end-to-end run covers it.

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | warning | contract | Telemetry encoding is plain CBOR rather than rmm_proto::canonical, because canonical forbids floats and Sample.value is f64. The alternative is a wire change to scaled integers. | pending | INVALID: type "contract" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |

- #1 context: Phase 4 CONTEXT says telemetry is encoded with canonical, but that cannot hold for f64 metric values. 04-03 ingest must use `telemetry::decode`. Please confirm or request the integer-scaling alternative.

## Handoff Context
- **Key outputs**: Cargo.lock; Cargo.toml; crates/rmm-agent-core/Cargo.toml; crates/rmm-agent-core/src/lib.rs; crates/rmm-agent-core/src/telemetry.rs; crates/rmm-agent-core/tests/telemetry.rs; crates/rmm-agent/src/main.rs; crates/rmm-platform/Cargo.toml; crates/rmm-platform/src/collect.rs; crates/rmm-platform/src/lib.rs; crates/rmm-proto/src/lib.rs; crates/rmm-proto/src/telemetry.rs
- **Decisions made**: encode/decode in telemetry.rs use plain `ciborium`, not `rmm_proto::canonical`, because canonical rejects floats and `Sample.value` is f64. `Inventory::hash` still uses canonical CBOR (no floats in that type).; `Intervals` has exactly hb, metric and inv. The inventory change check runs every `min(inv, 5 min)`, so setting inv in the env makes the check use that value. The forced resend happens after `inv` has elapsed.; Env format is `hb=2,metric=0.05,inv=5` (decimal seconds, clamped to 0.01..86400). Bad or unknown entries fall back to defaults.; `run_telemetry` takes a `CancellationToken` (re-exported from rmm_agent_core::telemetry, so rmm-agent's Cargo.toml needed no change). It returns `Result<(), TelemetryError>`.; Added `jetstream` to the workspace async-nats features, `tracing` and `ciborium` to rmm-agent-core, and `rmm_platform::collect::uptime_s()` for the heartbeat. None of these were named in the plan.; The first metric batch goes out after one jittered interval. The heartbeat and inventory go out immediately.; The `platform` argument overrides os_family, os_version and hostname in the inventory, so mock platforms work.
- **Open questions**: (none)
- **Conventions established**: Subjects are `telemetry.<client>.<agent>.{hb,inv,metric}`. hb is core NATS; inv and metric go through JetStream with the `Nats-Msg-Id` header set to the message's UUIDv7, which is also the payload `msg_id`.; Ingest must decode with `rmm_proto::telemetry::decode`, not canonical, because MetricBatch contains floats.; Metric names are constants in `rmm_proto::telemetry` (`METRIC_*`, `KIND_*`).; For tests, run debug builds with `RMM_AGENT_TELEMETRY_INTERVALS="hb=0.2,metric=0.5,inv=2"`.; Inventory `last_boot` is in unix seconds; `sent_at` and sample `t` are in unix milliseconds.

## Requirements Covered
- REQ-11

## Token Usage
18 requests, 907221 input tokens (842697 cached), 25733 output tokens, $0.5872
