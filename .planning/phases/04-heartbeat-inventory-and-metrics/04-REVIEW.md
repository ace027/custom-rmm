# Phase 4: Heartbeat, inventory and metrics — Review Summary

## Result: PASSED

**Cycles Used**: 2
**Reviewers**: testing-qa-verification-specialist, engineering-senior-developer, engineering-backend-architect
**Evaluators**: code-quality, integration, business-logic
**Completed**: 2026-11-01

## Findings Summary
- Must-fix (blocker, critical, major) found: 3; fixed: 3; unresolved: 0
- Suggestions (minor, advisory): 0
- Deferred (confidence 50-79%): 18
- Hot spots (flagged by 2+ reviewers): `crates/rmm-server/src/ingest.rs`, `crates/rmm-db/migrations/0003_telemetry.sql`, `crates/rmm-db/src/telemetry.rs`, `crates/rmm-server/tests/ingest.rs`

## Findings Detail
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | major | `crates/rmm-proto/src/telemetry.rs (consumed by crates/rmm-db/src/telemetry.rs):108-116` | `Inventory::hash()` covers every field, including `volumes[].free_bytes`. Free space changes on almost every report. The unchanged-hash short-circuit in `apply_inventory` then almost never fires. Each inventory report writes a device update and an append-only `inventory.changed` event, and `disk_free_bytes` is among the "changed" fields. | engineering-backend-architect | 85% | fixed |
| F-002 | major | `crates/rmm-db/src/telemetry.rs (root cause: crates/rmm-proto/src/telemetry.rs, crates/rmm-platform/src/collect.rs):138-203` | `Inventory::hash` covers every `Volume`, including `free_bytes`. Free space changes continuously, so the hash changes almost every 5-minute check. The agent then re-sends the inventory. `apply_inventory` sees a new hash, and `disk_free_bytes` is in its `field!` list, so it writes an `inventory.changed` event. That is roughly 288 events per device per day. When the hash differs but no typed field does (hostname or mount change), it writes an event with empty `{}` before/after. The e2e step (2) only asserts `>= 1` events and step (5) only counts events containing `ram_bytes`, so neither catches this. | evaluator:integration | 85% | fixed |
| F-003 | major | `crates/rmm-proto/src/telemetry.rs (consumed by crates/rmm-agent-core/src/telemetry.rs and crates/rmm-db/src/telemetry.rs):105-116` | `Inventory::hash` covers every field, including each `Volume.free_bytes`. Free disk space changes almost continuously. The agent re-checks every 5 minutes and re-sends whenever the hash differs, so it will usually send a new inventory. Ingest sees a new hash, updates the device, and writes an `inventory.changed` device_event with `disk_free_bytes` before/after. | evaluator:business-logic | 80% | fixed |

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-senior-developer: **NEEDS WORK**
- Cycle 1, engineering-backend-architect: **NEEDS WORK**
- Cycle 1, evaluator:code-quality: **NEEDS WORK**
- Cycle 1, evaluator:integration: **NEEDS WORK**
- Cycle 1, evaluator:business-logic: **NEEDS WORK**
- Cycle 2, testing-qa-verification-specialist: **PASS**
- Cycle 2, engineering-senior-developer: **PASS**
- Cycle 2, engineering-backend-architect: **PASS**
- Cycle 2, evaluator:integration: **PASS**
- Cycle 2, evaluator:business-logic: **PASS**

## Suggestions (Not Required)
(none)

## Deferred (Medium Confidence)
- `crates/rmm-server/src/ingest.rs` [major, 70%]: Delivery is at-least-once and `insert_metrics` is not idempotent. `msg_id` is decoded but never used, and the metrics table has no unique key. If an ack fails after commit, or `ack_wait` (30 s) expires, the batch is redelivered and every metric row is inserted again.
- `crates/rmm-server/src/ingest.rs` [major, 70%]: `Processor` caches an agent's status for 60 s (`CACHE_TTL`), and only active rows are cached. A revoked agent's cached row still has status `active`, so its telemetry keeps being accepted and written for up to 60 s after revocation. The revoked-agent test uses a fresh `Processor`, so the cache path is never exercised.
- `crates/rmm-server/src/ingest.rs` [minor, 60%]: `check_loop` resets `db_ok_at` on every successful `SELECT 1` ping every 10 s. This overwrites the `db_failed()` set by a failing write batch.
- `crates/rmm-db/migrations/0003_telemetry.sql` [major, 65%]: `GRANT rmm_service TO rmm_api, rmm_authd, rmm_ingest` makes `pg_has_role(current_user,'rmm_service','MEMBER')` true for `rmm_api` and `rmm_authd` as well. The "role-gated" bypass therefore reduces to the `rmm.is_service()` GUC alone for those roles. `rmm.is_service()` was not read in full; only its use in 0002 policies is visible, so this assumes it is GUC-based, as the "needs the GUC" comment suggests.
- `crates/rmm-server/src/ingest.rs` [minor, 65%]: The heartbeat sets `last_seen` to the agent-supplied `sent_at`. That value is accepted up to 5 minutes in the future and up to 7 days in the past. The update is unconditional (`set last_seen = $2`), so a redelivered, nak'd or out-of-order older heartbeat moves `last_seen` backwards. A skewed agent clock can push it into the future.
- `crates/rmm-db/src/telemetry.rs` [minor, 60%]: `touch_heartbeat` runs `update tenant.agent set last_seen = $2 where id = $1` with no ordering guard. Ingest passes the agent-supplied `sent_at` whenever it falls inside the window (ingest.rs 550-556).
- `crates/rmm-db/src/telemetry.rs` [minor, 60%]: `apply_inventory` always writes an `inventory.changed` device_event when the hash differs. It does this even when none of the typed fields changed (for example only volumes or software lists changed), so `changed` is empty and the event has empty `before` and `after` objects.
- `crates/rmm-server/src/ingest.rs` [minor, 55%]: There are two clocks, `unix_now()` and `now_ms()`, built from the same `SystemTime` logic. The agent cache is only pruned once it holds more than 10,000 entries, and the prune keeps entries that are still fresh. If every entry is under 60 s old, the map keeps growing until they expire.
- `crates/rmm-server/src/ingest.rs` [minor, 55%]: Metric insertion is plain `INSERT` with no unique key or conflict handling. If a commit succeeds but the ack fails (the code only logs "ack failed"), JetStream redelivers (`max_deliver` 5) and every sample is inserted again.
- `crates/rmm-db/src/telemetry.rs` [minor, 60%]: Metric inserts are not idempotent. `ts_private.metrics` has no unique key, and a nak, ack failure or `max_deliver` redelivery re-runs the whole batch. A committed transaction whose ack then fails duplicates all of its samples.
- `crates/rmm-db/migrations/0003_telemetry.sql` [advisory, 50%]: `device_event.client_id` and `device_id` are independent foreign keys. Nothing ties the event's client to the device's client. There is also no retention policy for the table.
- `crates/rmm-server/tests/ingest.rs` [minor, 75%]: The heartbeat database test only asserts the ack and the stats counter. It never reads back `tenant.agent.last_seen`. The metrics database test (521-545) also only asserts counters and does not query the stored rows.
- `crates/rmm-server/src/ingest.rs` [minor, 55%]: Any database error naks the whole batch, so one message that deterministically fails in Postgres makes the entire batch of up to 500 fail and be redelivered with it. After `max_deliver: 5` JetStream silently drops all of them, and nothing counts or logs the drops.
- `crates/rmm-server/src/ingest.rs` [minor, 60%]: Agents with status "active" are cached for 60 s. A revoked or inactive agent keeps being accepted, and its telemetry written, until the TTL expires. The cache is not invalidated by the revocation subject.
- `crates/rmm-server/tests/ingest.rs` [minor, 50%]: Ingest tests that exercise the DB path (identity mismatch, RAM change event, metrics under the agent's client) return early and pass silently when `DATABASE_URL` is unset.
- `crates/rmm-db/src/telemetry.rs` [minor, 60%]: F-002 is fixed in code. `Inventory::hash` now zeroes `free_bytes`, and `apply_inventory` no longer diffs `disk_free_bytes`. It also returns early with no event when the hash differs but no typed field does. The proto unit test `hash_ignores_free_space` covers the hash. I found no test in the two listed files for the new `apply_inventory` behaviour. The cases are a free-space-only change, a hostname-only change, and a mount-only change; each should write zero events. The earlier report said the e2e step only asserted `>= 1` events. I did not open the e2e or DB test files, so I cannot confirm they now assert exact event counts.
- `crates/rmm-db/src/telemetry.rs` [minor, 70%]: `Current.disk_free_bytes` is selected only to "keep the query shape". It is never read, so it needs `#[allow(dead_code)]`. The `disk_free_bytes` column is also written only when the inventory hash changes. The comment "updated below" hides that `tenant.device.disk_free_bytes` stays stale between inventory changes. Free space now reaches the database only through the metric path.
- `crates/rmm-proto/src/telemetry.rs` [advisory, 50%]: The hash covers `Vec<Volume>` in the order the agent enumerates it. If the agent's volume enumeration order is unstable, the hash flips. Each flip causes a needless inventory update and rewrites `inventory_at`. The `unwrap_or_default()` fallback is also unreachable by the comment's own argument, but it would give every payload the same hash if it ever failed.

## Fixes Applied
- cycle 1: engineering-senior-developer on F-001, F-002, F-003 (partial); checks 23/28 passed
- minor findings: engineering-backend-architect on F-001, F-002, F-003, F-005, F-006, F-007, F-008 (partial); engineering-senior-developer on F-004 (done); left as is: F-001: not fixed. It needs a design decision: either a `Nats-Msg-Id` publish-side change in the agent crate (outside my writable files), or a unique index including `time` that must be compatible with compression, which needs a migration. / F-007: no code change. `apply_inventory` already returns before the event insert when `changed` is empty (telemetry.rs lines 192-194). I only documented the `Some(vec![])` case. / Tests for F-002 (revoke, then process another batch on the same `Processor`) and F-006 (out-of-order heartbeat) were not added. They need a live DB and NATS to run and verify. / F-004 not fixed. `rmm_api` calls `begin_scoped(.., &Scope::Service(..))` in `crates/rmm-api/src/admin.rs` (lines 104, 218, 265, 308, 399) and `crates/rmm-api/src/enroll.rs` (line 203). Those paths need the bypass, so revoking `rmm_service` from `rmm_api` would break admin token/revoke/device/trust handling and enrollment. The test seed in `crates/rmm-db/tests/telemetry_rls.rs:29` also relies on it. / F-004, what is still true. `rmm.is_service()` is GUC-only (`crates/rmm-db/migrations/0002_identity.sql:8-10`), so for `rmm_api` the role check adds nothing. Closing that gap means moving the admin/enroll writes to a separate role or SECURITY DEFINER functions. That is a design decision, so I left it for you.; checks failed (4/28), changes undone

## Cycle Delta
- cycle 1: 1 out-of-domain finding(s) filtered (testing-qa-verification-specialist on database, owner engineering-backend-architect); see .planning/logs/authority-decisions-2026-11-01.log
- cycle 1: 3 must-fix, 0 suggestions, 15 deferred, 0 dropped (low confidence)
- cycle 2: 0 must-fix (resolved 3, new 0, unchanged 0), 0 suggestions, 3 deferred, 0 dropped (low confidence)

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
