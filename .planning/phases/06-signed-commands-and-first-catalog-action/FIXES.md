# Phase 6: Signed commands and first catalog action — Review Fixes

Fixes applied by the review loop, one section per cycle. Re-review decides whether each one holds.

## Cycle 1

**Date**: 2026-11-01
**Checks**: 28/34 passed
**Files changed**: `crates/rmm-agent-core/src/commands.rs`, `crates/rmm-agent-core/src/store.rs`, `crates/rmm-agent-core/tests/commands.rs`, `crates/rmm-api/src/actions.rs`

| Finding | Severity | File | Agent | Status | Notes |
|---------|----------|------|-------|--------|-------|
| F-001 | major | `crates/rmm-agent-core/src/commands.rs (with crates/rmm-agent-core/src/store.rs)` | engineering-senior-developer | fix applied | F-001 fixed. process_pending no longer aborts on an unreadable inbox row. It logs the error, queues a signed Rejected/Validation result for that row, marks the row done, and carries on with the rows behind it. The result's cmd_id is the row id if it is 16 bytes, otherwise a SHA-256 prefix of the id. |
| F-002 | major | `crates/rmm-api/src/actions.rs` | engineering-backend-architect | fix applied | F-002 fixed in actions.rs without a DB write path. The publish now happens before `tx.commit()`, so a failed publish rolls the run back and leaves no orphan `queued` row (the 503 still returns). `read_run` now reports a `queued` run older than `COMMAND_TTL_SECS` as `expired`, which covers an offline agent and an exhausted `max_deliver`. |
