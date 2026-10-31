# Phase 3: Enrollment and NATS auth callout — Review Fixes

Fixes applied by the review loop, one section per cycle. Re-review decides whether each one holds.

## Cycle 1

**Date**: 2026-10-31
**Checks**: 33/40 passed
**Files changed**: `crates/rmm-api/src/enroll.rs`

| Finding | Severity | File | Agent | Status | Notes |
|---------|----------|------|-------|--------|-------|
| F-001 | critical | `crates/rmm-api/src/enroll.rs` | engineering-backend-architect | not fixed | partial |

## Cycle 2

**Date**: 2026-10-31
**Checks**: 31/40 passed
**Files changed**: none

| Finding | Severity | File | Agent | Status | Notes |
|---------|----------|------|-------|--------|-------|
| F-001 | major | `crates/rmm-api/src/enroll.rs` | engineering-backend-architect | not fixed | `crates/rmm-db/src/repo.rs` has to change. `DeviceMatch` (line 53) needs a `device_status: String` field. The `sqlx::query_as!` in `find_devices_by_fingerprint` (line 207) needs `d.status as "device_status!"`. The sqlx offline cache may need regenerating too. Apart from that, `decide` and the `Reattach` arm of `enroll` in `crates/rmm-api/src/enroll.rs` need small edits, which I can make. `decide` would return `PendingReview` for any same-client match whose device status is not `active`. The `Reattach` arm would return the real device status instead of `"active"`. The `dm()` helper and its tests would then need a status field. Please either add `repo.rs` to my writable files, or tell me to use a separate runtime query in `enroll.rs` for device status. I would not choose the runtime query, because it bypasses the repo layer. |
