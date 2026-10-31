# Phase 3: Enrollment and NATS auth callout — Review Fixes

Fixes applied by the review loop, one section per cycle. Re-review decides whether each one holds.

## Cycle 1

**Date**: 2026-10-31
**Checks**: 22/40 passed
**Files changed**: none

| Finding | Severity | File | Agent | Status | Notes |
|---------|----------|------|-------|--------|-------|
| F-001 | major | `deploy/nginx/nginx.conf (read by crates/rmm-api/src/enroll.rs client_ip)` | engineering-senior-developer | not fixed | partial |
| F-004 | major | `deploy/nginx/nginx.conf (consumer: crates/rmm-api/src/enroll.rs)` | engineering-senior-developer | not fixed | partial |
| F-003 | major | `crates/rmm-server/src/authd.rs` | engineering-backend-architect | fix applied | F-003, F-005 and F-006 are fixed. A DB-backed authd test covers the allow and every deny path with audit rows. Revoke now returns 503 when the kick isn't published. New approve/reject device endpoints (admin, audited) with guarded transitions in the repo. |
| F-005 | major | `crates/rmm-api/src/admin.rs` | engineering-backend-architect | fix applied | F-003, F-005 and F-006 are fixed. A DB-backed authd test covers the allow and every deny path with audit rows. Revoke now returns 503 when the kick isn't published. New approve/reject device endpoints (admin, audited) with guarded transitions in the repo. |
| F-006 | major | `crates/rmm-api/src/lib.rs (routes at 148-159); crates/rmm-api/src/admin.rs; crates/rmm-db/src/repo.rs` | engineering-backend-architect | fix applied | F-003, F-005 and F-006 are fixed. A DB-backed authd test covers the allow and every deny path with audit rows. Revoke now returns 503 when the kick isn't published. New approve/reject device endpoints (admin, audited) with guarded transitions in the repo. |
