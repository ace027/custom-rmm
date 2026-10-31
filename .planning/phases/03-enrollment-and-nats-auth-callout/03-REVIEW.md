# Phase 3: Enrollment and NATS auth callout — Review Summary

## Result: STALE LOOP ABORTED

**Cycles Used**: 3
**Reviewers**: testing-qa-verification-specialist, engineering-senior-developer, engineering-backend-architect
**Evaluators**: code-quality, integration, business-logic
**Completed**: 2026-10-31

## Findings Summary
- Must-fix (blocker, critical, major) found: 5; fixed: 5; unresolved: 0
- Suggestions (minor, advisory): 1
- Deferred (confidence 50-79%): 10
- Hot spots (flagged by 2+ reviewers): `crates/rmm-server/src/authd.rs`, `crates/rmm-api/src/enroll.rs`, `crates/rmm-api/src/admin.rs`

## Findings Detail
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | major | `deploy/nginx/nginx.conf (read by crates/rmm-api/src/enroll.rs client_ip):28-30` | `client_ip` trusts the `X-Real-IP` request header, but nginx never sets or overwrites it for `/v1/enroll`. A client-supplied `X-Real-IP` passes through unchanged. If the header is absent, the limiter keys on the nginx container IP, so every client shares one bucket. | testing-qa-verification-specialist | 85% | fixed |
| F-002 | minor | `crates/rmm-server/src/authd.rs, crates/rmm-server/src/natsjwt.rs, crates/rmm-api/src/enroll.rs, crates/rmm-agent-core/src/enroll.rs:47-52` | The same "current unix seconds" helper is written four times, in three different styles (`unwrap_or(0)`, `map_or(0, ..)`, chrono). The two in rmm-server are identical copies. | engineering-senior-developer | 80% | deferred |
| F-003 | major | `crates/rmm-server/src/authd.rs:172-215` | `decide_in_db` and `decide` have no test that reaches the database. The only tests are `no_database_means_deny` and a deny response with a bad signature. The allow path, the status checks (agent not active, client not active, nkey mismatch, unknown agent) and the audit-row writes are never run. Only `scripts/e2e-enroll.sh` covers them, and that needs a live NATS and Postgres stack. | evaluator:code-quality, evaluator:integration | 80% | fixed |
| F-004 | major | `deploy/nginx/nginx.conf (consumer: crates/rmm-api/src/enroll.rs):28-30` | `client_ip()` trusts the `X-Real-IP` request header first. The `/v1/enroll` location in nginx never sets or overwrites that header, so the client's own value is passed through to the API. | evaluator:integration | 85% | fixed |
| F-005 | major | `crates/rmm-api/src/admin.rs:186-197` | Revocation commits the DB change and then makes one best-effort publish on core NATS, which is not persistent. If the publish fails, no NATS client is configured, or authd is down or reconnecting, the kick is lost. The endpoint still returns 204. authd's kick has no retry beyond the one repeat after 1 s. | evaluator:integration, evaluator:business-logic | 80% | fixed |
| F-006 | major | `crates/rmm-api/src/lib.rs (routes at 148-159); crates/rmm-api/src/admin.rs; crates/rmm-db/src/repo.rs:148-159` | Enrollment creates `pending_review` and `flagged` devices, and agents with status `suspect_clone`. No route or repo function moves them out of those states. The only status writers are `supersede_agent` and `set_agent_status`, and the only route that calls the latter sets `revoked`. `authd` denies any agent whose status is not `active`. | evaluator:business-logic | 80% | fixed |

## Unresolved Findings
(none)

## Resolved Findings
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | major | `deploy/nginx/nginx.conf (read by crates/rmm-api/src/enroll.rs client_ip):28-30` | `client_ip` trusts the `X-Real-IP` request header, but nginx never sets or overwrites it for `/v1/enroll`. A client-supplied `X-Real-IP` passes through unchanged. If the header is absent, the limiter keys on the nginx container IP, so every client shares one bucket. | testing-qa-verification-specialist | 85% | fixed |
| F-002 | minor | `crates/rmm-server/src/authd.rs, crates/rmm-server/src/natsjwt.rs, crates/rmm-api/src/enroll.rs, crates/rmm-agent-core/src/enroll.rs:47-52` | The same "current unix seconds" helper is written four times, in three different styles (`unwrap_or(0)`, `map_or(0, ..)`, chrono). The two in rmm-server are identical copies. | engineering-senior-developer | 80% | deferred |
| F-003 | major | `crates/rmm-server/src/authd.rs:172-215` | `decide_in_db` and `decide` have no test that reaches the database. The only tests are `no_database_means_deny` and a deny response with a bad signature. The allow path, the status checks (agent not active, client not active, nkey mismatch, unknown agent) and the audit-row writes are never run. Only `scripts/e2e-enroll.sh` covers them, and that needs a live NATS and Postgres stack. | evaluator:code-quality, evaluator:integration | 80% | fixed |
| F-004 | major | `deploy/nginx/nginx.conf (consumer: crates/rmm-api/src/enroll.rs):28-30` | `client_ip()` trusts the `X-Real-IP` request header first. The `/v1/enroll` location in nginx never sets or overwrites that header, so the client's own value is passed through to the API. | evaluator:integration | 85% | fixed |
| F-005 | major | `crates/rmm-api/src/admin.rs:186-197` | Revocation commits the DB change and then makes one best-effort publish on core NATS, which is not persistent. If the publish fails, no NATS client is configured, or authd is down or reconnecting, the kick is lost. The endpoint still returns 204. authd's kick has no retry beyond the one repeat after 1 s. | evaluator:integration, evaluator:business-logic | 80% | fixed |
| F-006 | major | `crates/rmm-api/src/lib.rs (routes at 148-159); crates/rmm-api/src/admin.rs; crates/rmm-db/src/repo.rs:148-159` | Enrollment creates `pending_review` and `flagged` devices, and agents with status `suspect_clone`. No route or repo function moves them out of those states. The only status writers are `supersede_agent` and `set_agent_status`, and the only route that calls the latter sets `revoked`. `authd` denies any agent whose status is not `active`. | evaluator:business-logic | 80% | fixed |

## Recommendation
Two re-reviews in a row found the same issues. Fix them by hand, or re-plan the affected work.

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-senior-developer: **PASS**
- Cycle 1, engineering-backend-architect: **NEEDS WORK**
- Cycle 1, evaluator:code-quality: **NEEDS WORK**
- Cycle 1, evaluator:integration: **NEEDS WORK**
- Cycle 1, evaluator:business-logic: **NEEDS WORK**
- Cycle 2, testing-qa-verification-specialist: **no verdict**
- Cycle 2, engineering-senior-developer: **no verdict**
- Cycle 2, engineering-backend-architect: **no verdict**
- Cycle 3, testing-qa-verification-specialist: **no verdict**
- Cycle 3, engineering-senior-developer: **no verdict**
- Cycle 3, engineering-backend-architect: **no verdict**

## Suggestions (Not Required)
- F-002 `crates/rmm-server/src/authd.rs, crates/rmm-server/src/natsjwt.rs, crates/rmm-api/src/enroll.rs, crates/rmm-agent-core/src/enroll.rs`: The same "current unix seconds" helper is written four times, in three different styles (`unwrap_or(0)`, `map_or(0, ..)`, chrono). The two in rmm-server are identical copies. (fix: Make `natsjwt::unix_now` `pub(crate)` and reuse it in `authd.rs`. Use one shared helper per crate boundary, or reuse the existing `Clock` traits that `rmm-trust` and `admin.rs` already define.)

## Deferred (Medium Confidence)
- `crates/rmm-server/src/authd.rs` [minor, 60%]: `kick_once` sends a single `$SYS.REQ.SERVER.PING.CONNZ` request and uses only the first reply (`sys.request` returns one response). It then sends the kick to that one server id. In a multi-server NATS cluster, connections on other servers are never kicked. The revocation notice is also a one-shot core publish. If authd is down or reconnecting at that moment, the notice is lost with no retry, and the connection survives until its JWT expires (up to 1 hour).
- `crates/rmm-api/src/enroll.rs` [major, 75%]: `client_ip` trusts the client-supplied `x-real-ip` header before the socket peer address. Any caller who can reach the API port can pick a new value on each request. Separately, when no IP can be determined the rate limiter is skipped entirely.
- `crates/rmm-db/migrations/0002_identity.sql` [major, 65%]: `tenant.device` has no uniqueness constraint on `(client_id, hw_fingerprint)`. The index at line 42 is non-unique. The enrollment handler does a read-then-insert: `find_devices_by_fingerprint`, then `insert_device`. Nothing serializes concurrent enrollments for the same fingerprint, for example two tokens used at once or a retry racing a reinstall.
- `crates/rmm-api/src/enroll.rs` [minor, 60%]: A pending-review agent is inserted as `active` (the column default) and then changed to `suspect_clone` by a second statement, `set_agent_status`.
- `crates/rmm-api/src/admin.rs` [major, 70%]: After the revocation commits, the kick notice is a plain core-NATS `publish` with no flush and no retry. If the publish fails, or authd is down or reconnecting at that moment, the error is only logged and the API still returns 204. `None` for `state.nats` is also just a warning.
- `crates/rmm-api/src/enroll.rs` [minor, 55%]: Concurrent enrollments with the same strong fingerprint and different keys both read `find_devices_by_fingerprint` before either inserts, with no lock or unique constraint on `hw_fingerprint`. Both can get `New`, producing two active devices for one machine. This also bypasses the clone check.
- `docs/runbooks/entra-setup.md` [major, 75%]: The runbook says to set `requestedAccessTokenVersion=2` and to set `RMM_ENTRA_AUDIENCE` to the `api://...` Application ID URI "exactly as in the token `aud`". v2.0 access tokens carry the API's client ID GUID as `aud`, not the `api://` URI. Only v1 tokens carry the URI. As written, `Validation::set_audience` would reject real Entra tokens.
- `crates/rmm-api/src/enroll.rs` [major, 60%]: `decide()` reattaches only when the old agent has not been seen for 24 hours. A reinstall on a machine that was online when it was uninstalled (the normal case) has `last_seen` within 24 hours, so it becomes `PendingReview` and the new agent is set to `suspect_clone`. Every reinstall test and `e2e-enroll.sh` (lines 175-183) first backdates `last_seen` to 25 hours with SQL. That hides this. The 24-hour rule also treats a prompt reinstall as a clone.
- `crates/rmm-api/src/enroll.rs` [minor, 65%]: On reattach the old agent is marked `superseded`, but nothing publishes a kick for it. Only `revoke_agent` publishes `REVOKED_SUBJECT`. Any live connection of the superseded agent keeps its JWT for up to 1 hour, with the permissions of its `agent_id`.
- `crates/rmm-api/src/lib.rs; crates/rmm-db/src/repo.rs` [minor, 60%]: `enrollment_token.revoked` is checked in `consume_enrollment_token`, but no API revokes or lists tokens.

## Fixes Applied
- cycle 1: engineering-senior-developer on F-001, F-004 (partial); engineering-backend-architect on F-003, F-005, F-006 (done); checks 22/40 passed

## Cycle Delta
- cycle 1: 5 must-fix, 1 suggestions, 10 deferred, 0 dropped (low confidence)
- cycle 2: 0 must-fix (resolved 5, new 0, unchanged 0), 0 suggestions, 0 deferred, 0 dropped (low confidence)
- cycle 2: no report from testing-qa-verification-specialist, engineering-senior-developer, engineering-backend-architect
- cycle 3: 0 must-fix (resolved 0, new 0, unchanged 0), 0 suggestions, 0 deferred, 0 dropped (low confidence)

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
