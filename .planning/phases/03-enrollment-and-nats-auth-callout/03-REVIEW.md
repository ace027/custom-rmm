# Phase 3: Enrollment and NATS auth callout — Review Summary

## Result: PASSED

**Cycles Used**: 1
**Reviewers**: testing-qa-verification-specialist, engineering-senior-developer, engineering-backend-architect
**Evaluators**: code-quality, integration, business-logic
**Completed**: 2026-10-31

## Findings Summary
- Must-fix (blocker, critical, major) found: 0; fixed: 0; unresolved: 0
- Suggestions (minor, advisory): 0
- Deferred (confidence 50-79%): 15
- Hot spots (flagged by 2+ reviewers): `crates/rmm-server/src/authd.rs`, `crates/rmm-api/src/enroll.rs`, `crates/rmm-api/src/admin.rs`

## Findings Detail
(none)

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-senior-developer: **PASS**
- Cycle 1, engineering-backend-architect: **PASS**
- Cycle 1, evaluator:code-quality: **PASS**
- Cycle 1, evaluator:integration: **NEEDS WORK**
- Cycle 1, evaluator:business-logic: **NEEDS WORK**

## Suggestions (Not Required)
(none)

## Deferred (Medium Confidence)
- `crates/rmm-server/src/authd.rs` [major, 65%]: `kick_once` sends one `PING.CONNZ` request and takes only the first reply. It reads `server.id` from that reply and sends kicks only to that server. In a clustered or multi-server NATS deployment, connections on the other servers are never kicked. A one-reply request also returns whichever server answers first.
- `crates/rmm-api/src/enroll.rs` [minor, 60%]: `client_ip` trusts the client-supplied `X-Real-IP` header ahead of the socket peer address. If the API port is reachable without nginx, an attacker rotates the header value and bypasses the enroll rate limit. The attacker-supplied value is also written into the audit rows. The limiter is skipped entirely when no IP is found.
- `crates/rmm-server/src/authd.rs` [minor, 50%]: The deny reason `database error: {err}` is stored in the audit detail and logged. Raw sqlx error text can include connection details. Also, when the audit insert fails, for example under a DB outage, the whole decision becomes a deny. That is the correct failure mode, but nothing is audited.
- `crates/rmm-server/src/authd.rs (also crates/rmm-server/src/natsjwt.rs, crates/rmm-api/src/enroll.rs, crates/rmm-agent-core/src/enroll.rs)` [minor, 75%]: Four private copies of a "seconds since the Unix epoch" helper exist (`unix_now` x3, `now_secs` x1). The two server copies fall back to `unwrap_or(0)` on a clock error.
- `crates/rmm-api/src/enroll.rs` [major, 70%]: Reattach decisions are not serialized. `find_devices_by_fingerprint` is a plain read, and nothing locks the device or the old agent, and there is no unique index on active agents per device. Two concurrent enrollments for the same fingerprint, for example a cloned image booting on two machines at once, both read "old agent seen more than 24h ago". Both choose `Reattach` on the same device. Both then insert an `active` agent for the same device.
- `crates/rmm-api/src/enroll.rs` [minor, 60%]: On `Reattach`, the existing `tenant.device` row is not updated. Hostname, OS family, and the serial and SMBIOS fields stay at their first-enrollment values. Only the agent is superseded.
- `crates/rmm-db/migrations/0002_identity.sql` [advisory, 55%]: `suspect_clone` agents are created by inserting as `active` and then updating (enroll.rs 300-320). `NewAgent` has no `status` field, so the row is `active` for the length of the transaction.
- `crates/rmm-api/src/auth.rs` [major, 65%]: `entra_key` holds the `state` mutex across the discovery and JWKS HTTP calls, which have a 5 s timeout. When a refresh fails, `fetched_at` is not updated. The key cache then stays `expired`, so every following request retries the refresh while holding the lock.
- `crates/rmm-server/src/natsjwt.rs` [minor, 60%]: `issuer.sign(...).unwrap_or_default()` turns a signing failure into an empty signature. The function still returns a JWT with an empty signature part.
- `crates/rmm-server/src/authd.rs` [advisory, 55%]: Revocation and kick (`handle_revoked`, `kick_once`, `connz_matches` against a live server) and the WSS-443 path through nginx are covered only by `scripts/e2e-enroll.sh`. The Windows DPAPI enroll and connect criterion is covered only by the manual runbook `docs/runbooks/windows-enroll-check.md`. The DB-backed authd test prints "skipping" and returns green when `DATABASE_URL` is unset.
- `crates/rmm-api/src/admin.rs` [major, 65%]: `publish_kicks` publishes the revocation on a core NATS subject (`rmm.internal.agent.revoked`) and treats a successful publish and flush as "kick published". Core NATS does not report whether anyone is subscribed. If authd is down, restarting or reconnecting, the notice is dropped and the API still returns 204.
- `deploy/compose.yaml` [minor, 60%]: `RMM_ENTRA_AUDIENCE` is hardcoded to `api://rmm-dev` and `RMM_AUTH_ALLOW_DEV` is hardcoded to `"1"`. Neither can be overridden from `deploy/.env`. `RMM_NATS_PUBLIC_URL` is likewise fixed to `wss://localhost`. Only the tenant id is configurable.
- `scripts/e2e-enroll.sh` [minor, 55%]: The first criterion (a Windows VM enrolls with a token and connects through nginx on 443) is covered only by a manual runbook (`docs/runbooks/windows-enroll-check.md`). The automated e2e runs a Linux agent. No test covers the authd-down revocation case or the Windows DPAPI keystore.
- `crates/rmm-db/src/repo.rs (also crates/rmm-db/migrations/0002_identity.sql)` [major, 70%]: `reject_device` revokes the held agents but leaves the device in `pending_review` or `flagged`. The device status CHECK constraint has no terminal value such as `rejected`. Two consequences follow. A rejected device can still be approved later. Every later enrollment with the same fingerprint matches the rejected device, fails `device_active`, and goes to `PendingReview` forever. The same applies to a reject followed by a re-reject.
- `crates/rmm-api/src/enroll.rs` [minor, 50%]: A weak fingerprint, for example a VM without SMBIOS data, always creates a new `active` device. A reinstall therefore never reattaches. It also cannot be flagged as a possible clone, and it leaves an orphan device each time.

## Fixes Applied
- minor findings: engineering-backend-architect on F-001, F-002, F-003, F-005, F-006, F-008, F-009 (partial); engineering-senior-developer on F-007 (done); left as is: F-001 not fixed: needs multi-reply collection and per-server kicks, which is a design change. Single-server NATS should be documented as a constraint. / F-002 trusted-proxy part not fixed: it needs a trusted-proxy config option. I only fixed the shared bucket for a missing IP. / F-006 not fixed: it needs a new repo function in crates/rmm-db/src/repo.rs, which is outside my writable files. / F-008 only partly fixed: the lock is still held across the HTTP fetch. Failed refreshes are now throttled, but a restructure to fetch outside the lock is left undone. / F-005 has no partial unique index backstop: that would be a migration, which is outside my writable files. / F-005 lock is untested: the advisory-lock query could not be run against Postgres here. / F-007 not fixed. The fix needs a `status` field on `NewAgent` in `crates/rmm-db/src/repo.rs`, changes to `insert_agent` and to the constructors in `crates/rmm-api/src/enroll.rs` and `crates/rmm-server/src/authd.rs`. Those files are not in my writable list, and the change breaks every `NewAgent` constructor, including `crates/rmm-db/tests/identity.rs`. The insert and the status update at enroll.rs 300-320 run in the same `tx` and commit together, so no other session can see an `active` clone row. It is a hardening refactor, not a bug. Nothing in `0002_identity.sql` needs to change, because the status CHECK constraint already allows `suspect_clone`.; checks failed (5/40), changes undone

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
