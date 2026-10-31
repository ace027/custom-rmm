# Phase 3: Enrollment and NATS auth callout — Review Summary

## Result: ESCALATED

**Cycles Used**: 3
**Reviewers**: testing-qa-verification-specialist, engineering-senior-developer, engineering-backend-architect
**Evaluators**: code-quality, integration, business-logic
**Completed**: 2026-10-31

## Findings Summary
- Must-fix (blocker, critical, major) found: 2; fixed: 0; unresolved: 2
- Suggestions (minor, advisory): 0
- Deferred (confidence 50-79%): 16
- Hot spots (flagged by 2+ reviewers): `crates/rmm-api/src/enroll.rs`, `crates/rmm-api/src/admin.rs`, `crates/rmm-server/src/authd.rs`

## Findings Detail
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | major | `crates/rmm-api/src/enroll.rs:57-92` | F-001 is still only partly fixed. `DeviceMatch` (repo.rs:53-64) and `find_devices_by_fingerprint` (repo.rs:207-225) do not return the device's own `status`. `decide` therefore looks only at the agent's status, `last_seen` and `allow_reattach`. A same-client device whose status is `flagged` or `pending_review` is still treated as reattachable in two cases. In the first, its agent is `active` with `last_seen` NULL or older than 24h. In the second, its agent is no longer `suspect_clone` because an operator changed the agent status without resolving the device. In both cases `Reattach` supersedes the old agent and creates a new `active` agent. The device row stays `flagged` or `pending_review`. The response hardcodes `status: "active"` for `Reattach` (line 259), so the response and the stored state disagree. The `decide_rules` test covers only the `suspect_clone` agent case, so nothing tests this path. | evaluator:business-logic | 80% | open |
| F-002 | major | `crates/rmm-api/src/enroll.rs (with /home/user/custom-rmm/crates/rmm-db/src/repo.rs:53-64, 207-225):68-85` | F-001 is only partly fixed. `DeviceMatch` and `find_devices_by_fingerprint` still carry no device status, so `decide` cannot see whether the matched device is `flagged`, `pending_review` or any other non-`active` state. It only checks the agent status. A same-client match whose device is `flagged` or `pending_review` can still return `Reattach` when its agent is `active` and not recently seen, or when the agent was changed from `suspect_clone` by an operator without resolving the device. The `Reattach` branch supersedes the old agent and inserts a new `active` agent. It never updates or checks the device row. The response then hardcodes `status: "active"` while the device stays `flagged` or `pending_review`. | evaluator:business-logic | 90% | open |

## Unresolved Findings
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | major | `crates/rmm-api/src/enroll.rs:57-92` | F-001 is still only partly fixed. `DeviceMatch` (repo.rs:53-64) and `find_devices_by_fingerprint` (repo.rs:207-225) do not return the device's own `status`. `decide` therefore looks only at the agent's status, `last_seen` and `allow_reattach`. A same-client device whose status is `flagged` or `pending_review` is still treated as reattachable in two cases. In the first, its agent is `active` with `last_seen` NULL or older than 24h. In the second, its agent is no longer `suspect_clone` because an operator changed the agent status without resolving the device. In both cases `Reattach` supersedes the old agent and creates a new `active` agent. The device row stays `flagged` or `pending_review`. The response hardcodes `status: "active"` for `Reattach` (line 259), so the response and the stored state disagree. The `decide_rules` test covers only the `suspect_clone` agent case, so nothing tests this path. | evaluator:business-logic | 80% | open |
| F-002 | major | `crates/rmm-api/src/enroll.rs (with /home/user/custom-rmm/crates/rmm-db/src/repo.rs:53-64, 207-225):68-85` | F-001 is only partly fixed. `DeviceMatch` and `find_devices_by_fingerprint` still carry no device status, so `decide` cannot see whether the matched device is `flagged`, `pending_review` or any other non-`active` state. It only checks the agent status. A same-client match whose device is `flagged` or `pending_review` can still return `Reattach` when its agent is `active` and not recently seen, or when the agent was changed from `suspect_clone` by an operator without resolving the device. The `Reattach` branch supersedes the old agent and inserts a new `active` agent. It never updates or checks the device row. The response then hardcodes `status: "active"` while the device stays `flagged` or `pending_review`. | evaluator:business-logic | 90% | open |

## Resolved Findings
(none)

## Recommendation
Fix the unresolved findings by hand, accept the phase as is, or investigate further.

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-senior-developer: **PASS**
- Cycle 1, engineering-backend-architect: **NEEDS WORK**
- Cycle 1, evaluator:code-quality: **NEEDS WORK**
- Cycle 1, evaluator:integration: **NEEDS WORK**
- Cycle 1, evaluator:business-logic: **NEEDS WORK**
- Cycle 2, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 2, engineering-senior-developer: **NEEDS WORK**
- Cycle 2, engineering-backend-architect: **NEEDS WORK**
- Cycle 2, evaluator:business-logic: **NEEDS WORK**
- Cycle 3, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 3, engineering-senior-developer: **NEEDS WORK**
- Cycle 3, engineering-backend-architect: **NEEDS WORK**
- Cycle 3, evaluator:business-logic: **NEEDS WORK**

## Suggestions (Not Required)
(none)

## Deferred (Medium Confidence)
- `crates/rmm-api/src/enroll.rs (query in crates/rmm-db/src/repo.rs:207-225)` [major, 70%]: `decide` only treats `revoked` as a blocking agent status. A device in `pending_review` or `flagged` has an agent with status `suspect_clone`, and authd never lets that agent connect, so its `last_seen` stays NULL. A later enrollment with the same strong fingerprint and a reattach-allowed token sees "not recent" and returns `Reattach` to that held device. The handler then supersedes the suspect agent and inserts a new agent with the default status, which is presumably `active`. It never updates the device row, which stays `pending_review`. The response also reports `status: "active"`.
- `crates/rmm-api/src/enroll.rs` [major, 70%]: `client_ip` trusts the client-supplied `X-Real-IP` header over the socket address. A grep of `deploy/` and `crates/rmm-api/src` found no nginx or API code that strips or overwrites this header.
- `crates/rmm-server/src/authd.rs (also crates/rmm-server/src/natsjwt.rs:56, crates/rmm-api/src/enroll.rs:129, crates/rmm-agent-core/src/enroll.rs:195)` [advisory, 70%]: `unix_now()` and similar helpers are copy-pasted in at least four places. `authd.rs` and `natsjwt.rs` are in the same crate and each have a private copy.
- `crates/rmm-api/src/enroll.rs (with crates/rmm-db/src/repo.rs)` [major, 70%]: `find_devices_by_fingerprint` does not return `tenant.device.status`. The `Reattach` branch always creates a new agent with the default status `active` and reports `status: "active"`. This applies even when the matched device is `pending_review` or `flagged`. A clone that was held for review can be reattached by a later token with `allow_reattach`, once its agent is older than 24h or has no `last_seen`. The agent is then `active`, and authd lets it connect.
- `crates/rmm-db/migrations/0002_identity.sql` [minor, 55%]: `msp.audit_event` has no index on `client_id`, `at` or `action`. `tenant.device` has no unique constraint or uniqueness rule for a strong fingerprint within a client. Reattach and enrollment have no lock on the matched device or fingerprint.
- `crates/rmm-api/src/enroll.rs` [minor, 50%]: The 409 "public key already enrolled" response lets anyone with a valid proof of possession check whether a public key exists. Reattach does not update the existing device's `hostname`, `site_id` or `os_family` from the new token and request, so the device record goes stale.
- `crates/rmm-api/src/admin.rs` [major, 70%]: `revoke_agent` commits the revocation and then publishes the kick notice on a plain core-NATS subject. If the publish fails or authd is down or reconnecting at that moment, the code only logs a warning and still returns 204. Core NATS does not store the message. authd has no startup or periodic reconciliation of agents that are revoked in the database but still connected.
- `crates/rmm-api/src/enroll.rs` [major, 65%]: Reattach supersedes the old agent in the database but publishes no revocation notice. An existing NATS connection of the superseded agent is not kicked. Its JWT lasts up to 1h (`USER_JWT_TTL_SECS`).
- `crates/rmm-server/src/authd.rs` [minor, 60%]: Every callout request writes a `nats.auth.deny` audit row, including ones from clients that failed the nonce signature check or are unknown. These come from unauthenticated internet clients on WSS 443. The only limit is 256 concurrent requests, with no rate limit or per-host throttle.
- `crates/rmm-server/src/authd.rs` [major, 55%]: The Rust tests for `decide_in_db`, `kick_once` and `handle_revoked` cover only the pure helpers. The allow, deny (revoked status, client status, nkey mismatch) and kick paths are tested only through `scripts/e2e-enroll.sh`. That script needs a running NATS server and Postgres. Whether CI runs it was not verified. The Windows DPAPI keystore test in windows.rs cannot run on the Linux CI.
- `deploy/compose.yaml` [minor, 65%]: The base `compose.yaml` hard-codes `RMM_AUTH_ALLOW_DEV: "1"` and mounts the dev signing key. With it, any `rmm-dev` token carrying the `RMM.Admin` role is accepted alongside real Entra tokens. `RMM_ENTRA_AUDIENCE` is also fixed at `api://rmm-dev`.
- `scripts/e2e-enroll.sh` [major, 55%]: The automated end-to-end run uses a Linux debug agent with a faked `/sys/class/dmi`. The first criterion is a Windows VM using a DPAPI-protected key, and the repo has no automated check for it (only the manual runbook `windows-enroll-check.md`). Entra OIDC login is covered only by mock-discovery unit tests in `crates/rmm-api/tests/auth.rs`, not by a real tenant token.
- `crates/rmm-api/src/lib.rs` [major, 65%]: The router has no endpoint to approve or reject a `pending_review` or `flagged` device, or to move a `suspect_clone` agent to `active` or `revoked`. Revoke exists, and nothing else writes these states.
- `crates/rmm-api/src/enroll.rs (with crates/rmm-db/src/repo.rs:53-64, 207-225)` [major, 75%]: F-001 is only partly fixed. `decide` now holds `suspect_clone` and `revoked` agents, which closes the pending-review clone case. It still ignores the device's own status. `DeviceMatch` has no `device_status` field, and `find_devices_by_fingerprint` does not select it. A `flagged` device (cross-client fingerprint match) is created with an `active` agent and `last_seen` NULL. A later same-client enrollment with an `allow_reattach` token takes the `Reattach` path. That path supersedes the agent on the flagged device and creates an `active` agent. It returns `status: "active"` (hardcoded) while the device row stays `flagged`. The same happens for any `pending_review` device whose agent is no longer `suspect_clone`, and for a device that is decommissioned or otherwise non-active. The tests in `decide_rules` do not cover device status.
- `crates/rmm-api/src/enroll.rs (with crates/rmm-db/src/repo.rs:53-64 and 207-225)` [major, 75%]: The F-001 fix only covers the `suspect_clone` and `revoked` agent states. `DeviceMatch` still has no device status, and `find_devices_by_fingerprint` does not select `d.status`. `decide` therefore cannot see a device in `pending_review` or `flagged`. The cases still open: - A `flagged` device is created by `NewFlagged` with an `active` agent, so `agent_status` is `active`. If that agent never connected, `last_seen` is NULL. A second same-client enrollment with an `allow_reattach` token reaches `Reattach` onto the flagged device. It supersedes that agent and returns `status: "active"`, because the `Reattach` arm hardcodes `"active"`. - A held device whose agent is later superseded or reset by a technician (so `agent_id` is None or the status is not `suspect_clone`) reattaches the same way. - The device row stays `pending_review` or `flagged`, but the response and agent state say active.
- `crates/rmm-api/src/enroll.rs` [minor, 75%]: `decide_rules` now covers `suspect_clone` but not a `revoked` agent status. It also has no case for a matched device that is `flagged` or `pending_review`, and no case where a held match comes after a reattachable match in the list.

## Fixes Applied
- cycle 1: engineering-backend-architect on F-001 (partial); checks 33/40 passed
- cycle 2: engineering-backend-architect on F-001 (blocked); checks 31/40 passed

## Cycle Delta
- cycle 1: 1 out-of-domain finding(s) filtered (engineering-senior-developer on api-design, owner engineering-backend-architect); see .planning/logs/authority-decisions-2026-10-31.log
- cycle 1: 1 must-fix, 0 suggestions, 13 deferred, 0 dropped (low confidence)
- cycle 2: 1 must-fix (resolved 0, new 0, unchanged 1), 0 suggestions, 3 deferred, 0 dropped (low confidence)
- cycle 3: 1 out-of-domain finding(s) filtered (engineering-senior-developer on database, owner engineering-backend-architect); see .planning/logs/authority-decisions-2026-10-31.log
- cycle 3: 2 must-fix (resolved 0, new 1, unchanged 1), 0 suggestions, 0 deferred, 0 dropped (low confidence)

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
