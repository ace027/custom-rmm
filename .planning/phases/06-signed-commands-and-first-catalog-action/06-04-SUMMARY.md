# Plan 06-04 Summary: Dev trust bootstrap, end-to-end actions and CI

## Result
**Status**: Partial
**Wave**: 3
**Agent**: testing-qa-verification-specialist
**Completed**: 2026-11-01
**Failure Class**: BLOCKER — $ RMM_HTTPS_PORT=8443 scripts/e2e-actions.sh (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| testing-qa-verification-specialist | — | 22 | 3.5 | 25.5 | heuristic |
| engineering-infrastructure-devops | — | 20 | 3.67 | 23.67 | heuristic |
| engineering-senior-developer | — | 12 | 3.78 | 15.78 | heuristic |

- **Task type detected**: quality-review
- **Confidence**: MEDIUM
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Dev trust bootstrap (done)
- [ ] Task 2: End-to-end actions (partial)
- [x] Task 3: Windows runbook and CI wiring (done)

## Files Modified
- `.github/workflows/ci.yml`
- `deploy/.env.example`
- `deploy/compose.yaml`
- `docs/dev-environment.md`
- `docs/runbooks/windows-action-check.md`
- `scripts/ci-local.sh`
- `scripts/dev-trust.sh`
- `scripts/dev-up.sh`
- `scripts/e2e-actions.sh`
- `scripts/e2e-enroll.sh`
- `scripts/e2e-offline.sh`
- `scripts/e2e-telemetry.sh`

## Verification Results
11/12 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `RMM_HTTPS_PORT=8443 scripts/e2e-actions.sh` | 1 | FAIL |
| `RMM_HTTPS_PORT=8443 scripts/e2e-enroll.sh` | 0 | PASS |
| `$HOME/.local/bin/actionlint .github/workflows/ci.yml \|\| actionlint .github/workflows/ci.yml` | 0 | PASS |
| `scripts/check-layering.sh` | 0 | PASS |
| `bash -n scripts/dev-trust.sh && bash -n scripts/dev-up.sh` | 0 | PASS |
| `docker compose -f deploy/compose.yaml --env-file deploy/.env.example config -q` | 0 | PASS |
| `RMM_HTTPS_PORT=8443 scripts/dev-up.sh` | 0 | PASS |
| `RMM_HTTPS_PORT=8443 scripts/smoke-dev.sh` | 0 | PASS |
| `bash -n scripts/e2e-actions.sh` | 0 | PASS |
| `grep -q e2e-actions .github/workflows/ci.yml` | 0 | PASS |
| `grep -q windows_spooler .github/workflows/ci.yml` | 0 | PASS |
| `test -f docs/runbooks/windows-action-check.md` | 0 | PASS |

## Key Decisions
- command.seed is chowned to uid 10001 with mode 0600 when dev-trust.sh runs as root; otherwise it is mode 0644
- Manifest, revocations and any re-sign use nanosecond timestamps as seq, so a re-sign always supersedes the stored one
- The API refuses to issue a revoked definition, so check (3) enrolls a second agent after uploading the revocation, then deletes that revocations row from msp.trust_artifact before issuing. This simulates a server that missed the revocation.
- The agent only learns revocations from its enrollment bundle. An e2e rerun is safe because the EXIT trap uploads an empty revocations document with a higher seq (the trap itself was not exercised).
- Check (2): with FAIL_START the full recipe fails at steps (service.wait), not verify, so the script asserts "a failed stage plus rollback ok".

## Issues Encountered
- Check (1) fails. Consumer agent_<id> shows the message delivered (consumer_seq 4, ack_pending 1), but the agent never receives or acks it. Its log only repeats "bound to command consumer" every 36 s, so each MSG.NEXT pull seems to end in a timeout error.
- Not yet established why. The agent sets custom_inbox_prefix `_INBOX_<agent>` in transport.rs and the JWT allows subscribing to `_INBOX_<agent>.>`.
- Suspects, all in crates/ which I may not edit: a reply routing problem on the MSG.NEXT request (async-nats send_request vs the inbox), or the pull's `expires` handling.
- Checks (2), (3) and (4) never ran. The `nats pub --force-stdin` forged-result publish is untested.
- Blocked: none
- BLOCKER: $ RMM_HTTPS_PORT=8443 scripts/e2e-actions.sh (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | out-of-scope fix | Fix the agent command pull in crates/ (rmm-agent-core commands.rs intake, or the agent NATS permissions in rmm-server natsjwt.rs). | approved | Same root cause as #2; fixed in commands.rs (user-approved). |
| 2 | blocker | quality | Resolve: $ RMM_HTTPS_PORT=8443 scripts/e2e-actions.sh (exit 1) | approved | User approved the command intake fix. Root cause: the agent's MSG.NEXT pull used async-nats' shared request multiplexer, which drops JetStream deliveries arriving under the stream subject. Fixed with a dedicated inbox per pull; regression test tests/intake_nats.rs added. e2e-actions checks 1-4 now pass locally. Re-run 06-04 verification. |

- #1 context: The CMD consumer delivers the command, but the agent's MSG.NEXT request times out and rebinds every 36 s, so no result is produced. e2e-actions.sh cannot pass until this is fixed. This is a possible 06-02 defect found by the e2e run, and crates/ is forbidden to me.
- #2 context: Verification failed (RMM_HTTPS_PORT=8443 scripts/e2e-actions.sh); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: .github/workflows/ci.yml; deploy/.env.example; deploy/compose.yaml; docs/dev-environment.md; docs/runbooks/windows-action-check.md; scripts/ci-local.sh; scripts/dev-trust.sh; scripts/dev-up.sh; scripts/e2e-actions.sh; scripts/e2e-enroll.sh; scripts/e2e-offline.sh; scripts/e2e-telemetry.sh
- **Decisions made**: command.seed is chowned to uid 10001 with mode 0600 when dev-trust.sh runs as root; otherwise it is mode 0644; Manifest, revocations and any re-sign use nanosecond timestamps as seq, so a re-sign always supersedes the stored one; The API refuses to issue a revoked definition, so check (3) enrolls a second agent after uploading the revocation, then deletes that revocations row from msp.trust_artifact before issuing. This simulates a server that missed the revocation.; The agent only learns revocations from its enrollment bundle. An e2e rerun is safe because the EXIT trap uploads an empty revocations document with a higher seq (the trap itself was not exercised).; Check (2): with FAIL_START the full recipe fails at steps (service.wait), not verify, so the script asserts "a failed stage plus rollback ok".
- **Open questions**: (none)
- **Conventions established**: The next step is a 06-02 agent-side or natsjwt fix for command delivery. Then rerun scripts/e2e-actions.sh and fix whatever (2), (3) and (4) turn up.; deploy/dev/trust/command.pub holds public= and key_id= for the command key.; To avoid dev-up.sh's slow rebuild of rmm-server:dev on every call, skip the build when the image exists. This is optional; I did not change it.

## Requirements Covered
- REQ-15
- REQ-16
- REQ-17

### Failed verification output
`RMM_HTTPS_PORT=8443 scripts/e2e-actions.sh`
```
533-10624a2a05b5 [3murl[0m[2m=[0mwss://localhost:8443/nats
[2m2026-11-01T16:00:21.559149Z[0m [33m WARN[0m [2mrmm_agent_core::blocks[0m[2m:[0m test platform enabled: services are simulated
[2m2026-11-01T16:00:21.567167Z[0m [33m WARN[0m [2mrmm_agent_core::telemetry[0m[2m:[0m outbox drain incomplete [3msent[0m[2m=[0m0 [3mfailed[0m[2m=[0m1
[2m2026-11-01T16:00:22.345625Z[0m [32m INFO[0m [2masync_nats::connector[0m[2m:[0m connected successfully [3mserver[0m[2m=[0m8080 [3mmax_payload[0m[2m=[0m1048576
[2m2026-11-01T16:00:22.346026Z[0m [32m INFO[0m [2masync_nats[0m[2m:[0m event: connected
[2m2026-11-01T16:00:22.346182Z[0m [32m INFO[0m [2mrmm_agent[0m[2m:[0m nats connected
[2m2026-11-01T16:00:22.349651Z[0m [32m INFO[0m [2mrmm_agent_core::commands[0m[2m:[0m bound to command consumer [3mconsumer[0m[2m=[0magent_026eeeab-7115-4e8c-8533-10624a2a05b5
[2m2026-11-01T16:00:58.353494Z[0m [32m INFO[0m [2mrmm_agent_core::commands[0m[2m:[0m bound to command consumer [3mconsumer[0m[2m=[0magent_026eeeab-7115-4e8c-8533-10624a2a05b5
[2m2026-11-01T16:01:34.357454Z[0m [32m INFO[0m [2mrmm_agent_core::commands[0m[2m:[0m bound to command consumer [3mconsumer[0m[2m=[0magent_026eeeab-7115-4e8c-8533-10624a2a05b5
[2m2026-11-01T16:02:10.362726Z[0m [32m INFO[0m [2mrmm_agent_core::commands[0m[2m:[0m bound to command consumer [3mconsumer[0m[2m=[0magent_026eeeab-7115-4e8c-8533-10624a2a05b5
cleared revocations

```

## Token Usage
33 requests, 2593927 input tokens (2309832 cached), 34464 output tokens, $1.5168
