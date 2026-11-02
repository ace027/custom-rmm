# Phase 5: Encrypted local store and offline sync — Review Summary

## Result: PASSED

**Cycles Used**: 1
**Reviewers**: testing-qa-verification-specialist, engineering-backend-architect
**Completed**: 2026-11-01

## Findings Summary
- Must-fix (blocker, critical, major) found: 0; fixed: 0; unresolved: 0
- Suggestions (minor, advisory): 0
- Deferred (confidence 50-79%): 7
- Hot spots (flagged by 2+ reviewers): `crates/rmm-agent-core/src/store.rs`

## Findings Detail
(none)

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-backend-architect: **NEEDS WORK**

## Suggestions (Not Required)
(none)

## Deferred (Medium Confidence)
- `crates/rmm-agent-core/src/store.rs` [major, 65%]: The database runs in WAL mode with `synchronous=NORMAL`. In that mode a commit is not fsynced, so a power loss or OS crash can drop recently committed transactions. Those include `seq_floor` writes and `replay` inserts. The test `committed_rows_survive_a_crash` only covers a process crash.
- `crates/rmm-agent-core/src/store.rs` [minor, 70%]: `outbox_peek` deletes unreadable rows and returns only the readable ones. If every row in the first `limit` (200) is corrupt, it returns an empty vec. `drain_once` then reports `empty: true`, and `drain_loop` sleeps on `wake` or `reconnect` even though valid rows are still queued.
- `crates/rmm-agent-core/src/enroll.rs` [major, 60%]: `enroll --force` creates a new agent identity but keeps the existing `agent-store.db`. Queued rows carry subjects built from the old agent_id and client_id. Under the new per-agent JWT these publishes are most likely denied and never acked, since nothing in `Sink` or `drain_loop` handles it. The same rows stay at the head of the drain order (inventory is priority 1) and are retried forever.
- `scripts/e2e-offline.sh` [major, 70%]: The success criterion is "after 1 hour offline all queued telemetry and results arrive with no duplicates". The e2e test uses a 60 s outage with a 1 s metric interval, which is about 60 batches. No test covers inventory (priority 1) queued during an outage. No test covers a backlog larger than `MAX_IN_FLIGHT` (200) or a multi-batch drain, and no test checks that `drain_loop` and the real `JetStreamSink` honour the ack timeout under a large backlog. Command results do not exist yet, so "results" is untested.
- `crates/rmm-agent-core/src/enroll.rs` [minor, 55%]: `verify_bundle` calls the blocking SQLite-backed `SeqStore` (`Store::get`, `Store::put`, WAL write) directly on the async runtime thread inside `enroll`. The Store API documents that async callers must use `spawn_blocking`.
- `crates/rmm-server/src/ingest.rs` [major, 70%]: A database failure naks the whole batch with a 5 s delay. The consumer has `max_deliver: 5` and `ack_wait: 30s`. A Postgres outage of about 25 s or more exhausts the delivery budget. JetStream then stops redelivering those messages to the `ingest` consumer.
- `crates/rmm-db/migrations/0004_ingest_dedupe.sql` [minor, 60%]: The header claims "agents never queue longer than the stream keeps messages". That is not enforced. The agent outbox is bounded only by rows and bytes (`MAX_OUTBOX_ROWS` and `MAX_OUTBOX_BYTES`), not by age. The stream keeps messages 3 days, dedupe retention is 7 days, and ingest drops samples older than 7 days.

## Fixes Applied
- minor findings: engineering-backend-architect on F-001, F-002, F-003, F-005, F-006 (partial); engineering-senior-developer on F-004, F-007 (partial); left as is: F-003 partial: I did not add the drain-side drop after N consecutive permission-denied publishes. That needs a design decision about Sink error classification. / F-003 no regression test for the purge. F-002 has no test for the all-corrupt window either. / F-006 partial: I did not add an escalating nak backoff. The nak delay is still a constant 5 s, which now repeats without a cap. I did not add the "DB fails more than 5 deliveries" test, because it needs a live NATS and Postgres setup. / F-001: `committed_rows_survive_a_crash` still only covers a process crash. A power-loss test is not practical here. / F-004 (new tests not added): a backlog over 200 rows, an inventory change during the outage, and a 1 h nightly scenario each need design choices (interval and outage length, a way to trigger inventory changes) and a docker stack run to validate. Command results don't exist yet. / F-007 (age limit not added): a maximum outbox row age in the agent is a design change outside the files I may edit. I corrected the comment instead, which the finding allows.; checks 21/21 passed, 4 file(s) changed

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
