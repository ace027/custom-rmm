# Phase 2: Trust core and signing CLI — Review Summary

## Result: PASSED

**Cycles Used**: 2
**Reviewers**: testing-qa-verification-specialist, engineering-senior-developer, engineering-frontend-developer
**Evaluators**: code-quality, integration, business-logic
**Completed**: 2026-10-31

## Findings Summary
- Must-fix (blocker, critical, major) found: 2; fixed: 2; unresolved: 0
- Suggestions (minor, advisory): 1
- Deferred (confidence 50-79%): 15
- Hot spots (flagged by 2+ reviewers): `crates/rmm-trust/src/verify.rs`, `crates/rmm-sign/src/cli.rs`, `crates/rmm-trust/src/store.rs`, `docs/runbooks/root-ceremony.md`

## Findings Detail
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | major | `crates/rmm-trust/src/verify.rs:48-91` | `MemoryReplayCache` prunes using an internal `now` that defaults to 0 and changes only when the caller invokes `set_now`. It is not tied to the `Clock` passed to `verify_command`. `TrustStore::verify_command` never updates it, and the `ReplayCache` trait has no time parameter. A caller who skips `set_now` gets a cache that never prunes. The same happens if it forgets to call it before each command. | testing-qa-verification-specialist, evaluator:code-quality, evaluator:business-logic | 80% | fixed |
| F-002 | advisory | `n/a (all listed files)` | The changeset contains only Rust crates (trust core, signing CLI), CI workflows, scripts, and runbooks. It has no frontend code: no components, props, state, rendering, or layout. | engineering-frontend-developer | 95% | deferred |
| F-003 | major | `crates/rmm-sign/src/cli.rs:477-487` | `rmm-sign verify` of a `Command` envelope never checks the time window. It runs `verify_role`, `decode_doc` and `validate()` (which only checks that the window is well-formed), but there is no `check_time`. An expired or not-yet-valid command prints `OK`. The other three document types go through `apply_*`, which do check time, so this path behaves differently. `crates/rmm-sign/tests/cli.rs` has no test for an expired document. | evaluator:code-quality, evaluator:integration, evaluator:business-logic | 85% | fixed |

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-senior-developer: **NEEDS WORK**
- Cycle 1, engineering-frontend-developer: **PASS**
- Cycle 1, evaluator:code-quality: **NEEDS WORK**
- Cycle 1, evaluator:integration: **NEEDS WORK**
- Cycle 1, evaluator:business-logic: **NEEDS WORK**
- Cycle 2, testing-qa-verification-specialist: **PASS**
- Cycle 2, engineering-senior-developer: **PASS**
- Cycle 2, engineering-frontend-developer: **PASS**
- Cycle 2, evaluator:integration: **PASS**

## Suggestions (Not Required)
- F-002 `n/a (all listed files)`: The changeset contains only Rust crates (trust core, signing CLI), CI workflows, scripts, and runbooks. It has no frontend code: no components, props, state, rendering, or layout. (fix: None needed.)

## Deferred (Medium Confidence)
- `crates/rmm-sign/src/cli.rs` [minor, 65%]: `write_out` with `--force` truncates the existing file and then writes it in place. It does not write to a temporary file and rename it, and it does not call `sync_all`.
- `crates/rmm-trust/src/store.rs` [minor, 50%]: `apply_revocations` and `apply_techlist` check only the signing roles and the document's own validity window. They never check that the installed manifest is still unexpired (`now < m.expires_at`). Only `verify_command` checks that, through `trust_fresh`, and it skips the check for `TrustUpdate`.
- `crates/rmm-sign/src/card_backend.rs, docs/runbooks/yubikey-setup.md` [major, 60%]: The success criterion "YubiKey OpenPGP Ed25519 signature (with touch) verifies in rmm-trust" is covered only by a fake card (`fake("a", 3)`) in unit tests. The real-hardware check is `scripts/yubikey-smoke.sh`, and I checked only that it parses (`bash -n`). I found no recorded evidence that it was run on a physical key. I did not read the card backend's PIN-retry handling or its touch-timeout handling beyond the test fakes.
- `crates/rmm-trust/src/verify.rs (with crates/rmm-trust/src/store.rs)` [major, 70%]: `MemoryReplayCache` prunes using a `now` field that the caller must refresh with `set_now`. The `ReplayCache::seen(cmd_id, expires_at)` trait gets no clock. If `set_now` is skipped, `now` stays 0 and nothing is ever pruned. A caller that forgets it gets a cache that grows without bound.
- `crates/rmm-trust/src/verify.rs` [minor, 60%]: The `Clock`, `SeqStore`, `ReplayCache` and `DocKind` traits and types live in `store.rs`. Their only implementations (`FixedClock`, `MemorySeqStore`, `MemoryReplayCache`) live in `verify.rs`, which also re-exports `Envelope`, `SigEntry`, `pae`, `signing_message` and the store types. `verify.rs` is a grab-bag of re-exports and test doubles. `rmm-sign/src/cli.rs` imports `FixedClock` and `MemorySeqStore` from it, and imports `TrustStore` through it.
- `crates/rmm-trust/src/store.rs` [minor, 60%]: `apply_revocations` and `apply_techlist` are near-identical: they check the manifest, decode with a type check, run `verify_role`, decode the doc, validate it, check time, check seq, then `put` and install. They differ only in type, role, `DocKind` and the target field. The three doc kinds also keep parallel `Option<doc>` and `Option<Envelope>` fields, and the same pairing appears in the `held` calls.
- `crates/rmm-sign/src/cli.rs` [minor, 65%]: `ids.dedup()` only removes adjacent duplicates. `Envelope.sigs` is not guaranteed to be sorted or unique, so the same signer can be printed twice. Counting in `TrustStore` uses a `BTreeSet`, so the printed list can disagree with the counted signers.
- `crates/rmm-sign/tests/cli.rs, crates/rmm-sign/src/card_backend.rs` [major, 60%]: `PcscCard` is the only code that talks to the real YubiKey, and no automated test covers it. It is covered only by `scripts/yubikey-smoke.sh`, which needs hardware. The CLI integration tests also have no case for `verify` of a `Command` envelope, and none for the touch-signature-verifies-in-rmm-trust path other than the fake card.
- `crates/rmm-sign/src/file_backend.rs` [advisory, 50%]: The passphrase from `RMM_SIGN_PASSPHRASE` is read into a plain `String` that is not zeroized, unlike the prompted path, which uses `Zeroizing`. `RMM_CARD_PIN` is handled the same way: `std::env::var` returns an unzeroized `String` that is then copied.
- `crates/rmm-trust/src/store.rs` [major, 65%]: `MemoryReplayCache` prunes entries only against the `now` set through `set_now`, and `ReplayCache::seen` takes no `now`. `TrustStore::verify_command` has the clock but never passes it to the cache. A caller that uses `verify_command` as written never prunes, so the cache grows without bound. The only `set_now` calls are in the cache's own unit test.
- `scripts/yubikey-smoke.sh` [major, 60%]: The YubiKey criterion is covered only by a manual script. Nothing in the repo records a successful run. `docs/runbooks/yubikey-setup.md` says to paste the `PASS key_id=...` line into the key register, but no such line is recorded. The only automated card tests use a fake card (`FakeCard`).
- `docs/runbooks/root-ceremony.md` [major, 60%]: "Root ceremony dry run documented" is met only by an empty checklist and a blank sign-off table. No dry run is recorded: no date, no timings, no problems found, and no confirmation that the commands in the runbook work as written.
- `scripts/check-agent-no-sign.sh` [minor, 50%]: The check only inspects debug builds. The marker is a `#[used]` static. Release profiles with LTO, strip or opt-level changes are what actually ship, and the positive control is also debug-only. A release rmm-sign could lose the marker, and the check would not notice.
- `crates/rmm-sign/tests/cli.rs` [minor, 60%]: The new CLI time-window check for commands has a test for the expired side only. The `issued_at > now + SKEW_SECS` branch at cli.rs:486 (not yet valid) has no test. The expired test does pass for the right reason: the manifest and cert last about 100 days, so only the command expires.
- `crates/rmm-sign/src/cli.rs` [minor, 70%]: F-001 and F-003 are fixed. The replay cache now takes a `Clock`, and `verify` rejects expired commands, with tests in `tests/cli.rs`. The fix copies the not-yet-valid and expired window check from the private `check_time` in `crates/rmm-trust/src/store.rs:69`. It uses a different error path and message, and the `SKEW_SECS` rule now exists in two places.

## Fixes Applied
- cycle 1: engineering-backend-architect on F-001, F-003 (done); checks 32/32 passed
- minor findings: engineering-backend-architect on F-002, F-003, F-006, F-007, F-010, F-012, F-013 (partial); engineering-senior-developer on F-014 (partial); left as is: F-006: not fixed. It moves public types and changes imports across crates and tests, which is a larger refactor than this task allows. / F-007: not fixed. It needs a design decision (generic accept helper versus Option<(D, Envelope)> fields). / F-013: not fixed. It does not apply to the current code. MemoryReplayCache takes a Clock at construction, in verify.rs lines 58-113, and seen() prunes against self.clock.now() on every new insert. There is no set_now method. Passing `now` through the trait would change 14 constructor call sites for no functional gain. The one real gap is that verify_command and the cache could be given different clocks. I did not add a test that drives pruning through verify_command. / F-012, RMM_CARD_PIN part: not fixed. read_pin in card_backend.rs already wraps the value in Zeroizing, and that file is not in my writable list. / F-014 (hardware run): I have no YubiKey or `pcscd` here, so I recorded no key_id, date, firmware or touch policy in the runbook. Someone with the key must run the script and paste the `PASS key_id=...` line. I also could not edit `docs/runbooks/yubikey-setup.md`, which is outside my writable files. / F-014 (`ykman` parsing): the touch-policy check parses `ykman openpgp info` loosely, because the output layout differs between `ykman` versions. Check it against the real output on the first hardware run.; checks 32/32 passed, 4 file(s) changed

## Cycle Delta
- cycle 1: 2 must-fix, 1 suggestions, 13 deferred, 0 dropped (low confidence)
- cycle 2: 0 must-fix (resolved 2, new 0, unchanged 0), 0 suggestions, 2 deferred, 0 dropped (low confidence)

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
