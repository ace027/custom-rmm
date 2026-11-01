# Phase 9: MSI packaging — Review Summary

## Result: PASSED

**Cycles Used**: 2
**Reviewers**: testing-qa-verification-specialist, engineering-frontend-developer
**Completed**: 2026-11-01

## Findings Summary
- Must-fix (blocker, critical, major) found: 2; fixed: 2; unresolved: 0
- Suggestions (minor, advisory): 0
- Deferred (confidence 50-79%): 4
- Hot spots (flagged by 2+ reviewers): `installer/wix/Package.wxs`, `scripts/msi-check.ps1`

## Findings Detail
| ID | Severity | Location | Issue | Reviewers | Confidence | Status |
|----|----------|----------|-------|-----------|------------|--------|
| F-001 | blocker | `installer/wix/Package.wxs:30` | The immediate action `RmmEnrollData` stores the enroll command line in a property named `RmmEnroll`. The deferred action is `RmmEnrollRun`. WixQuietExec64 reads its command from the CustomActionData of the deferred action, and that data is only populated from a property with the same name as the action Id (`RmmEnrollRun`). `RmmEnrollRun` therefore gets empty or no data, and the real enroll command never runs. | testing-qa-verification-specialist | 85% | fixed |
| F-002 | major | `scripts/msi-check.ps1:83-93` | The only token test installs against an unreachable server and expects failure. No check does a successful enrollment, such as a reachable or stub server, an enrolled-identity file, or the `--if-not-enrolled` path. The token-leak scan covers only that failing run's log. | testing-qa-verification-specialist, engineering-frontend-developer | 80% | fixed |

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **FAIL**
- Cycle 1, engineering-frontend-developer: **NEEDS WORK**
- Cycle 2, testing-qa-verification-specialist: **PASS**
- Cycle 2, engineering-frontend-developer: **PASS**

## Suggestions (Not Required)
(none)

## Deferred (Medium Confidence)
- `.github/workflows/ci.yml` [major, 75%]: The CI matrix covers only windows-2022 and windows-2025. The criterion names Win10, Win11, Server 2019 and Server 2022. The `msi-validation.md` runbook has empty result tables for the other OSes.
- `installer/wix/Package.wxs` [major, 55%]: The enrollment token is passed on the command line of `WixQuietExec64`. That action echoes the command line in its verbose log output. `Hidden="yes"` masks the property in the MSI property dump and `CustomActionData`, but I don't believe it covers the action's own log lines. I did not run an install, because this is a Linux host.
- `scripts/msi-check.ps1` [minor, 55%]: The rollback checks cover only Program Files\RMM and ProgramData\RMM\bootstrap. They never check that ProgramData\RMM is gone or empty after the failed enroll install. The agent creates state files outside the MSI components, such as the key file. `Package.wxs` does not track them, and its `RemoveFolderEx` runs only on uninstall, so a failed install can leave `ProgramData\RMM` behind. If enrollment succeeds and a later action such as StartServices fails, the identity and trust DB remain after rollback.
- `installer/wix/Package.wxs, scripts/msi-check.ps1, crates/rmm-agent/tests/cli.rs` [advisory, 70%]: No defects found in the three listed files. I read them and the agent enroll code. I did not run the verification commands, and the MSI script needs Windows, so it was never executed here.

## Fixes Applied
- cycle 1: engineering-senior-developer on F-001, F-002 (done); checks 19/19 passed
- minor findings: engineering-infrastructure-devops on F-003 (partial); engineering-senior-developer on F-004, F-003 (partial); left as is: F-003: Not fixed. A `windows-2019` runner can't be added because GitHub has retired that image, and hosted runners don't exist for Win10 or Win11. I didn't confirm the retirement against GitHub's docs. The empty tables in `msi-validation.md` need real manual-run results, and that file is outside my writable files. / F-004: not fixed. The agent already reads RMM_ENROLL_TOKEN when --token is absent (main.rs:387-388), but WixQuietExec64 cannot set a per-process environment. The alternatives are a token file or stdin, which means new agent CLI behaviour, or a system-wide Environment element, which would leak the token worse. The existing success-path token-leak check (msi-check.ps1 line 137, install-enroll.log) is the test for the verbose-log leak. It needs a Windows run to confirm. / F-003 (cleanup half): the new assertion detects a leftover ProgramData\RMM. Whether to add a rollback or cleanup action that wipes RMM_DATA_DIR, or to document the behaviour, is a design decision. I left it for you.; checks 19/19 passed, 2 file(s) changed

## Cycle Delta
- cycle 1: 1 out-of-domain finding(s) filtered (testing-qa-verification-specialist on frontend, owner engineering-frontend-developer); see .planning/logs/authority-decisions-2026-11-01.log
- cycle 1: 2 must-fix, 0 suggestions, 2 deferred, 0 dropped (low confidence)
- cycle 2: 0 must-fix (resolved 2, new 0, unchanged 0), 0 suggestions, 2 deferred, 0 dropped (low confidence)

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
