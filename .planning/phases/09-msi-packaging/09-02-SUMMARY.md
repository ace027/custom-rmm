# Plan 09-02 Summary: MSI CI checks and Windows validation matrix

## Result
**Status**: Partial
**Wave**: 2
**Agent**: testing-qa-verification-specialist
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| testing-qa-verification-specialist | — | 16 | 3.62 | 19.62 | mandatory |
| engineering-senior-developer | — | 17 | 3.82 | 20.82 | heuristic |
| engineering-infrastructure-devops | — | 17 | 3.67 | 20.67 | heuristic |

- **Task type detected**: quality-review
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: msi-check.ps1 (done)
- [x] Task 2: CI msi job (done)
- [x] Task 3: Manual validation runbook (done)

## Files Modified
- `.github/workflows/ci.yml`
- `docs/dev-environment.md`
- `docs/runbooks/msi-validation.md`
- `scripts/msi-check.ps1`

## Verification Results
8/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); assert 'msi' in d['jobs']"` | 0 | PASS |
| `test -s scripts/msi-check.ps1` | 0 | PASS |
| `test -s docs/runbooks/msi-validation.md` | 0 | PASS |
| `grep -q '/fa' scripts/msi-check.ps1` | 0 | PASS |
| `python3 -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/ci.yml')); assert 'msi' in d['jobs']"` | 0 | PASS |
| `grep -q 'msi-check.ps1' .github/workflows/ci.yml` | 0 | PASS |
| `grep -q 'Server 2019' docs/runbooks/msi-validation.md` | 0 | PASS |
| `grep -q 'msi-validation' docs/dev-environment.md` | 0 | PASS |

## Key Decisions
- `RMM_ROOT_PUBKEYS` in CI is the RFC 8032 test vector 1 public key (`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`), a public test value rather than a production root.
- The script fails fast if `RMMWatchdog`, `Program Files\RMM` or `ProgramData\RMM` already exist. msiexec 0 and 3010 count as success.
- It also asserts the Run value is absent after rollback, and it runs a best-effort uninstall if a check fails after install.
- The script stops the service before creating the slot and `state.json` markers, so the watchdog cannot rewrite them while hashes are taken.
- The runbook uses `rmm.local` as the server name, because `scripts/dev-certs.sh` issues the cert for `localhost`, `rmm.local` and 127.0.0.1.

## Issues Encountered
- Nothing has run: no Windows host or PowerShell here. The first CI run is the first real test of the script and the job.
- If repair does not start the service, the "Running after repair" check fails. That depends on `ServiceControl Start="install"` firing on `/fa`, which I could not confirm.
- The unreachable-server rollback check may take a while, depending on the agent's enroll timeout.
- Install logs are uploaded as artifacts. The rollback log is checked for the token, but the later logs are not.

## Escalations
(none)

## Handoff Context
- **Key outputs**: .github/workflows/ci.yml; docs/dev-environment.md; docs/runbooks/msi-validation.md; scripts/msi-check.ps1
- **Decisions made**: `RMM_ROOT_PUBKEYS` in CI is the RFC 8032 test vector 1 public key (`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`), a public test value rather than a production root.; The script fails fast if `RMMWatchdog`, `Program Files\RMM` or `ProgramData\RMM` already exist. msiexec 0 and 3010 count as success.; It also asserts the Run value is absent after rollback, and it runs a best-effort uninstall if a check fails after install.; The script stops the service before creating the slot and `state.json` markers, so the watchdog cannot rewrite them while hashes are taken.; The runbook uses `rmm.local` as the server name, because `scripts/dev-certs.sh` issues the cert for `localhost`, `rmm.local` and 127.0.0.1.
- **Open questions**: (none)
- **Conventions established**: Script usage: `scripts/msi-check.ps1 -Msi PATH [-LogDir DIR]`. The default log directory is `.\msi-logs`.; Check the first CI run results on both Windows images.; The results table in `docs/runbooks/msi-validation.md` is left empty for the operator.

## Requirements Covered
- REQ-22

## Token Usage
8 requests, 274658 input tokens (238713 cached), 10543 output tokens, $0.2430
