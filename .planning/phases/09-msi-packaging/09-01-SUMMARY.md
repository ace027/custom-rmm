# Plan 09-01 Summary: WiX package, xtask msi and agent enrollment flag

## Result
**Status**: Complete
**Wave**: 1
**Agent**: engineering-infrastructure-devops
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-infrastructure-devops | — | 18 | 3.67 | 21.67 | heuristic |
| engineering-senior-developer | — | 16 | 3.82 | 19.82 | heuristic |
| testing-qa-verification-specialist | — | 16 | 3.62 | 19.62 | heuristic |

- **Task type detected**: implementation
- **Confidence**: MEDIUM
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Agent --if-not-enrolled and env token (done)
- [x] Task 2: WiX package (done)
- [x] Task 3: xtask msi and install runbook (done)

## Files Modified
- `crates/rmm-agent/src/main.rs`
- `crates/rmm-agent/tests/cli.rs`
- `docs/runbooks/msi-install.md`
- `installer/wix/Package.wxs`
- `installer/wix/README.md`
- `xtask/src/main.rs`
- `xtask/src/msi.rs`

## Verification Results
11/11 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-agent --test cli` | 0 | PASS |
| `cargo run -q -p xtask -- msi --dry-run` | 0 | PASS |
| `python3 -c "import xml.dom.minidom; xml.dom.minidom.parse('installer/wix/Package.wxs')"` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `cargo clippy -p rmm-agent --all-targets -- -D warnings` | 0 | PASS |
| `python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse('installer/wix/Package.wxs')"` | 0 | PASS |
| `grep -q 'ENROLL_TOKEN' installer/wix/Package.wxs` | 0 | PASS |
| `grep -q 'RemoveFolderEx' installer/wix/Package.wxs` | 0 | PASS |
| `! grep -qi 'slots' installer/wix/Package.wxs` | 0 | PASS |
| `cargo clippy -p xtask --all-targets -- -D warnings` | 0 | PASS |
| `test -s docs/runbooks/msi-install.md` | 0 | PASS |

## Key Decisions
- clap's `env` feature is not enabled in the workspace and I may not edit the root Cargo.toml, so the token env fallback is read manually with `std::env::var`.
- The wipe-on-uninstall property `RMM_WIPE_DIR` is set only when `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE`. It is set after CostFinalize from the registry-searched `RMM_DATA_DIR`. A major upgrade therefore never wipes the data root.
- The enroll command line goes through a hidden `RmmEnroll` property and a `HideTarget` custom action, so the token stays out of the install log.
- The UpgradeCode is `2F2C502D-D040-4141-9696-2CD23FCCEEB5`. Keep it fixed.

## Issues Encountered
- `wix` is not installed here, so Package.wxs is untested beyond XML well-formedness. Plan 09-02 CI must confirm that `WixRemoveFoldersEx` runs after the service stops and after the property is set. It should also confirm `Wix4UtilCA_X64` and that a hidden property with no value is accepted.
- Cargo.lock needed no change.
- The MSI creates `%ProgramData%\RMM\bootstrap` with inherited ACLs. Enrollment runs before the watchdog starts, so the SYSTEM+Administrators DACL is applied later, in the watchdog. I did not add `util:PermissionEx`; consider it as a follow-up.
- `.planning/STATE.md` shows as modified in `git status`. I did not touch it.

## Escalations
(none)

## Handoff Context
- **Key outputs**: crates/rmm-agent/src/main.rs; crates/rmm-agent/tests/cli.rs; docs/runbooks/msi-install.md; installer/wix/Package.wxs; installer/wix/README.md; xtask/src/main.rs; xtask/src/msi.rs
- **Decisions made**: clap's `env` feature is not enabled in the workspace and I may not edit the root Cargo.toml, so the token env fallback is read manually with `std::env::var`.; The wipe-on-uninstall property `RMM_WIPE_DIR` is set only when `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE`. It is set after CostFinalize from the registry-searched `RMM_DATA_DIR`. A major upgrade therefore never wipes the data root.; The enroll command line goes through a hidden `RmmEnroll` property and a `HideTarget` custom action, so the token stays out of the install log.; The UpgradeCode is `2F2C502D-D040-4141-9696-2CD23FCCEEB5`. Keep it fixed.
- **Open questions**: (none)
- **Conventions established**: CI should install WiX with `dotnet tool install --global wix --version 5.0.2` and `wix extension add --global WixToolset.Util.wixext/5.0.2`.; CI should run `cargo run -p xtask -- msi` with RMM_ROOT_PUBKEYS set, or `--no-build` to reuse existing binaries. The output is `target/msi/rmm-agent-0.1.0-x64.msi`.; An unreachable SERVER_URL with ENROLL_TOKEN set should fail with exit code 1603 and roll back.

## Requirements Covered
- REQ-22

## Token Usage
12 requests, 431898 input tokens (389741 cached), 19225 output tokens, $0.3756
