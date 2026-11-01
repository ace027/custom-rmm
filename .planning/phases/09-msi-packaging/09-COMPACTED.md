---
phase: 09-msi-packaging
compacted: 2026-11-01
original_summaries: [09-01-SUMMARY.md, 09-02-SUMMARY.md]
requirements_satisfied: [REQ-22]
---

# Phase 9: MSI packaging — Compacted Summary

## Deliverables
- 09-01 WiX package, xtask msi and agent enrollment flag (Complete): crates/rmm-agent/src/main.rs, crates/rmm-agent/tests/cli.rs, docs/runbooks/msi-install.md, installer/wix/Package.wxs, installer/wix/README.md, xtask/src/main.rs, xtask/src/msi.rs
- 09-02 MSI CI checks and Windows validation matrix (Complete)

## Decisions
- 09-01: clap's `env` feature is not enabled in the workspace and I may not edit the root Cargo.toml, so the token env fallback is read manually with `std::env::var`.
- 09-01: The wipe-on-uninstall property `RMM_WIPE_DIR` is set only when `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE`. It is set after CostFinalize from the registry-sear
- 09-01: The enroll command line goes through a hidden `RmmEnroll` property and a `HideTarget` custom action, so the token stays out of the install log.

## Conventions and Open Questions
- 09-01 convention: CI should install WiX with `dotnet tool install --global wix --version 5.0.2` and `wix extension add --global WixToolset.Util.wixext/5.0.2`.
- 09-01 convention: CI should run `cargo run -p xtask -- msi` with RMM_ROOT_PUBKEYS set, or `--no-build` to reuse existing binaries. The output is `target/msi/rmm-agent-0.1.0-x64.m
- 09-01 convention: An unreachable SERVER_URL with ENROLL_TOKEN set should fail with exit code 1603 and roll back.
- 09-02 convention: The runbook's results table is for the operator to fill in. The matrix covers 4 OSes by hand and 2 runners in CI.
- 09-02 convention: The CI MSI check assumes a clean runner and fails fast if `RMMWatchdog` or `ProgramData\RMM` already exists.

## Files Modified
| File | Change |
|------|--------|
| `crates/rmm-agent/src/main.rs` | 09-01: WiX package, xtask msi and agent enrollment flag |
| `crates/rmm-agent/tests/cli.rs` | 09-01: WiX package, xtask msi and agent enrollment flag |
| `docs/runbooks/msi-install.md` | 09-01: WiX package, xtask msi and agent enrollment flag |
| `installer/wix/Package.wxs` | 09-01: WiX package, xtask msi and agent enrollment flag |
| `installer/wix/README.md` | 09-01: WiX package, xtask msi and agent enrollment flag |
| `xtask/src/main.rs` | 09-01: WiX package, xtask msi and agent enrollment flag |
| `xtask/src/msi.rs` | 09-01: WiX package, xtask msi and agent enrollment flag |

## Verification
- 09-01 (REQ-22): 11/11 verification commands passed
- 09-02 (REQ-22): 8/8 verification commands passed

## Agents
- 09-01: engineering-infrastructure-devops
- 09-02: testing-qa-verification-specialist

## Also Covered
- xtask/Cargo.toml
- Cargo.lock
- .github/workflows/ci.yml
- scripts/msi-check.ps1
- docs/runbooks/msi-validation.md
- docs/dev-environment.md
