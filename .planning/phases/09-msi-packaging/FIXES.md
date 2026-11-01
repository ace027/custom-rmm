# Phase 9: MSI packaging — Review Fixes

Fixes applied by the review loop, one section per cycle. Re-review decides whether each one holds.

## Cycle 1

**Date**: 2026-11-01
**Checks**: 19/19 passed
**Files changed**: `crates/rmm-agent/tests/cli.rs`, `installer/wix/Package.wxs`, `scripts/msi-check.ps1`

| Finding | Severity | File | Agent | Status | Notes |
|---------|----------|------|-------|--------|-------|
| F-001 | blocker | `installer/wix/Package.wxs` | engineering-senior-developer | fix applied | F-001 fixed: the data property and the `Property=` attribute are now `RmmEnrollRun`, so they match the deferred action Id and the property stays Hidden. F-002: msi-check.ps1 now has a stub-server enrollment stage and an agent-launched assertion on the failure case. I could not run the PowerShell script or build the MSI on this Linux host, so those changes are untested here. The stub reply has an empty trust bundle, so it relies on the agent accepting that without compiled-in root keys, as `verify_bundle` allows. |
| F-002 | major | `scripts/msi-check.ps1` | engineering-senior-developer | fix applied | F-001 fixed: the data property and the `Property=` attribute are now `RmmEnrollRun`, so they match the deferred action Id and the property stays Hidden. F-002: msi-check.ps1 now has a stub-server enrollment stage and an agent-launched assertion on the failure case. I could not run the PowerShell script or build the MSI on this Linux host, so those changes are untested here. The stub reply has an empty trust bundle, so it relies on the agent accepting that without compiled-in root keys, as `verify_bundle` allows. |
