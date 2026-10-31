# Phase 2: Trust core and signing CLI — Review Fixes

Fixes applied by the review loop, one section per cycle. Re-review decides whether each one holds.

## Cycle 1

**Date**: 2026-10-31
**Checks**: 32/32 passed
**Files changed**: `crates/rmm-sign/src/cli.rs`, `crates/rmm-sign/tests/cli.rs`, `crates/rmm-trust/src/verify.rs`, `crates/rmm-trust/tests/trust_store.rs`

| Finding | Severity | File | Agent | Status | Notes |
|---------|----------|------|-------|--------|-------|
| F-001 | major | `crates/rmm-trust/src/verify.rs` | engineering-backend-architect | fix applied | F-001 and F-003 are both fixed, with F-001 done by the brief's alternate fix because `store.rs` isn't writable. `MemoryReplayCache` now takes a `Clock` at construction, `set_now` is gone, and the cache is capped. `rmm-sign verify` now rejects an expired or not-yet-valid `Command`. Clippy is clean. |
| F-003 | major | `crates/rmm-sign/src/cli.rs` | engineering-backend-architect | fix applied | F-001 and F-003 are both fixed, with F-001 done by the brief's alternate fix because `store.rs` isn't writable. `MemoryReplayCache` now takes a `Clock` at construction, `set_now` is gone, and the cache is capped. `rmm-sign verify` now rejects an expired or not-yet-valid `Command`. Clippy is clean. |
