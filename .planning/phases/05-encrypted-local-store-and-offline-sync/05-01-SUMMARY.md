# Plan 05-01 Summary: Encrypted local store

## Result
**Status**: Failed
**Wave**: 1
**Agent**: engineering-senior-developer
**Completed**: 2026-11-01
**Failure Class**: BLOCKER — $ scripts/check-layering.sh (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 20 | 3.85 | 23.85 | heuristic |
| testing-qa-verification-specialist | — | 14 | 3.58 | 17.58 | heuristic |
| engineering-infrastructure-devops | — | 11 | 3.67 | 14.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: HIGH
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Named key stores (done)
- [x] Task 2: Store implementation (done)
- [x] Task 3: Store tests (done)

## Files Modified
- `Cargo.lock`
- `Cargo.toml`
- `crates/rmm-agent-core/Cargo.toml`
- `crates/rmm-agent-core/src/enroll.rs`
- `crates/rmm-agent-core/src/lib.rs`
- `crates/rmm-agent-core/src/store.rs`
- `crates/rmm-agent-core/tests/store.rs`
- `crates/rmm-platform/src/keystore.rs`
- `crates/rmm-platform/src/lib.rs`
- `crates/rmm-platform/src/windows.rs`

## Verification Results
10/11 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-platform -p rmm-agent-core --locked` | 0 | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo xwin build --target x86_64-pc-windows-msvc -p rmm-agent --locked` | 0 | PASS |
| `scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo deny check` | 0 | PASS |
| `cargo test -p rmm-platform --locked` | 0 | PASS |
| `cargo xwin clippy --target x86_64-pc-windows-msvc -p rmm-platform --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo build -p rmm-agent-core --locked` | 0 | PASS |
| `scripts/check-layering.sh` | 1 | FAIL |
| `cargo test -p rmm-agent-core --test store --locked` | 0 | PASS |
| `test $(grep -c '#\[test\]\\|#\[tokio::test\]' crates/rmm-agent-core/tests/store.rs) -ge 12` | 0 | PASS |

## Key Decisions
- `rusqlite` is 0.32 rather than the latest 0.41 (the plan says latest). The lockfile has `sqlx-sqlite` 0.8.6, which needs `libsqlite3-sys` 0.30.x, and only rusqlite 0.32 uses that; newer versions fail on the duplicate `links = "sqlite3"`.
- `keystore_named` returns no `Result`, so an invalid name makes every `load`, `store` and `delete` fail instead of panicking.
- Each outbox payload is encrypted with the `msg_id` as its row key, since `seq` does not exist before the insert.
- For `seq_floor`, the clear-text `seq` is also in the AAD of the encrypted `content_id`. Editing `seq` in the file makes the floor unreadable.
- The `SeqStore`/`ReplayCache` traits cannot return errors, so the store fails closed. An unreadable floor reports `(u64::MAX, ..)` so every document is rejected, and a failed replay check reports "already seen".
- A failed `SeqStore::put` sets a sticky `Store::seq_write_failed()` flag, and enroll checks it after applying the bundle.
- Eviction in `outbox_push`: when over a bound, it drops rows with priority > 0 and >= the new row's priority, highest priority number first and oldest first. Priority 0 is never dropped. A push that cannot make room is itself dropped and returns false. Dropped rows are counted in `Store::dropped_count()`.
- The byte bound counts stored ciphertext length, nonce and tag included.
- `Store::open_with_limits` was added so tests can use small bounds; `open` uses 50000 rows and 64 MiB.
- Nonces and the store key come from `rand::rngs::SysRng`, the same OS random source enroll already uses.
- `--force` re-enroll keeps the existing seq floors and store, so rollback protection also holds across a forced re-enroll.

## Issues Encountered
- `.planning/STATE.md` and `.planning/memory/PREFERENCES.md` show as modified in git. I did not touch them.
- `Store::seq_get` and the replay-pruning clock use `SystemTime`; the `ReplayCache` trait has no clock, so the replay prune test uses real time.
- BLOCKER: $ scripts/check-layering.sh (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | api | Resolve: $ scripts/check-layering.sh (exit 1) | pending |  |

- #1 context: Verification failed (scripts/check-layering.sh); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: Cargo.lock; Cargo.toml; crates/rmm-agent-core/Cargo.toml; crates/rmm-agent-core/src/enroll.rs; crates/rmm-agent-core/src/lib.rs; crates/rmm-agent-core/src/store.rs; crates/rmm-agent-core/tests/store.rs; crates/rmm-platform/src/keystore.rs; crates/rmm-platform/src/lib.rs; crates/rmm-platform/src/windows.rs
- **Decisions made**: `rusqlite` is 0.32 rather than the latest 0.41 (the plan says latest). The lockfile has `sqlx-sqlite` 0.8.6, which needs `libsqlite3-sys` 0.30.x, and only rusqlite 0.32 uses that; newer versions fail on the duplicate `links = "sqlite3"`.; `keystore_named` returns no `Result`, so an invalid name makes every `load`, `store` and `delete` fail instead of panicking.; Each outbox payload is encrypted with the `msg_id` as its row key, since `seq` does not exist before the insert.; For `seq_floor`, the clear-text `seq` is also in the AAD of the encrypted `content_id`. Editing `seq` in the file makes the floor unreadable.; The `SeqStore`/`ReplayCache` traits cannot return errors, so the store fails closed. An unreadable floor reports `(u64::MAX, ..)` so every document is rejected, and a failed replay check reports "already seen".; A failed `SeqStore::put` sets a sticky `Store::seq_write_failed()` flag, and enroll checks it after applying the bundle.; Eviction in `outbox_push`: when over a bound, it drops rows with priority > 0 and >= the new row's priority, highest priority number first and oldest first. Priority 0 is never dropped. A push that cannot make room is itself dropped and returns false. Dropped rows are counted in `Store::dropped_count()`.; The byte bound counts stored ciphertext length, nonce and tag included.; `Store::open_with_limits` was added so tests can use small bounds; `open` uses 50000 rows and 64 MiB.; Nonces and the store key come from `rand::rngs::SysRng`, the same OS random source enroll already uses.; `--force` re-enroll keeps the existing seq floors and store, so rollback protection also holds across a forced re-enroll.
- **Open questions**: (none)
- **Conventions established**: Callers open the store with `Store::open(dir, rmm_platform::keystore_named(dir, STORE_KEY_FILE).as_ref())`. `DB_FILE` and `STORE_KEY_FILE` are exported from `store`.; `Store` is `Send + Sync`, all methods are synchronous (use `spawn_blocking`), and `Store` and `&Store` both implement `SeqStore` and `ReplayCache`, so an `Arc<Store>` works.; `outbox_peek` fails the whole call if any row fails to decrypt, so a corrupt row would block a drain. Plan 05-02 needs a policy for that.; `outbox_push` returns false when the row was dropped by the bounds; plan 05-02 should count or log it.; Dedupe in the outbox relies on the `msg_id` unique column. Re-pushing an id that was already deleted queues it again.

## Requirements Covered
- REQ-14

## Error Details
Verification failed: scripts/check-layering.sh

### Failed verification output
`scripts/check-layering.sh`
```
PASS crate rmm-proto exists in workspace
PASS crate rmm-trust exists in workspace
PASS crate rmm-recipe exists in workspace
PASS crate rmm-platform exists in workspace
PASS crate rmm-agent-core exists in workspace
PASS crate rmm-agent exists in workspace
PASS crate rmm-watchdog exists in workspace
PASS crate rmm-session exists in workspace
PASS crate rmm-db exists in workspace
PASS crate rmm-api exists in workspace
PASS crate rmm-server exists in workspace
PASS crate rmm-sign exists in workspace
PASS rmm-db does not depend on rmm-platform or rmm-agent-core
PASS rmm-api does not depend on rmm-platform or rmm-agent-core
PASS rmm-server does not depend on rmm-platform or rmm-agent-core
PASS rmm-agent does not enable rmm-trust feature sign
FAIL rmm-agent-core enables rmm-trust feature sign
PASS rmm-watchdog does not enable rmm-trust feature sign
PASS rmm-session does not enable rmm-trust feature sign
PASS rmm-watchdog does not depend on tokio
PASS rmm-proto does not depend on rmm-platform
PASS rmm-trust does not depend on rmm-platform
PASS rmm-recipe does not depend on rmm-platform
PASS rmm-agent does not depend on age
PASS rmm-agent-core does not depend on age
PASS rmm-watchdog does not depend on age
PASS rmm-session does not depend on age

```

## Token Usage
24 requests, 1678588 input tokens (1578846 cached), 42202 output tokens, $0.9871
