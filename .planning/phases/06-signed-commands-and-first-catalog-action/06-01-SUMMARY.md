# Plan 06-01 Summary: Recipe schema, validator, fixtures and phase dependencies

## Result
**Status**: Partial
**Wave**: 1
**Agent**: engineering-security-engineer
**Completed**: 2026-11-01
**Failure Class**: BLOCKER — $ cargo clippy --workspace --all-targets --locked -- -D warnings (exit 101)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-security-engineer | — | 5 | 2.5 | 7.5 | mandatory |
| engineering-senior-developer | — | 20 | 3.77 | 23.77 | heuristic |
| engineering-infrastructure-devops | — | 14 | 3.67 | 17.67 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: Dependencies and document types (done)
- [x] Task 2: Static and parameter validation (done)
- [x] Task 3: Golden negative-path fixtures (done)

## Files Modified
- `Cargo.lock`
- `Cargo.toml`
- `catalog/printing.spooler-restart.json`
- `crates/rmm-agent-core/tests/fixtures/README.md`
- `crates/rmm-agent-core/tests/fixtures/cmd-bad-param.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-expired.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-good-param.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-replay.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-revoked.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-rogue-definition.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-tampered.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-unknown-block.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-valid.env`
- `crates/rmm-agent-core/tests/fixtures/cmd-wrong-agent.env`
- `crates/rmm-agent-core/tests/fixtures/definition-param.env`
- `crates/rmm-agent-core/tests/fixtures/definition-revoked.env`
- `crates/rmm-agent-core/tests/fixtures/definition-rogue.env`
- `crates/rmm-agent-core/tests/fixtures/definition-unknown-block.env`
- `crates/rmm-agent-core/tests/fixtures/definition-valid.env`
- `crates/rmm-agent-core/tests/fixtures/manifest.env`
- `crates/rmm-agent-core/tests/fixtures/revocations.env`
- `crates/rmm-agent-core/tests/fixtures/root.pub.hex`
- `crates/rmm-api/Cargo.toml`
- `crates/rmm-recipe/Cargo.toml`
- `crates/rmm-recipe/src/definition.rs`
- `crates/rmm-recipe/src/lib.rs`
- `crates/rmm-recipe/src/result.rs`
- `crates/rmm-recipe/src/validate.rs`
- `crates/rmm-recipe/tests/validate.rs`
- `crates/rmm-server/Cargo.toml`
- `xtask/Cargo.toml`
- `xtask/src/action_fixtures.rs`
- `xtask/src/main.rs`

## Verification Results
6/8 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-recipe --locked` | 0 | PASS |
| `cargo run -q -p xtask -- action-fixtures && git diff --exit-code crates/rmm-agent-core/tests/fixtures/` | 0 | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 101 | FAIL |
| `scripts/check-layering.sh` | 0 | PASS |
| `cargo deny check` | 0 | PASS |
| `cargo build --workspace --locked` | 101 | FAIL |
| `cargo clippy -p rmm-recipe --all-targets --locked -- -D warnings` | 0 | PASS |
| `test -f crates/rmm-agent-core/tests/fixtures/README.md` | 0 | PASS |

## Key Decisions
- A snapshot key is the producing block's name, for example `service.query`. Step has no snapshot-name field.
- A service definition may also use files.write blocks, via the ALLOWED_EXTRA table in validate.rs. Without it the spooler action would fail its own capability check.
- The spooler `files.quarantine` root is the logical name "spool", which the platform maps to its allowlisted root.
- The spooler verify stage is `service.wait running` with 2 retries, since no block compares a query result.
- Unset string `max_len` defaults to 256 and is capped at 4096.
- TooManySteps and InvalidRetries are unit variants. The other RecipeError variants carry strings.

## Issues Encountered
- The rmm-agent-core compile error blocks the workspace-wide build and clippy checks. Plan 06-02 or a separate fix has to repair or add `Store::outbox_clear`.
- The `cmd-valid.env`, `cmd-replay.env` and `cmd-good-param.env` fixtures are all valid. The tests must feed `cmd-replay.env` twice to get the replay rejection.
- Blocked: none
- BLOCKER: $ cargo clippy --workspace --all-targets --locked -- -D warnings (exit 101)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | out-of-scope file | Who fixes the missing `Store::outbox_clear()` call in crates/rmm-agent-core/src/enroll.rs:402? | pending | INVALID: type "out-of-scope file" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 2 | blocker | api | Resolve: $ cargo clippy --workspace --all-targets --locked -- -D warnings (exit 101) | pending |  |

- #1 context: crates/rmm-agent-core/src/ is forbidden for this plan and I did not touch it. The error appears with this plan's changes in place. Only this plan's workspace-wide build and clippy criteria are affected.
- #2 context: Verification failed (cargo clippy --workspace --all-targets --locked -- -D warnings; cargo build --workspace --locked); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: Cargo.lock; Cargo.toml; catalog/printing.spooler-restart.json; crates/rmm-agent-core/tests/fixtures/README.md; crates/rmm-agent-core/tests/fixtures/cmd-bad-param.env; crates/rmm-agent-core/tests/fixtures/cmd-expired.env; crates/rmm-agent-core/tests/fixtures/cmd-good-param.env; crates/rmm-agent-core/tests/fixtures/cmd-replay.env; crates/rmm-agent-core/tests/fixtures/cmd-revoked.env; crates/rmm-agent-core/tests/fixtures/cmd-rogue-definition.env; crates/rmm-agent-core/tests/fixtures/cmd-tampered.env; crates/rmm-agent-core/tests/fixtures/cmd-unknown-block.env; crates/rmm-agent-core/tests/fixtures/cmd-valid.env; crates/rmm-agent-core/tests/fixtures/cmd-wrong-agent.env; crates/rmm-agent-core/tests/fixtures/definition-param.env; crates/rmm-agent-core/tests/fixtures/definition-revoked.env; crates/rmm-agent-core/tests/fixtures/definition-rogue.env; crates/rmm-agent-core/tests/fixtures/definition-unknown-block.env; crates/rmm-agent-core/tests/fixtures/definition-valid.env; crates/rmm-agent-core/tests/fixtures/manifest.env; crates/rmm-agent-core/tests/fixtures/revocations.env; crates/rmm-agent-core/tests/fixtures/root.pub.hex; crates/rmm-api/Cargo.toml; crates/rmm-recipe/Cargo.toml; crates/rmm-recipe/src/definition.rs; crates/rmm-recipe/src/lib.rs; crates/rmm-recipe/src/result.rs; crates/rmm-recipe/src/validate.rs; crates/rmm-recipe/tests/validate.rs; crates/rmm-server/Cargo.toml; xtask/Cargo.toml; xtask/src/action_fixtures.rs; xtask/src/main.rs
- **Decisions made**: A snapshot key is the producing block's name, for example `service.query`. Step has no snapshot-name field.; A service definition may also use files.write blocks, via the ALLOWED_EXTRA table in validate.rs. Without it the spooler action would fail its own capability check.; The spooler `files.quarantine` root is the logical name "spool", which the platform maps to its allowlisted root.; The spooler verify stage is `service.wait running` with 2 retries, since no block compares a query result.; Unset string `max_len` defaults to 256 and is capped at 4096.; TooManySteps and InvalidRetries are unit variants. The other RecipeError variants carry strings.
- **Open questions**: (none)
- **Conventions established**: Fixtures use NOW=1_800_000_000, agent `agent_0000000000000001`, client `client_0000000000000001`. `root.pub.hex` is the single compiled root with threshold 1, and the manifest ceiling is [service, files.write]. The README lists each file and its expected rejection.; Definitions and results use `from_envelope_payload` for strict canonical decoding and `to_canonical` to encode. Neither decoder validates. The agent must run validate_definition(def, BLOCKS) and then validate_params.; The validator does not bound literal values such as `timeout_s`, or check `Definition.timeout_s` against them. The executor must clamp them to the definition timeout.; rmm-sign (plan 06-04) must parse the catalog JSON draft as a Definition. Args are written `{"lit": ...}`, `{"param": ...}` or `{"snapshot": ...}`.

## Requirements Covered
- REQ-15
- REQ-16

### Failed verification output
`cargo clippy --workspace --all-targets --locked -- -D warnings`
```
    Checking rmm-agent-core v0.1.0 (/home/user/custom-rmm/crates/rmm-agent-core)
    Checking rmm-sign v0.1.0 (/home/user/custom-rmm/crates/rmm-sign)
    Checking rmm-server v0.1.0 (/home/user/custom-rmm/crates/rmm-server)
error[E0599]: no method named `outbox_clear` found for struct `store::Store` in the current scope
   --> crates/rmm-agent-core/src/enroll.rs:402:61
    |
402 |         let purged = tokio::task::spawn_blocking(move || db.outbox_clear())
    |                                                             ^^^^^^^^^^^^
    |
   ::: crates/rmm-agent-core/src/store.rs:123:1
    |
123 | pub struct Store {
    | ---------------- method `outbox_clear` not found for this struct
    |
help: there is a method `outbox_len` with a similar name
    |
402 -         let purged = tokio::task::spawn_blocking(move || db.outbox_clear())
402 +         let purged = tokio::task::spawn_blocking(move || db.outbox_len())
    |

    Checking rmm-api v0.1.0 (/home/user/custom-rmm/crates/rmm-api)
For more information about this error, try `rustc --explain E0599`.
error: could not compile `rmm-agent-core` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...

```
`cargo build --workspace --locked`
```
   Compiling rmm-agent-core v0.1.0 (/home/user/custom-rmm/crates/rmm-agent-core)
   Compiling rmm-server v0.1.0 (/home/user/custom-rmm/crates/rmm-server)
   Compiling rmm-sign v0.1.0 (/home/user/custom-rmm/crates/rmm-sign)
   Compiling rmm-watchdog v0.1.0 (/home/user/custom-rmm/crates/rmm-watchdog)
   Compiling rmm-session v0.1.0 (/home/user/custom-rmm/crates/rmm-session)
error[E0599]: no method named `outbox_clear` found for struct `Store` in the current scope
   --> crates/rmm-agent-core/src/enroll.rs:402:61
    |
402 |         let purged = tokio::task::spawn_blocking(move || db.outbox_clear())
    |                                                             ^^^^^^^^^^^^
    |
   ::: crates/rmm-agent-core/src/store.rs:123:1
    |
123 | pub struct Store {
    | ---------------- method `outbox_clear` not found for this struct
    |
help: there is a method `outbox_len` with a similar name
    |
402 -         let purged = tokio::task::spawn_blocking(move || db.outbox_clear())
402 +         let purged = tokio::task::spawn_blocking(move || db.outbox_len())
    |

For more information about this error, try `rustc --explain E0599`.
error: could not compile `rmm-agent-core` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...

```

## Token Usage
17 requests, 1146815 input tokens (1054984 cached), 37359 output tokens, $0.8141
