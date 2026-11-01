# Phase 1: Workspace, dev environment and CI — Review Summary

## Result: PASSED

**Cycles Used**: 1
**Reviewers**: testing-qa-verification-specialist, engineering-senior-developer
**Evaluators**: code-quality, integration, business-logic
**Completed**: 2026-10-31

## Findings Summary
- Must-fix (blocker, critical, major) found: 0; fixed: 0; unresolved: 0
- Suggestions (minor, advisory): 0
- Deferred (confidence 50-79%): 14
- Hot spots (flagged by 2+ reviewers): `scripts/check-layering.sh`, `deploy/compose.yaml`, `scripts/dev-up.sh`, `scripts/test-layering.sh`

## Findings Detail
(none)

## Reviewer Verdicts
- Cycle 1, testing-qa-verification-specialist: **NEEDS WORK**
- Cycle 1, engineering-senior-developer: **PASS**
- Cycle 1, evaluator:code-quality: **NEEDS WORK**
- Cycle 1, evaluator:integration: **PASS**
- Cycle 1, evaluator:business-logic: **PASS**

## Suggestions (Not Required)
(none)

## Deferred (Medium Confidence)
- `scripts/check-layering.sh` [major, 75%]: The `rmm-trust` `sign` feature check runs `cargo tree ... -i rmm-trust 2>/dev/null || true`. Any cargo failure (bad flag, unresolved package, `rmm-trust` not in that crate's tree) gives empty output. The `grep` then finds nothing, and the script reports PASS.
- `deploy/compose.yaml` [minor, 60%]: Required secrets and URLs use `${VAR}` rather than `${VAR:?msg}`. If `deploy/.env` is missing or incomplete, compose only warns and substitutes an empty string. Postgres then starts with an empty password, or fails with an unclear error, and NATS auth runs with empty passwords.
- `deploy/compose.yaml` [minor, 70%]: The database image is `timescale/timescaledb:latest-pg17`, a floating tag. The NATS and nginx images are pinned.
- `scripts/dev-up.sh` [minor, 50%]: The script copies `.env.example` (with its default passwords) to `.env` without any warning. It also hardcodes the sandbox-specific path `/root/.ccr/ca-bundle.crt`. The default nginx port 443 also needs privileges, or a free port, on a developer machine.
- `crates/rmm-server/src/main.rs` [minor, 60%]: One 290-line file holds the CLI definition, the api/ingest/authd/migrate/openapi/healthcheck subcommands, the NATS connect and watcher loop, the healthcheck probe, and the tests. The server's NATS connection and health state logic is not separated from the CLI dispatch.
- `crates/rmm-platform/Cargo.toml` [minor, 55%]: The crate cannot inherit `[workspace.lints]` and also relax `unsafe_code`. It copies the whole clippy and rust lint table by hand, with `unsafe_code = "allow"` and the extra `undocumented_unsafe_blocks`.
- `scripts/check-layering.sh` [minor, 50%]: The layering rules are hard-coded in bash that shells out to `cargo tree` and `grep`. The crate list is a hard-coded string, and the python3 snippet parses `cargo metadata`. The rules are not data-driven, so each new crate or rule means more shell. Part of the same intent is probably also in `deny.toml`.
- `Cargo.toml (also scripts/check-layering.sh, crates/rmm-sign/Cargo.toml)` [major, 70%]: `rmm-sign` enables `rmm-trust/sign`, and it is a workspace member. Cargo unifies features for any multi-package invocation, so `cargo build --workspace` and `cargo test --workspace` compile `rmm-trust` with `sign` and link it into `rmm-agent` and the other endpoint binaries. The layering check runs `cargo tree -p <agent crate> -e features` one package at a time. It never sees the unified case, so it passes while the real build ships signing code.
- `scripts/test-layering.sh` [minor, 60%]: The negative tests inject violations only into `rmm-api` (server to platform) and `rmm-agent-core` (sign). The `rmm-server`, `rmm-db`, `rmm-watchdog` (tokio) and `rmm-proto`, `rmm-trust`, `rmm-recipe` (platform) rules have no negative test.
- `scripts/dev-up.sh` [minor, 70%]: The script hardcodes the sandbox-specific path `/root/.ccr/ca-bundle.crt` and auto-injects it as the extra CA. The `--network host` and proxy build args in the Dockerfile and compose file are also environment-specific.
- `crates/rmm-watchdog/src/main.rs, crates/rmm-sign/src/main.rs, crates/rmm-session/src/main.rs, crates/rmm-agent/src/main.rs` [advisory, 55%]: The binary skeletons have no tests, and the `--version` branches are untested. The `sign` feature path in `rmm-trust` is covered only by running the binary.
- `crates/rmm-api/src/lib.rs` [minor, 60%]: The router serves `GET /openapi.json`, but `paths(healthz)` leaves it out of the OpenAPI document. nginx doesn't proxy `/openapi.json`, so it is reachable only inside the compose network.
- `.dockerignore` [minor, 65%]: `deploy/.env` is not excluded from the build context. `COPY . .` copies it into the build stage.
- `.github/workflows/ci.yml` [minor, 50%]: `test-windows` runs `cargo test` and builds only `rmm-agent`. It does not build `rmm-watchdog`, `rmm-session` or `rmm-sign` natively, and it runs no clippy. These crates are covered only by the cross-compile job.

## Fixes Applied
- minor findings: engineering-senior-developer on F-001, F-002, F-003, F-004, F-006, F-007, F-009 (partial); engineering-backend-architect on F-005 (done); left as is: F-001 (partly): I did not add a negative test that injects features=["sign"]. The existing case (b) already does this on rmm-agent-core and passes. / F-003: not fixed. I can't verify an exact timescaledb tag offline, and a made-up tag could break the stack. Someone needs to pick the version. / F-006 (partly): I did not add the matching comment to the root Cargo.toml, which is outside my writable list. I also did not add an automated table-comparison check. / F-007: not fixed. Moving the rules to an xtask subcommand or cargo-deny is a design change. / F-002 (not checked): I did not run `docker compose config` to confirm the `:?` syntax is accepted. / F-004: the 443 privilege problem is only documented in a comment. The default port is unchanged. / F-005: not fixed. The split needs new files (`cli.rs`, `nats.rs`, `healthcheck.rs`), but I may only write `crates/rmm-server/src/main.rs`. It is also a large restructuring, not a small fix, so it needs the orchestrator to approve the module layout and the extra writable files.; checks 39/39 passed, 5 file(s) changed

## Coverage
No coverage data found (looked for coverage/coverage-summary.json, coverage-summary.json, coverage/lcov.info, lcov.info, coverage.xml, coverage/cobertura-coverage.xml, coverage/coverage.xml, coverage.txt, coverage/coverage.txt). Advisory only: run the test suite with coverage to check review.coverage_thresholds.
