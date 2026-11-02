# Plan 08-01 Summary: Signed releases, artifact hosting and trust/release distribution

## Result
**Status**: Complete with Warnings
**Wave**: 1
**Agent**: engineering-backend-architect
**Completed**: 2026-11-01

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-backend-architect | — | 14 | 3.47 | 17.47 | mandatory |
| engineering-senior-developer | — | 19 | 3.89 | 22.89 | heuristic |
| testing-qa-verification-specialist | — | 16 | 3.58 | 19.58 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: ReleaseManifest document and rmm-sign support (done)
- [x] Task 2: Artifact hosting and NATS distribution (done)
- [x] Task 3: Agent periodic trust and release refresh (done)

## Files Modified
- `crates/rmm-agent-core/src/commands.rs`
- `crates/rmm-agent-core/src/lib.rs`
- `crates/rmm-agent-core/src/refresh.rs`
- `crates/rmm-agent-core/tests/refresh.rs`
- `crates/rmm-agent/src/main.rs`
- `crates/rmm-api/Cargo.toml`
- `crates/rmm-api/src/admin.rs`
- `crates/rmm-api/src/artifacts.rs`
- `crates/rmm-api/src/distribution.rs`
- `crates/rmm-api/src/lib.rs`
- `crates/rmm-api/src/state.rs`
- `crates/rmm-api/tests/artifacts.rs`
- `crates/rmm-api/tests/distribution.rs`
- `crates/rmm-db/migrations/0007_releases.sql`
- `crates/rmm-db/src/lib.rs`
- `crates/rmm-db/src/releases.rs`
- `crates/rmm-server/src/api.rs`
- `crates/rmm-server/src/natsjwt.rs`
- `crates/rmm-server/tests/natsjwt.rs`
- `crates/rmm-sign/src/cli.rs`
- `crates/rmm-sign/src/drafts.rs`
- `crates/rmm-sign/tests/cli.rs`
- `crates/rmm-trust/src/docs.rs`
- `crates/rmm-trust/src/envelope.rs`
- `crates/rmm-trust/tests/release.rs`
- `deploy/.env.example`
- `deploy/compose.yaml`
- `deploy/nats/nats.conf`
- `deploy/nginx/nginx.conf`
- `docs/openapi.json`

## Verification Results
13/13 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-trust` | 0 | PASS |
| `cargo test -p rmm-sign` | 0 | PASS |
| `cargo test -p rmm-agent-core` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-db -p rmm-api -p rmm-server --locked` | 0 | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 | PASS |
| `bash scripts/check-layering.sh` | 0 | PASS |
| `bash scripts/check-agent-no-sign.sh` | 0 | PASS |
| `cargo test -p rmm-trust --test release` | 0 | PASS |
| `DATABASE_URL=postgres://rmm:$(grep '^RMM_PG_PASSWORD=' deploy/.env.example \| cut -d= -f2)@127.0.0.1:5432/rmm cargo test -p rmm-api --test artifacts --test distribution` | 0 | PASS |
| `cargo test -p rmm-server --test natsjwt` | 0 | PASS |
| `t=$(mktemp) && cp docs/openapi.json "$t" && cargo run -q -p xtask -- openapi && cmp docs/openapi.json "$t"` | 0 | PASS |
| `cargo test -p rmm-agent-core --test refresh` | 0 | PASS |
| `cargo clippy -p rmm-agent-core -p rmm-agent --all-targets -- -D warnings` | 0 | PASS |

## Key Decisions
- `rmm-trust/Cargo.toml` is not in the file list, so I could not add the `semver` crate there. Version validation uses a hand-written strict semver 2.0 check (`docs::is_semver`) with the same accept/reject rules. 08-02 may want the `semver` crate directly in the watchdog; adding it to `rmm-trust` would need a one-line Cargo.toml change plus the Cargo.lock entry.
- The trust upload route stays `PUT /api/v1/trust/{kind}` (the plan wrote POST); 'release' is handled outside `DocKind`, because `store.rs` is not writable.
- Extra `validate()` rules beyond the plan: `expires_at` must be after `issued_at` (max 400 days), artifact names must be plain file names, and platform strings are not restricted to the two known values.
- `nats.conf`: the api user needed `allow_responses` because agents reply on their own `_INBOX_<id>` prefix.
- Artifact upload returns 201 with `{sha256_hex, size}`. The 256 MiB limit is enforced by counting bytes (413), not only by `DefaultBodyLimit`.
- The refresh skips documents already cached byte for byte, and an older seq is refused by the store's rollback check and only logged.

## Issues Encountered
- `scripts/dev-trust.sh` is not in my file list, so it does not create `deploy/dev/artifacts`. The bind mount must exist and be writable by uid 10001 (like `deploy/dev/recordings`) before the API container starts.
- Not tested: the 256 MiB oversize path (it would take too long to stream), and the nginx and nats.conf changes (no nginx or nats-server in the sandbox).

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | info | out-of-scope-file | Add `semver.workspace = true` to `crates/rmm-trust/Cargo.toml`, or keep the hand-written `is_semver`? | pending | INVALID: type "out-of-scope-file" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 2 | info | deployment | Have `scripts/dev-trust.sh` create `deploy/dev/artifacts` with mode 777? | pending | INVALID: type "deployment" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |

- #1 context: The plan says to use the workspace semver crate, but `crates/rmm-trust/Cargo.toml` is not in `files_modified`, so I wrote `is_semver` instead and did not touch it. 08-02 needs semver ordering for the downgrade check and will probably want the crate in the watchdog's dependencies.
- #2 context: The compose bind mount for `RMM_ARTIFACT_DIR` needs the directory to exist and be writable by uid 10001, the same as the recordings directory. The script is outside this plan's file list.

## Handoff Context
- **Key outputs**: crates/rmm-agent-core/src/commands.rs; crates/rmm-agent-core/src/lib.rs; crates/rmm-agent-core/src/refresh.rs; crates/rmm-agent-core/tests/refresh.rs; crates/rmm-agent/src/main.rs; crates/rmm-api/Cargo.toml; crates/rmm-api/src/admin.rs; crates/rmm-api/src/artifacts.rs; crates/rmm-api/src/distribution.rs; crates/rmm-api/src/lib.rs; crates/rmm-api/src/state.rs; crates/rmm-api/tests/artifacts.rs; crates/rmm-api/tests/distribution.rs; crates/rmm-db/migrations/0007_releases.sql; crates/rmm-db/src/lib.rs; crates/rmm-db/src/releases.rs; crates/rmm-server/src/api.rs; crates/rmm-server/src/natsjwt.rs; crates/rmm-server/tests/natsjwt.rs; crates/rmm-sign/src/cli.rs; crates/rmm-sign/src/drafts.rs; crates/rmm-sign/tests/cli.rs; crates/rmm-trust/src/docs.rs; crates/rmm-trust/src/envelope.rs; crates/rmm-trust/tests/release.rs; deploy/.env.example; deploy/compose.yaml; deploy/nats/nats.conf; deploy/nginx/nginx.conf; docs/openapi.json
- **Decisions made**: `rmm-trust/Cargo.toml` is not in the file list, so I could not add the `semver` crate there. Version validation uses a hand-written strict semver 2.0 check (`docs::is_semver`) with the same accept/reject rules. 08-02 may want the `semver` crate directly in the watchdog; adding it to `rmm-trust` would need a one-line Cargo.toml change plus the Cargo.lock entry.; The trust upload route stays `PUT /api/v1/trust/{kind}` (the plan wrote POST); 'release' is handled outside `DocKind`, because `store.rs` is not writable.; Extra `validate()` rules beyond the plan: `expires_at` must be after `issued_at` (max 400 days), artifact names must be plain file names, and platform strings are not restricted to the two known values.; `nats.conf`: the api user needed `allow_responses` because agents reply on their own `_INBOX_<id>` prefix.; Artifact upload returns 201 with `{sha256_hex, size}`. The 256 MiB limit is enforced by counting bytes (413), not only by `DefaultBodyLimit`.; The refresh skips documents already cached byte for byte, and an older seq is refused by the store's rollback check and only logged.
- **Open questions**: (none)
- **Conventions established**: `refresh::run(client, store, RefreshOptions{agent, shell, on_release, wake, shutdown}, interval)`: 08-03 sets `on_release` in `crates/rmm-agent/src/main.rs`. The callback runs in a blocking context, and the release seq floor is not persisted by the agent.; `rmm_trust::docs::verify_release(&TrustStore, envelope_bytes, now)` is the check for a release envelope. The watchdog can use the same function, since `rmm-trust` is one of its allowed dependencies.; Artifacts are named by the server-computed SHA-256 at `GET /v1/artifacts/{sha256_hex}`; the download is unauthenticated and the signed hash is the trust anchor.

## Requirements Covered
- REQ-21

## Token Usage
51 requests, 6322537 input tokens (6126303 cached), 69617 output tokens, $2.4120
