# Plan 01-03 Summary: GitHub Actions CI

## Result
**Status**: Partial
**Wave**: 3
**Agent**: engineering-infrastructure-devops
**Completed**: 2026-10-31
**Failure Class**: BLOCKER — $ scripts/ci-local.sh lint (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-infrastructure-devops | — | 20 | 0 | 20 | heuristic |
| engineering-senior-developer | — | 20 | 0 | 20 | heuristic |
| testing-qa-verification-specialist | — | 19 | 0 | 19 | heuristic |

- **Task type detected**: implementation
- **Confidence**: MEDIUM
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: CI workflow (done)
- [ ] Task 2: actionlint and local CI runner (partial)
- [x] Task 3: CI documentation (done)

## Files Modified
- `.github/workflows/ci.yml`
- `README.md`
- `docs/ci.md`
- `scripts/ci-local.sh`

## Verification Results
9/10 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `$HOME/.local/bin/actionlint .github/workflows/ci.yml \|\| actionlint .github/workflows/ci.yml` | 0 | PASS |
| `scripts/ci-local.sh lint` | 1 | FAIL |
| `scripts/ci-local.sh windows-cross` | 0 | PASS |
| `python3 -c "import yaml;d=yaml.safe_load(open('.github/workflows/ci.yml'));assert {'lint','windows-cross','test-linux','test-windows'} <= set(d['jobs'])"` | 0 | PASS |
| `grep -q 'contents: read' .github/workflows/ci.yml` | 0 | PASS |
| `bash -n scripts/ci-local.sh` | 0 | PASS |
| `scripts/ci-local.sh test-linux` | 0 | PASS |
| `test -f docs/ci.md` | 0 | PASS |
| `grep -q 'ci-local.sh' docs/ci.md` | 0 | PASS |
| `grep -q 'docs/ci.md' README.md` | 0 | PASS |

## Key Decisions
- The cache key is `cargo-xwin-<version from cargo xwin --version>-<hash of rust-toolchain.toml>-xwin-v1`.
- `DATABASE_URL` is built from `RMM_PG_PASSWORD` in deploy/.env.example against localhost:5432. The `RMM_DATABASE_URL` in that file points at the compose-internal host `timescale`, which the runner can't reach.
- `SQLX_OFFLINE=false` is set for the `cargo sqlx prepare --check` step only.
- `XWIN_ACCEPT_LICENSE=1` is set for the windows-cross job and in ci-local.sh.

## Issues Encountered
- RUSTSEC-2026-0382: rustls-webpki 0.102.8 comes in through async-nats 0.42.0 and rmm-server. The fix is >=0.103.16, but async-nats pins the old version. The remedy is in Cargo.toml/Cargo.lock (upgrade async-nats), or in deny.toml (an ignore entry). I may not edit any of these.
- test-windows and the real GitHub runs could not be exercised here.
- BLOCKER: $ scripts/ci-local.sh lint (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | dependency | Resolve RUSTSEC-2026-0382 (rustls-webpki 0.102.8 via async-nats 0.42.0). Choose between upgrading async-nats or adding a justified ignore to deny.toml. | pending |  |
| 2 | blocker | quality | Resolve: $ scripts/ci-local.sh lint (exit 1) | pending |  |

- #1 context: Both options touch files outside plan 01-03 (Cargo.toml, Cargo.lock, deny.toml). `cargo deny check` is a lint gate, so the lint job and `ci-local.sh lint` fail until this is decided.
- #2 context: Verification failed (scripts/ci-local.sh lint); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: .github/workflows/ci.yml; README.md; docs/ci.md; scripts/ci-local.sh
- **Decisions made**: The cache key is `cargo-xwin-<version from cargo xwin --version>-<hash of rust-toolchain.toml>-xwin-v1`.; `DATABASE_URL` is built from `RMM_PG_PASSWORD` in deploy/.env.example against localhost:5432. The `RMM_DATABASE_URL` in that file points at the compose-internal host `timescale`, which the runner can't reach.; `SQLX_OFFLINE=false` is set for the `cargo sqlx prepare --check` step only.; `XWIN_ACCEPT_LICENSE=1` is set for the windows-cross job and in ci-local.sh.
- **Open questions**: (none)
- **Conventions established**: CI will fail at lint's `cargo deny check` until the advisory above is resolved.; Regenerate .sqlx and the OpenAPI spec whenever queries or routes change, since both are CI gates.; test-linux needs Docker and uses RMM_HTTPS_PORT=8443.

## Requirements Covered
- REQ-03
- REQ-23

### Failed verification output
`scripts/ci-local.sh lint`
```
-alpha.7 (try `cargo update -p rustls-webpki`)
    [0m[36m├[0m rustls-webpki v0.102.8
      └── async-nats v0.42.0
          └── rmm-server v0.1.0

[0m[1m[38;5;9merror[vulnerability][0m[1m: Certificate verification may accept distrusted intermediates[0m
    [0m[36m┌─[0m /home/user/custom-rmm/Cargo.lock:163:1
    [0m[36m│[0m
[0m[36m163[0m [0m[36m│[0m [0m[31mrustls-webpki 0.102.8 registry+https://github.com/rust-lang/crates.io-index[0m
    [0m[36m│[0m [0m[31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[0m [0m[31msecurity vulnerability detected[0m
    [0m[36m│[0m
    [0m[36m├[0m ID: RUSTSEC-2026-0382
    [0m[36m├[0m Advisory: https://rustsec.org/advisories/RUSTSEC-2026-0382
    [0m[36m├[0m Affected versions may accept certificate paths containing distrusted emSign
      intermediate public keys when the configured trust anchors allow such paths.
      The private keys corresponding to these intermediates are now well known.
      
      Versions 0.103.16 and 0.104.0-alpha.8 reject paths containing these public keys.
    [0m[36m├[0m Announcement: https://github.com/rustls/webpki/pull/546
    [0m[36m├[0m Solution: Upgrade to >=0.103.16, <0.104.0-alpha.1 OR >=0.104.0-alpha.8 (try `cargo update -p rustls-webpki`)
    [0m[36m├[0m rustls-webpki v0.102.8
      └── async-nats v0.42.0
          └── rmm-server v0.1.0

advisories [31mFAILED[0m, bans [32mok[0m, licenses [32mok[0m, sources [32mok[0m

```

## Token Usage
7 requests, 174863 input tokens (151443 cached), 7130 output tokens, $0.1601
