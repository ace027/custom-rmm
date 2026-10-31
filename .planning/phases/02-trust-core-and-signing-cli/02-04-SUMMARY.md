# Plan 02-04 Summary: rmm-sign CLI, YubiKey backend, runbooks and agent no-sign check

## Result
**Status**: Partial
**Wave**: 3
**Agent**: engineering-senior-developer
**Completed**: 2026-10-31
**Failure Class**: BLOCKER — $ scripts/ci-local.sh lint (exit 1)

## Agent Selection Rationale

| Candidate | Semantic | Heuristic | Memory | Total | Source |
|-----------|----------|-----------|--------|-------|--------|
| engineering-senior-developer | — | 23 | 0 | 23 | mandatory |
| engineering-infrastructure-devops | — | 22 | 3.67 | 25.67 | heuristic |
| testing-qa-verification-specialist | — | 18 | 0 | 18 | heuristic |

- **Task type detected**: implementation
- **Confidence**: LOW
- **Adapter**: claude-code
- **Model tier**: sonnet

## Completed Tasks
- [x] Task 1: CLI and file backend (done)
- [x] Task 2: YubiKey OpenPGP backend and manual smoke script (done)
- [x] Task 3: Root ceremony runbook, agent no-sign check and CI wiring (done)

## Files Modified
- `.github/workflows/ci.yml`
- `Cargo.lock`
- `crates/rmm-sign/Cargo.toml`
- `crates/rmm-sign/src/card_backend.rs`
- `crates/rmm-sign/src/cli.rs`
- `crates/rmm-sign/src/drafts.rs`
- `crates/rmm-sign/src/file_backend.rs`
- `crates/rmm-sign/src/main.rs`
- `crates/rmm-sign/tests/cli.rs`
- `docs/ci.md`
- `docs/runbooks/root-ceremony.md`
- `docs/runbooks/yubikey-setup.md`
- `scripts/check-agent-no-sign.sh`
- `scripts/ci-local.sh`
- `scripts/yubikey-smoke.sh`

## Verification Results
14/16 verification commands passed (run by Triad after the agent finished).

## Verification Commands
| Command | Exit Code | Result |
|---------|-----------|--------|
| `cargo test -p rmm-sign --locked` | 0 | PASS |
| `scripts/check-agent-no-sign.sh` | 0 | PASS |
| `scripts/check-layering.sh` | 0 | PASS |
| `cargo test --workspace --locked` | 0 | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | PASS |
| `scripts/ci-local.sh lint` | 1 | FAIL |
| `cargo build -p rmm-sign --locked` | 0 | PASS |
| `cargo build -p rmm-sign --no-default-features --locked` | 0 | PASS |
| `cargo clippy -p rmm-sign --all-targets --locked -- -D warnings` | 0 | PASS |
| `cargo test -p rmm-sign --locked card` | 0 | PASS |
| `bash -n scripts/yubikey-smoke.sh` | 0 | PASS |
| `grep -q 'set-touch sig fixed' docs/runbooks/yubikey-setup.md` | 0 | PASS |
| `cargo xwin build --target x86_64-pc-windows-msvc -p rmm-sign --locked` | 101 | FAIL |
| `$HOME/.local/bin/actionlint .github/workflows/ci.yml \|\| actionlint .github/workflows/ci.yml` | 0 | PASS |
| `grep -q 'check-agent-no-sign' .github/workflows/ci.yml` | 0 | PASS |
| `grep -qi 'dry run' docs/runbooks/root-ceremony.md` | 0 | PASS |

## Key Decisions
- Draft diff, signer line and confirmation prompt go to stderr; stdout carries only results (key ids, wrote/signer lines, verify output).
- Added the `serde` and `getrandom = "0.2"` dependencies. `serde` is needed for the generic draft helpers. `getrandom` supplies the OsRng seed because rand_core 0.10 has no OsRng. Both are already in Cargo.lock via age.
- `verify` on a manifest prints the root signers; on techlist, revocations and command it uses `verify_role`. Non-manifest documents need --manifest.
- `--expect-key-id` is also accepted by `pubkey` and `sign` for the file backend, not just the card.
- check-agent-no-sign.sh deletes old binaries before building so a stale binary cannot pass.

## Issues Encountered
- The disk filled up during the work, so I ran `cargo clean` on the build output and rebuilt with CARGO_PROFILE_DEV_DEBUG=0.
- The CLI test suite takes about 15 s because each invocation does an age scrypt operation.
- BLOCKER: $ scripts/ci-local.sh lint (exit 1)

## Escalations
| # | Severity | Type | Decision | Status | Resolution |
|---|----------|------|----------|--------|------------|
| 1 | blocker | quality-gate / out-of-scope file | How to handle the two `cargo deny` advisories that adding `age` introduces. Options: (a) add justified `ignore` entries for RUSTSEC-2026-0374 and RUSTSEC-2026-0387 in deny.toml; (b) replace `age` with a different passphrase-encryption approach, which means a plan change. `deny.toml` is not in my file list and overriding a quality gate is outside my authority. | pending | INVALID: type "quality-gate / out-of-scope file" is not one of architecture, dependency, scope, schema, api, deletion, infrastructure, quality |
| 2 | blocker | quality | Resolve: $ scripts/ci-local.sh lint (exit 1) | pending |  |

- #1 context: The baseline `cargo deny check` was clean before this plan. RUSTSEC-2026-0374 is `basic-toml` (unmaintained), pulled by age through i18n-embed-fl, with no upgrade available. RUSTSEC-2026-0387 is a constant-time vulnerability in crypto-bigint 0.5.5, pulled by age through hpke and p256 0.13, and cannot be upgraded here. age 0.12 has no feature flag to drop either dependency, and the plan names `age`. Both are build-time or tool-side risks: the unmaintained crate is not exercised at runtime, and rmm-sign never uses the age p256/hpke recipients. Neither is in the agent (the check-agent-no-sign.sh run confirms the agent binary has no signing code). `scripts/ci-local.sh lint` and the CI lint job stay red until this is decided.
- #2 context: Verification failed (scripts/ci-local.sh lint; cargo xwin build --target x86_64-pc-windows-msvc -p rmm-sign --locked); a BLOCKER is not auto-fixed.

## Handoff Context
- **Key outputs**: .github/workflows/ci.yml; Cargo.lock; crates/rmm-sign/Cargo.toml; crates/rmm-sign/src/card_backend.rs; crates/rmm-sign/src/cli.rs; crates/rmm-sign/src/drafts.rs; crates/rmm-sign/src/file_backend.rs; crates/rmm-sign/src/main.rs; crates/rmm-sign/tests/cli.rs; docs/ci.md; docs/runbooks/root-ceremony.md; docs/runbooks/yubikey-setup.md; scripts/check-agent-no-sign.sh; scripts/ci-local.sh; scripts/yubikey-smoke.sh
- **Decisions made**: Draft diff, signer line and confirmation prompt go to stderr; stdout carries only results (key ids, wrote/signer lines, verify output).; Added the `serde` and `getrandom = "0.2"` dependencies. `serde` is needed for the generic draft helpers. `getrandom` supplies the OsRng seed because rand_core 0.10 has no OsRng. Both are already in Cargo.lock via age.; `verify` on a manifest prints the root signers; on techlist, revocations and command it uses `verify_role`. Non-manifest documents need --manifest.; `--expect-key-id` is also accepted by `pubkey` and `sign` for the file backend, not just the card.; check-agent-no-sign.sh deletes old binaries before building so a stale binary cannot pass.
- **Open questions**: (none)
- **Conventions established**: The agent binary is built alone to avoid feature unification. Keep that in any new CI steps.; A manifest root_keys entry is the 64-hex public key printed by keygen-root, not the key_id.; Run scripts/yubikey-smoke.sh with a real YubiKey at review or ship and record its PASS line.

## Requirements Covered
- REQ-07

### Failed verification output
`scripts/ci-local.sh lint`
```
ate at the first unequal limb,
     and `BoxedMontyForm::invert` branched on whether an inverse exists.
     
     ## Impact
     
     Applications using affected operations on secret integers may leak information
     through timing or microarchitectural side channels. This includes information
     about intermediate arithmetic values, matching limbs, and invertibility.
     
     Such leakage could potentially enable recovery of cryptographic secrets.
     Practical exploitability depends on the downstream algorithm, compiler, target
     CPU, and an attacker's ability to observe the side channel.
     
     ## Resolution
     
     Upgrade to v0.7.6, which removes the identified branches, updates `ctutils` to
     include its constant-time fixes, and adds BINSEC-based regression checks using
     `cargo checkct` for arithmetic on multiple targets.
   [0m[36m├[0m Announcement: https://github.com/RustCrypto/crypto-bigint/pull/1365
   [0m[36m├[0m Solution: Upgrade to >=0.7.6 (try `cargo update -p crypto-bigint`)
   [0m[36m├[0m crypto-bigint v0.5.5
     └── elliptic-curve v0.13.8
         ├── p256 v0.13.2
         │   ├── age v0.12.1
         │   │   └── rmm-sign v0.1.0
         │   └── hpke v0.12.0
         │       ├── age v0.12.1 (*)
         │       └── age-core v0.12.0
         │           └── age v0.12.1 (*)
         └── primeorder v0.13.6
             └── p256 v0.13.2 (*)

advisories [31mFAILED[0m, bans [32mok[0m, licenses [32mok[0m, sources [32mok[0m

```
`cargo xwin build --target x86_64-pc-windows-msvc -p rmm-sign --locked`
```
ocks_in_conditions' '--allow=clippy::assigning_clones' --cfg 'feature="color"' --cfg 'feature="error-context"' --cfg 'feature="help"' --cfg 'feature="std"' --cfg 'feature="suggestions"' --cfg 'feature="usage"' --check-cfg 'cfg(docsrs,test)' --check-cfg 'cfg(feature, values("cargo", "color", "debug", "default", "deprecated", "env", "error-context", "help", "std", "string", "suggestions", "unicode", "unstable-doc", "unstable-ext", "unstable-styles", "unstable-v5", "usage", "wrap_help"))' -C metadata=06f5e1b7abd1138e -C extra-filename=-d58c0c22c702d65c --out-dir /home/user/custom-rmm/target/x86_64-pc-windows-msvc/debug/deps --target x86_64-pc-windows-msvc -C linker=lld-link -L dependency=/home/user/custom-rmm/target/x86_64-pc-windows-msvc/debug/deps -L dependency=/home/user/custom-rmm/target/debug/deps --extern anstream=/home/user/custom-rmm/target/x86_64-pc-windows-msvc/debug/deps/libanstream-83fbf579d9458f41.rmeta --extern anstyle=/home/user/custom-rmm/target/x86_64-pc-windows-msvc/debug/deps/libanstyle-7ebf8fbae680072b.rmeta --extern clap_lex=/home/user/custom-rmm/target/x86_64-pc-windows-msvc/debug/deps/libclap_lex-8f566446ca2a503d.rmeta --extern strsim=/home/user/custom-rmm/target/x86_64-pc-windows-msvc/debug/deps/libstrsim-46ceab9a0436df1e.rmeta --cap-lints allow -C linker-flavor=lld-link -Lnative=/root/.cache/cargo-xwin/xwin/crt/lib/x86_64 -Lnative=/root/.cache/cargo-xwin/xwin/sdk/lib/um/x86_64 -Lnative=/root/.cache/cargo-xwin/xwin/sdk/lib/ucrt/x86_64` (exit status: 101)

```

## Token Usage
50 requests, 5070272 input tokens (4925336 cached), 64080 output tokens, $1.9882
