# Project State

## Current Position
- **Phase**: 1 of 9 (planned)
- **Status**: Phase 1 planned -- 3 plans across 3 waves
- **Last Activity**: Phase 1 planning (2026-10-31)

## Progress
```
[....................] 0% — 0/29 plans complete
```

## Recent Decisions
- Approach B (balanced) from the design exploration
- Remote shell requires a technician WebAuthn co-signature verified by the agent
- Hardware-only authenticators for shell co-sign (AAGUID allowlist)
- YubiKey signing via OpenPGP applet Ed25519 with openpgp-card crates; PIV Ed25519 (fw 5.7+) is the fallback
- Deterministic CBOR envelopes, signatures over a fixed digest
- NATS agent auth via a Rust auth callout issuing scoped JWTs
- Agent key Ed25519 wrapped by DPAPI in phase 1; TPM later
- Metrics in a private compressed hypertable behind scoped views
- App-level AEAD local store instead of SQLCipher
- CI uses both cargo-xwin cross-compile and a native Windows runner
- Entra ID OIDC for technician login; recordings retained 1 year; revocation mirror deferred
- Root key generated air-gapped, age-encrypted on two USB sticks (safe + offsite)
- Foundation is broken into 9 Triad phases (design milestones M0-M8); product phases 2-6 come later

## Next Action
Run `/triad:build` to execute Phase 1: Workspace, dev environment and CI
