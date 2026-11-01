---
phase: 02-trust-core-and-signing-cli
compacted: 2026-10-31
original_summaries: [02-01-SUMMARY.md, 02-02-SUMMARY.md, 02-03-SUMMARY.md, 02-04-SUMMARY.md]
requirements_satisfied: [REQ-04, REQ-05, REQ-06, REQ-07]
---

# Phase 2: Trust core and signing CLI — Compacted Summary

## Deliverables
- 02-01 Canonical CBOR codec, keys and signed envelope (Complete): Cargo.lock, Cargo.toml, crates/rmm-proto/Cargo.toml, crates/rmm-proto/src/canonical.rs, crates/rmm-proto/src/lib.rs, crates/rmm-proto/tests/canonical_props.rs, crates/rmm-sign/src/main.rs, crates/rmm-trust/Cargo.toml, crates/rmm-trust/src/docs.rs, crates/rmm-trust/src/envelope.rs, crates/rmm-trust/src/error.rs, crates/rmm-trust/src/keys.rs, crates/rmm-trust/src/lib.rs, crates/rmm-trust/src/sign.rs, crates/rmm-trust/src/store.rs, crates/rmm-trust/src/verify.rs, crates/rmm-trust/src/webauthn.rs, crates/rmm-trust/tests/envelope_vectors.rs, crates/rmm-trust/tests/vectors/envelope.json
- 02-02 Trust documents, manifest chain and revocation verification (Complete with Warnings): crates/rmm-trust/src/docs.rs, crates/rmm-trust/src/error.rs, crates/rmm-trust/src/store.rs, crates/rmm-trust/src/verify.rs, crates/rmm-trust/tests/docs_vectors.rs, crates/rmm-trust/tests/trust_store.rs, crates/rmm-trust/tests/vectors/docs.json
- 02-03 WebAuthn assertion verification (Complete): crates/rmm-trust/src/webauthn.rs, crates/rmm-trust/tests/webauthn.rs
- 02-04 rmm-sign CLI, YubiKey backend, runbooks and agent no-sign check (Complete)

## Decisions
- 02-01: ed25519-dalek 3.0 has no "std" feature, so the workspace dep uses default-features=false with features ["zeroize"]
- 02-01: Depth is the number of nested containers: 32 is accepted, 33 is rejected. ciborium's recursion limit error maps to DepthExceeded.
- 02-01: ciborium decodes CBOR "undefined" (f7) as null, so it is rejected as NonCanonical rather than Malformed. A test records this.
- 02-02: CommandBody uses tag "kind" with kebab-case variants (invoke, shell-open, trust-update, collect). Collect keeps the Rust field `kind` but sends it on the wire a
- 02-03: Check order: authenticator data under 37 bytes, then clientDataJSON parse (Malformed), type, challenge, origin, rpIdHash, UP, UV, and the signature last.
- 02-03: `crossOrigin: true` returns `Origin`.
- 02-03: Challenge decoding is strict base64url: no padding, no non-zero trailing bits. Any decode failure returns `Challenge`.

## Conventions and Open Questions
- 02-01 convention: Envelope.verify_sig(&entry, &PublicKey) checks one signature only. Threshold logic, role checks and WrongType enforcement belong to the plan 02-02 TrustStore.
- 02-01 convention: Signer is a trait object (&dyn Signer), so the plan 02-04 age-file and YubiKey backends only need to implement it. Ed25519Signer::from_seed is the software path
- 02-01 convention: no key-generation helper exists yet.
- 02-02 convention: The agent and CLI should use rmm_trust::verify::{TrustStore, Clock, SeqStore, ReplayCache, DocKind, FixedClock, MemorySeqStore, MemoryReplayCache}. Document typ
- 02-03 convention: Phase 7 builds `Expected { challenge: shell_challenge(canonical_grant_bytes), rp_id, origins, require_uv }`. It then calls `parse_cose_key(stored_cose_bytes)` a
- 02-03 convention: `AuthFlags.sign_count` is returned, but replay and counter policy are not enforced here and belong to the caller.
- 02-03 convention: p256 with the `ecdsa` feature already includes signing, so no extra dev feature was needed.
- 02-04 convention: Signing CLI: `rmm-sign` has keygen-root, pubkey, sign, verify and inspect. Backends are `file:<path>` and `card[:<ident>]`, and `card` is a default feature.
- 02-04 convention: `scripts/check-agent-no-sign.sh` is wired into CI and is the binary-level guard against signing code reaching the agent.

## Files Modified
| File | Change |
|------|--------|
| `Cargo.lock` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `Cargo.toml` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-proto/Cargo.toml` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-proto/src/canonical.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-proto/src/lib.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-proto/tests/canonical_props.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-sign/src/main.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/Cargo.toml` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/docs.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/envelope.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/error.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/keys.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/lib.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/sign.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/store.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/verify.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/webauthn.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/tests/envelope_vectors.rs` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/tests/vectors/envelope.json` | 02-01: Canonical CBOR codec, keys and signed envelope |
| `crates/rmm-trust/src/docs.rs` | 02-02: Trust documents, manifest chain and revocation verification |
| `crates/rmm-trust/src/error.rs` | 02-02: Trust documents, manifest chain and revocation verification |
| `crates/rmm-trust/src/store.rs` | 02-02: Trust documents, manifest chain and revocation verification |
| `crates/rmm-trust/src/verify.rs` | 02-02: Trust documents, manifest chain and revocation verification |
| `crates/rmm-trust/tests/docs_vectors.rs` | 02-02: Trust documents, manifest chain and revocation verification |
| `crates/rmm-trust/tests/trust_store.rs` | 02-02: Trust documents, manifest chain and revocation verification |
| `crates/rmm-trust/tests/vectors/docs.json` | 02-02: Trust documents, manifest chain and revocation verification |
| `crates/rmm-trust/src/webauthn.rs` | 02-03: WebAuthn assertion verification |
| `crates/rmm-trust/tests/webauthn.rs` | 02-03: WebAuthn assertion verification |

## Verification
- 02-01 (REQ-04): 13/13 verification commands passed
- 02-02 (REQ-05, REQ-06): 8/8 verification commands passed
- 02-03 (REQ-04): 4/4 verification commands passed
- 02-04 (REQ-07): 16/16 verification commands passed

## Agents
- 02-01: engineering-senior-developer
- 02-02: engineering-security-engineer
- 02-03: engineering-security-engineer
- 02-04: engineering-senior-developer

## Also Covered
- crates/rmm-sign/Cargo.toml
- crates/rmm-sign/src/cli.rs
- crates/rmm-sign/src/file_backend.rs
- crates/rmm-sign/src/card_backend.rs
- crates/rmm-sign/src/drafts.rs
- crates/rmm-sign/tests/cli.rs
- docs/runbooks/root-ceremony.md
- docs/runbooks/yubikey-setup.md
- scripts/yubikey-smoke.sh
- .github/workflows/ci.yml
- scripts/ci-local.sh
- docs/ci.md
