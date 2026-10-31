# Phase 2: Trust core and signing CLI -- Context

## Phase Goal
Verifiable signing chain: canonical CBOR envelopes, certificates, trust manifest, revocations, command and technician-list types, WebAuthn verification, and rmm-sign with file and YubiKey backends

## Requirements Covered
- REQ-04
- REQ-05
- REQ-06
- REQ-07

## What Already Exists (from prior phases)
- Phase 1: workspace with 12 crates; rmm-trust has feature `sign` gating `pub mod sign` (placeholder SIGNING_ENABLED) and `pub mod verify` (placeholder); rmm-proto has PROTOCOL_VERSION and subject builders; rmm-sign is a stub depending on rmm-trust[sign]
- scripts/check-layering.sh enforces per-package: agent-side crates never enable rmm-trust/sign; CI in .github/workflows/ci.yml with jobs lint, windows-cross, test-linux, test-windows; scripts/ci-local.sh mirrors the Linux jobs
- Phase 1 review deferred finding (major): cargo unifies features in multi-package builds, so `cargo build --workspace` or one cargo-xwin invocation listing rmm-agent and rmm-sign compiles rmm-trust with `sign` into the agent. This phase adds a binary-level check and builds the agent in its own invocation
- Design: .planning/explorations/2026-10-31-rmm-backend-phase1-design.md section 'Signing chain'

## Key Design Decisions
- Canonical encoding: deterministic CBOR (RFC 8949 4.2.1) via serde + ciborium::Value with our own canonical encoder: shortest-form integers and lengths, definite lengths only, map keys sorted bytewise by their encoded form, no duplicate keys, no floats, no tags, no undefined/simple values except bool and null, nesting depth <= 32, no trailing bytes. Decoding parses with ciborium, re-encodes canonically and rejects unless byte-identical (NonCanonical), then deserializes
- Byte newtypes (KeyId [u8;32], Sig64 [u8;64], Bytes Vec<u8>) serialize as lowercase hex strings when the serializer is human-readable (JSON drafts) and as CBOR byte strings otherwise
- Envelope {v: 1, type: text, payload: bytes, sigs: [{key_id: bytes32, alg: "ed25519", sig: bytes64}]}. key_id = SHA-256(raw 32-byte Ed25519 public key). PAE = "DSSEv1 " || ascii(len(type)) || " " || type || " " || ascii(len(payload)) || " " || payload. Signed message M = b"RMMSIG1" || SHA-256(PAE) (39 bytes); Ed25519 (pure) over M
- Payload type strings: rmm.manifest/1, rmm.revocations/1, rmm.command/1, rmm.techlist/1
- All times are u64 Unix seconds; clock skew tolerance 300 s; clock, sequence store and replay cache are injected traits so verification is pure and testable
- Certificates live inside the root-signed TrustManifest (no separate cert envelopes); roles: root, catalog, release, techlist, artifact-revoke, command, policy; thresholds per role in the manifest, 1-of-1 today
- Root rotation: a new manifest must meet the threshold of the currently trusted root set and, if its root_keys differ, the threshold of its own root set; seq strictly increasing; equal seq accepted only if the payload hash is identical (else Equivocation)
- Fuzzing uses proptest on the stable toolchain (random bytes and structured mutations of canonical encodings); libFuzzer is deferred because the toolchain is pinned stable
- Golden vectors: committed JSON files under crates/rmm-trust/tests/vectors/ generated from fixed seeds by an #[ignore]d test run with RMM_REGEN_VECTORS=1; normal tests check encode(struct)==bytes, decode(bytes)==struct and signature verification
- YubiKey: OpenPGP applet Ed25519 signing slot through openpgp-card 0.7 + card-backend-pcsc 0.5 behind rmm-sign cargo feature `card` (default on). Linux needs libpcsclite-dev (CI installs it); Windows uses winscard. No hardware exists in CI or this sandbox, so the hardware criterion is proven by a manual script and recorded as a human step
- Root key file: Ed25519 seed age-encrypted with a passphrase (age crate, scrypt), passphrase from RMM_SIGN_PASSPHRASE or an interactive prompt
- Agent binaries must not contain signing code: rmm-trust's sign module carries a #[used] marker static; scripts/check-agent-no-sign.sh builds rmm-agent alone (Linux and x86_64-pc-windows-msvc) and fails if the marker string is in the binary, and confirms the marker is present in rmm-sign
- Board quick-assess ran before plans existed (score 3.8, all concerns about missing artifacts); its recommendations are adopted as constraints: golden vectors both directions, proptest corpora for non-canonical CBOR, negative tests for seq rollback, expiry, revoked and wrong-role keys, a check that the agent excludes sign, the ceremony runbook, and a recorded YubiKey session (manual)
- Architecture proposals skipped (--auto, no spec assessment)

## Plan Structure
- **Plan 02-01 (Wave 1)**: Canonical CBOR codec, keys and signed envelope -- Implement deterministic CBOR encode/strict decode in rmm-proto, key and byte newtypes, the DSSE-style envelope with Ed25519 signing (sign feature) and single-signature verification in rmm-trust, with golden vectors and proptest coverage; stub the remaining rmm-trust modules for wave 2.
- **Plan 02-02 (Wave 2)**: Trust documents, manifest chain and revocation verification -- Define the TrustManifest, certificates, ArtifactRevocations, Command, ShellGrant and TechnicianList documents and implement the TrustStore that verifies them with role thresholds, revocation, expiry, rollback and equivocation protection, plus command binding and replay checks.
- **Plan 02-03 (Wave 2)**: WebAuthn assertion verification -- Implement agent-side verification of a WebAuthn assertion over a ShellGrant challenge (ES256 and EdDSA), with COSE key parsing and full test coverage.
- **Plan 02-04 (Wave 3)**: rmm-sign CLI, YubiKey backend, runbooks and agent no-sign check -- Build the rmm-sign CLI with an age-encrypted file backend (root) and an OpenPGP-card Ed25519 backend (YubiKey, touch), readable diffs before signing, the root ceremony and YubiKey runbooks, and a binary-level check that the agent contains no signing code, wired into CI.
