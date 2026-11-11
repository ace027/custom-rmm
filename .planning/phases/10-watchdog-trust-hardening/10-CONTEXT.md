# Phase 10: Watchdog trust hardening -- Context

## Phase Goal
The watchdog honors key and artifact revocation on its own: it never accepts a trust manifest older than one it has seen, and never installs a revoked release.

## Requirements Covered
- REQ-24

## What Already Exists (from prior phases)
- crates/rmm-watchdog/src/apply.rs verify_pending: builds a fresh TrustStore with MemorySeqStore per check, so any validly signed unexpired manifest in pending/ is accepted; no revocation check
- crates/rmm-watchdog/src/state.rs State{active, active_version, previous, release_seq_floor, bad_hashes, trial} saved as state.json (temp + rename); a .bak fallback exists; a corrupt state falls back to bootstrap with floors at 0
- crates/rmm-agent-core/src/update.rs stages manifest.env, release.env, artifact, then READY; refresh.rs already refuses revoked releases on the agent side (TrustStore::is_artifact_revoked, Envelope::content_id)
- rmm-trust: TrustStore::apply_manifest / apply_revocations, ArtifactRevocations{seq, expires_at, revoked_hashes}, Role::ArtifactRevoke
- Fixtures for the watchdog come from `cargo run -p xtask -- action-fixtures` (crates/rmm-watchdog/tests/fixtures/, byte-exact via .gitattributes); scripts/e2e-update.sh has 5 checks

## Key Design Decisions
- State gains manifest_seq_floor and revocations_seq_floor (u64, serde default 0). A manifest that verifies against the compiled roots with seq below manifest_seq_floor is rejected with reason stale_manifest; a verified manifest with a higher seq raises the floor (saved before anything else happens), whatever the release outcome
- The agent stages a fourth file, revocations.env (its current stored revocation list envelope), before READY. The watchdog requires it: missing, not verifying under the staged manifest with the artifact-revoke role, expired, or with seq below revocations_seq_floor gives bad_revocations; a higher seq raises the floor
- A release whose envelope content id or this platform's artifact sha256 is in the verified revocation list is rejected with reason revoked
- Fail closed on state loss: when state.json exists but neither it nor its backup parses, the watchdog keeps supervising the bootstrap slot and rejects every pending release with reason state_corrupt until an operator removes or repairs the file; a state file that is simply absent (fresh install) starts normally with floors at 0
- Old state files without the new fields load with floors 0 (upgrade path); an agent older than this phase stages no revocations.env and is therefore not updatable by a new watchdog, which is acceptable because agent and watchdog ship together in the MSI and nothing is deployed yet
- Check order in verify_pending: manifest verifies -> manifest floor -> revocations verify and floor -> release verifies -> revoked -> existing seq, downgrade, platform, known-bad, size and hash checks

## Plan Structure
- **Plan 10-01 (Wave 1)**: Watchdog manifest and revocation floors, revoked-release rejection -- Make the watchdog reject stale manifests, stale or missing revocation lists and revoked releases, and fail closed when its state is corrupt.
- **Plan 10-02 (Wave 2)**: Agent stages the revocation list; end-to-end checks and runbook -- Have the agent stage revocations.env with every release and prove the new watchdog rejections end to end.
