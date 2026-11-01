# Phase 8: Watchdog and A/B updater -- Context

## Phase Goal
Agents update themselves from signed releases through a sync, network-free watchdog with A/B slots, health-check rollback, downgrade and tamper rejection, and core restart.

## Requirements Covered
- REQ-21

## What Already Exists (from prior phases)
- rmm-trust: Role::Release exists; envelope types manifest/revocations/command/techlist; TrustStore::verify_role; compiled roots via option_env!("RMM_ROOT_PUBKEYS") pattern in rmm-agent-core
- rmm-sign: DocType variants Manifest, Revocations, Techlist, Command, Definition
- rmm-api: POST /api/v1/trust/{kind} for manifest/revocations/techlist with seq tracking; Admin extractor; AppState with nats client
- rmm-server natsjwt.rs grants agents pub svc.trust.latest, but nothing serves it yet, so running agents never receive new manifests, revocations or techlists (phase 7 gap)
- rmm-watchdog: skeleton main.rs, deps rmm-proto + rmm-trust only
- rmm-agent: CLI binary run by hand/e2e (no service host yet); heartbeat reports version
- e2e scripts pattern: scripts/e2e-actions.sh, scripts/e2e-shell.sh, dev-trust.sh file-backend signing

## Key Design Decisions
- ReleaseManifest (rmm.release/1, Role::Release): {seq, version (semver string), issued_at, expires_at, artifacts:[{platform:'windows-x86_64'|'linux-x86_64', sha256:32 bytes, size:u64, name}]}; validate(): version parses as semver, at least one artifact, unique platforms, size > 0 and <= 268435456
- Distribution: the api process serves NATS request/reply svc.trust.latest (latest stored manifest, revocations and techlist envelopes as a CBOR map) and svc.release.latest (latest stored release envelope or empty); agents request both on connect and every 15 minutes, and apply trust documents through the existing verified TrustUpdate path (higher seq only)
- Artifacts: POST /api/v1/admin/artifacts (Admin, raw body <= 256 MiB) stores RMM_ARTIFACT_DIR/<sha256 hex> computed server-side (0600 file, 0700 dir); GET /v1/artifacts/{sha256} unauthenticated, streamed, 404 if absent; the channel is untrusted because the hash is signed
- Version source: agent version = option_env!("RMM_AGENT_VERSION") or CARGO_PKG_VERSION; release builds use the workspace version
- Watchdog root layout (Windows %ProgramData%\RMM\, unix --root DIR): slots/a/, slots/b/, bootstrap/ (MSI-owned, never written by the watchdog), pending/ (agent writes release.env, manifest.env, the artifact, then READY last), state.json {active:'a'|'b'|'bootstrap', active_version, previous, release_seq_floor, bad_hashes[], trial:{slot, version, started_at}|null}; state written atomically (write temp + rename) and ACL'd SYSTEM+Administrators on Windows
- Watchdog verification (independent of the agent): manifest.env chains to the compiled root keys, release.env verifies with Role::Release under that manifest, release.seq > release_seq_floor, semver version > active_version (downgrade or equal rejected), artifact for this platform has matching size and SHA-256, hash not in bad_hashes; anything else deletes pending/ and logs the reason
- Health: the agent writes <state_dir>/health.json {version, pid, ts} after its first successful heartbeat publish and refreshes it every heartbeat; the watchdog treats a trial as healthy when health.json shows the trial version and its pid within the health timeout (default 180 s, flag max 300 s); otherwise, or after 3 crashes during the trial, it rolls back to previous, adds the hash to bad_hashes and keeps release_seq_floor at the bad release's seq
- Supervision: the watchdog spawns the active slot's agent binary with the configured args and restarts it after exit with backoff 1, 2, 4, 8 s (cap 8 s, reset after 60 s of uptime), so a killed core restarts within 10 s
- The watchdog is a Windows service (SCM dispatcher via the windows crate, LocalSystem) and a foreground process on unix for dev/e2e; it depends only on rmm-proto, rmm-trust and windows, has no async runtime and no network code (layering check enforces it)
- The e2e bad build is a correctly signed artifact that never becomes healthy (a script that sleeps), proving rollback without test hooks in the agent

## Plan Structure
- **Plan 08-01 (Wave 1)**: Signed releases, artifact hosting and trust/release distribution -- Add the ReleaseManifest document and its rmm-sign support, artifact upload and download, and NATS responders for svc.trust.latest and svc.release.latest, plus the agent-side periodic refresh that applies new trust documents.
- **Plan 08-02 (Wave 2)**: Watchdog: A/B slots, verified apply, health rollback and supervision -- Turn rmm-watchdog into the supervisor and updater: it runs the active slot's agent, restarts it within 10 s, independently verifies and applies pending releases into the inactive slot, and rolls back builds that fail the health check.
- **Plan 08-03 (Wave 3)**: Agent update client, health signal and end-to-end update -- Have the agent download newer signed releases into pending/, write its health signal, and prove apply, rollback, downgrade and tamper rejection and core restart end to end.
