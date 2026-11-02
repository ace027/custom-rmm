# Runbook: release and rollback of the agent

Purpose: publish a new agent build to all endpoints, watch it roll out, and recover from a bad build. Updates are pulled by the agent, verified twice (agent and watchdog) against the compiled-in root keys, installed by the watchdog into the inactive A/B slot and kept only if the new agent reports healthy.

How it works, in short:

1. The agent asks the server for the latest `release` (on connect and every 15 minutes), verifies it with the `release` role, and skips it when the version is not newer than its own, when the watchdog marked the artifact bad, or when a release is already staged.
2. Otherwise it downloads `GET /v1/artifacts/<sha256>` into `<root>/pending/`, compares size and SHA-256 with the signed values, writes `manifest.env`, `release.env`, `artifact` and last an empty `READY`.
3. `rmm-watchdog` verifies the staged release itself (manifest chain to the root keys, release role, time window, sequence above its floor, newer version, platform artifact, size, hash, not in `bad_hashes`), copies the artifact into the inactive slot, records a trial in `state.json` and starts it.
4. The new agent writes `health.json` (`version`, `pid`, `ts`) after each heartbeat. When it names the trial's version and pid within the health timeout (default 3 minutes, at most 5 minutes), the watchdog promotes the slot. Otherwise it returns to the previous slot and adds the artifact hash to `bad_hashes`.

## Before you start

- You need the `release` YubiKey (`yubikey-setup.md`), the `rmm-sign` binary from a reviewed commit, an Admin token for the API and the version number. Versions are semantic versions and must be strictly higher than the running one; the sequence number must be strictly higher than every earlier release.
- The manifest installed on the server must grant the `release` role to your key (`root-ceremony.md`).

## Build

Build on the Windows runner with the production root keys compiled in; the version is baked in at build time:

```powershell
$env:RMM_ROOT_PUBKEYS = "<hex root key[,hex root key]>"
$env:RMM_AGENT_VERSION = "1.4.0"
cargo build --release --locked -p rmm-agent
```

The result is `target\release\rmm-agent.exe` for `windows-x86_64`. Check `rmm-agent.exe --version` prints `rmm-agent 1.4.0`, and run `scripts/check-agent-no-sign.sh` on the build machine's commit. The build must stay under 256 MiB.

## Upload

```sh
curl -sS --data-binary @rmm-agent.exe -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/octet-stream' \
  https://rmm.example.com/api/v1/admin/artifacts
# {"sha256_hex":"<64 hex>","size":12345678}
```

The server computes the hash and stores the file under it; note both values. A repeated upload of the same bytes is harmless.

## Draft, sign, publish

Write `release.json`; `sha256` is the hex value returned by the upload, `size` the byte count, `name` a plain file name, `seq` higher than any earlier release, `expires_at` at most 400 days after `issued_at`:

```json
{
  "seq": 12,
  "version": "1.4.0",
  "issued_at": 1800000000,
  "expires_at": 1807776000,
  "artifacts": [
    {"platform": "windows-x86_64", "sha256": "<64 hex>", "size": 12345678, "name": "rmm-agent.exe"}
  ]
}
```

Sign with the YubiKey (release role) and review what is shown before confirming:

```sh
rmm-sign sign --type release --in release.json --backend card --expect-key-id <key_id> --out release.env
rmm-sign verify --roots <root pubkey> --root-threshold 1 --manifest manifest.env release.env
curl -sS -X PUT --data-binary @release.env -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/octet-stream' https://rmm.example.com/api/v1/trust/release
```

HTTP 204 means the server verified and stored it. 422 means verification failed (wrong role, expired, sequence not above the stored release, or the stored manifest does not know your key). Releases are not pushed: agents pick it up within 15 minutes or at their next reconnect.

## Watch the rollout

- Agents that applied the update report the new `agent_version` in their heartbeats; compare against the number of active agents. Agents that are offline update when they reconnect.
- On an endpoint, `rmm-watchdog status --root "%ProgramData%\RMM"` prints `state.json`: `active_version`, `trial` (set while a new build is being proven), `bad_hashes`, `release_seq_floor`. The watchdog logs one JSON line per transition (`release_staged`, `release_installed`, `trial_promoted`, `trial_rolled_back`, `release_rejected` with a `reason`).
- Roll out to a few machines first by publishing during a quiet period and checking the first promotions before the rest reconnect.

## Roll back

Downgrades are rejected by design, on the agent and in the watchdog, so a release cannot be replaced by an older version number. To go back to the previous build, publish it again as a newer release: rebuild (or reuse the previous artifact bytes) with a higher version, for example `1.4.1`, a higher `seq`, and the previous build's hash. Agents install it like any other update.

A build that starts but never reports healthy (crash, hang, no heartbeat within the health timeout) needs no action on the endpoint: the watchdog goes back to the previous slot by itself and records the hash in `bad_hashes`. The server keeps offering the release, the agent finds the hash in `bad_hashes` (`KnownBad`) and does nothing. Publish a fixed build with a higher version.

## What `bad_hashes` means

`bad_hashes` in `state.json` lists SHA-256 values of artifacts that failed a trial on this endpoint. The watchdog never installs them again and the agent does not download them. It is per endpoint and persistent. The same bytes are never retried; a fixed build has a different hash. Do not edit the file by hand; reinstalling the agent resets it.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Agent log `update failed ... hash_mismatch` | The stored artifact differs from the signed hash: upload again and publish a new release. |
| `release_rejected` `bad_manifest` / `bad_release` | The staged manifest does not chain to the compiled root keys, or the release was not signed with the `release` role. |
| `release_rejected` `replayed_seq` | `seq` is not above the one installed last. |
| `release_rejected` `downgrade` | The version is not higher than the active one. |
| `trial_rolled_back` | The new build did not report healthy in time; read the agent's own log first. |
| Agent log `no watchdog root: updates are disabled` | The agent runs without `rmm-watchdog` (set `RMM_WATCHDOG_ROOT` if the root is elsewhere). |
