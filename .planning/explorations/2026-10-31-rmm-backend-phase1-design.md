# Design Exploration — RMM Backend Workspace and Phase 1

## Initial Ask

Explore and plan the RMM backend from the platform spec (read in full: `RMM Platform Spec.md` at the repo root; the ask referred to `docs/spec.md`, which does not exist).

This repo is a Rust Cargo workspace for the agent (Windows first, then Linux, macOS), watchdog, session helper, server, shared crate, and YubiKey signing CLI. The web UI is **not** built here (it is `packages/rmm` in the separate React 19 / TypeScript 7 suite monorepo); this repo exposes an OpenAPI spec via `utoipa`.

Non-negotiables:
- No AI on endpoints; the agent only runs signed catalog actions and signed scripts.
- The server can invoke signed definitions but never create them; root key offline, signing key on YubiKey, signed revocation list.
- Agent connects outbound only (NATS over WebSocket, TLS 443).
- No obfuscation, packers, or `-EncodedCommand`; prefer OS APIs over shelling out.
- Postgres + TimescaleDB with row-level security; `client_id` on every table.
- No n8n anywhere.

Goal: propose the workspace/crate layout, CI, dev environment, and a detailed phase 1 plan (enrollment with per-agent identity, inventory, heartbeat, remote shell, signing chain), flagging spec gaps and risky assumptions first.

## Research Summary

### Facts
- The repo contains only `README.md`, `RMM Platform Spec.md` and `RMM Technician Console.html` (UI mockup). No code, no `.planning/` project yet.
- The spec's "Build phases" section is an unrendered embed ("6 phases, 1 gate"); phase contents are not in the repo.
- `async-nats` has a `websockets` cargo feature (tokio-websockets); whether it is default differs by version, so enable it explicitly. Upstream tests cover `ws://` and `wss://`. ([lib.rs features](https://lib.rs/crates/async-nats/features), [websocket tests](https://docs.rs/crate/async-nats/0.50.0/source/tests/websocket_test.rs))
- NATS WebSocket requires TLS unless `no_tls`; users can be pinned with `allowed_connection_types: ["WEBSOCKET"]`; only binary frames. ([NATS websocket config](https://docs.nats.io/nats-server/configuration/websocket/websocket_conf))
- NATS auth callout (v2.10+) on `$SYS.REQ.USER.AUTH` returns a signed user JWT with per-connection permissions; anything able to read the callout subject can harvest credentials. ([Auth callout](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout))
- TimescaleDB: ROW LEVEL SECURITY is not supported on compressed (columnstore) chunks. ([Timescale compression docs](https://docs.timescale.com/api/latest/compression))
- `yubikey.rs` (iqlusion, PIV) supports RSA and ECDSA P-256/P-384, not Ed25519, and is unaudited. YubiKey PIV Ed25519 needs firmware 5.7+; the OpenPGP applet supports Ed25519 on all YubiKey 5. ([yubikey.rs](https://github.com/iqlusioninc/yubikey.rs), [SSL.com on fw 5.7.4](https://www.ssl.com/no/blogger/yubikey-firmware-5-7-4-legger-til-st%C3%B8tte-for-3072-bit-RSA-kodesigneringsn%C3%B8kler/))
- `cargo-xwin` cross-compiles to `x86_64-pc-windows-msvc` from Linux (clang/lld, ~1.5 GB SDK download; cache it). ([Zondax workflow PR](https://github.com/Zondax/_workflows/pull/94))
- `portable-pty` (from WezTerm) wraps ConPTY (Windows 10 1809+ / Server 2019+). ([portable-pty](https://docs.rs/portable-pty))

### Inferences (verify with spikes)
- The OpenPGP card's EdDSA operation takes a short input, so signers sign a fixed 32-byte digest (`"RMMSIG1" || SHA-256(PAE)`). Verify in the M1 spike.
- `async-nats` `with_auth_callback` exposes the server nonce, so the agent's Ed25519 key can serve directly as its NATS nkey. Verify in M2.
- ConPTY works from a LocalSystem service in session 0. Verify in CI by installing the agent as a service.
- The Windows TPM key provider will not hold Ed25519 keys; TPM-backed agent keys would be P-256.
- SQLCipher drags OpenSSL into the Windows cross-compile; app-level AEAD over SQLite avoids it.

### Assumptions
- One JetStream durable consumer per agent is fine on a single NATS node for a few thousand agents (Dean IT's fleet). Revisit before 10k or clustering.
- Technician console login uses Entra ID OIDC (spec names Entra only for MCP).
- Internal machines run Windows 10 1809+ / Server 2019+.

## Product Definition

- **Target users:** Dean IT technicians (console via the external React app), the MSP owner as key custodian (signing ceremonies), and internal endpoints first; client endpoints only after the parallel-run gate.
- **Primary outcome:** a Windows agent that enrolls with a device-held identity, reports heartbeat and inventory, runs one signed catalog action end to end, opens a technician-co-signed remote shell, and updates itself safely — all under a trust chain where a compromised server cannot run arbitrary code.
- **Value proposition:** Kaseya-proof by construction: every executable thing on an endpoint traces to an offline root key and a YubiKey touch, or (for shells) to a technician's own hardware key.
- **Non-goals (this repo / phase 1):** the web UI; AI gateway, MCP server, autonomy gate, shadow mode; policy engine and compound conditions (only a signed policy stub carrying capability groups); remote desktop and file transfer; patching; Linux and macOS agents (Linux `Platform` exists for tests only); Authenticode/notarization; PSA integration; n8n.

## Recommended Approach

**Approach B — balanced** (chosen):

- **Envelopes:** DSSE-style wrapper around deterministic-CBOR payloads (RFC 8949 §4.2); strict decode (re-encode and byte-compare); signatures over `"RMMSIG1" || SHA-256(PAE(type, payload))`; `alg` field per signature; threshold counting of distinct, unrevoked, role-holding keys (1-of-1 now, 2-of-N later by manifest change).
- **Trust:** a TUF-inspired, root-signed `TrustManifest` (root keys, certs with `roles[]`, thresholds, revoked keys, console RP ID/origins, capability ceiling) plus a catalog-signed `ArtifactRevocations` list with expiry. Monotonic `seq` rollback protection; fail closed when revocations go stale.
- **YubiKey:** OpenPGP applet Ed25519 via the `openpgp-card` crates; raw Ed25519 over our envelope digest (no GPG packet format). Two separate signing keys (daily + backup), each certified by root.
- **Shell:** technician co-sign. The grant is a WebAuthn challenge; the agent verifies the assertion against a YubiKey-signed `TechnicianList`. The server alone cannot open a shell.
- **NATS auth:** a Rust auth-callout service; agent proves possession of its device key against the server nonce; scoped 1-hour user JWT, WebSocket only.
- **Agent key:** Ed25519 wrapped with DPAPI (SYSTEM user scope) behind a `KeyStore` trait; TPM P-256 later.
- **Metrics:** Timescale hypertable in a private schema with compression, no RLS, no grants; read only through scoped `security_barrier` views.
- **Local store:** SQLite with app-level AEAD.
- **Forward compatibility with approach C:** `alg` fields, `KeyStore` trait, and a reserved `e2e_pubkey` in the shell grant.

## Alternatives Considered

| Approach | Strengths | Tradeoffs | Decision |
| --- | --- | --- | --- |
| A. Conservative: JSON/JCS envelopes, static per-agent NATS JWTs, server-only shell grant, uncompressed metrics | Fewest moving parts; human-readable payloads | Breaks the co-sign and auth-callout decisions; JCS number canonicalization is fragile; static JWTs hard to revoke; metrics storage grows fast | Rejected |
| **B. Balanced (above)** | Meets every non-negotiable and decision; avoids risky toolchain deps; crypto-agile; upgrade path to C | More trust code to write; RLS on metrics via views, not native policies | **Chosen** |
| B + E2E-encrypted shell in phase 1 | Compromised server can't inject keystrokes | Server-side recording becomes much harder | Deferred (field reserved) |
| C. Ambitious: full TUF with online timestamp role, COSE_Sign1, TPM keys day 1, E2E shell, transparency log | Strongest against server compromise and disk cloning | +2–3 months; still needs a non-TPM path for VMs | Rejected for phase 1; items queued as Later |
| Signing via PIV Ed25519 (fw 5.7+) | Standard PIV slot | Needs new keys, no Rust crate support (raw APDU or PKCS#11) | Fallback if OpenPGP spike fails |
| Signing via PIV ECDSA P-256 | Works with `yubikey.rs` today | Mixed algorithms; unaudited crate | Rejected |
| NATS operator-mode JWTs / mTLS client certs | No callout service / standard PKI | Slow revocation / CA lifecycle plus TLS termination at Nginx | Rejected |
| Windows CI native-only or cross-only | Simpler | Slow and costly / Windows tests never run | Rejected; use both |

## Feature Scope

### MVP (phase 1)
- [ ] Workspace skeleton, toolchain pin, lints, cargo-deny layering, compose dev env, CI green
- [ ] Trust core: CBOR codec, envelopes, certs, manifest, revocations, commands, technician list, WebAuthn verification, golden vectors, fuzzing
- [ ] `rmm-sign` CLI: file backend (root), OpenPGP-card backend (YubiKey, touch), readable diff before signing; root ceremony runbook
- [ ] Enrollment: tokens, `/v1/enroll`, DPAPI KeyStore, hw fingerprint + reattach/clone rules
- [ ] NATS auth callout (`authd`), scoped JWTs, WSS through Nginx on 443
- [ ] Heartbeat, inventory (typed columns + JSONB + `device_event` diffs), metrics ingest into compressed hypertable behind scoped views
- [ ] Encrypted local store: offline queue, replay cache, trust and policy cache
- [ ] Signed commands via per-agent JetStream consumers; executor pipeline (pre-check, snapshot, execute, verify, rollback); signed results; `action_run`, `audit_event`
- [ ] First catalog action: restart print spooler and clear its queue (blocks `service.*`, `files.quarantine/restore`)
- [ ] Remote shell: WebAuthn registration, technician-list signing, co-signed grant, ConPTY as SYSTEM, relay with backpressure, asciicast recording, session-helper "IT is connected" indicator
- [ ] Watchdog + A/B signed updater with health-check rollback and downgrade protection
- [ ] WiX MSI with `ENROLL_TOKEN` property (unsigned; Authenticode later)
- [ ] OpenAPI spec generated by `utoipa` and published as a CI artifact

### Later
- [ ] TPM-backed P-256 agent keys; E2E-encrypted shell (`e2e_pubkey`)
- [ ] Policy engine (compile, sign, push), compound conditions, reconciler
- [ ] Rest of the first catalog slice; `script.run` signed scripts
- [ ] AI gateway, shadow mode, autonomy gate, MCP server
- [ ] File transfer, remote desktop (WebRTC, coturn)
- [ ] Linux then macOS agents; .deb/.rpm/.pkg; macOS CI runner
- [ ] Authenticode via Azure Artifact Signing; AV/MDE CI stage
- [ ] Out-of-band revocation mirror; transparency log; full TUF timestamp role

## Experience / Workflow

1. **Key ceremony (once):** generate the root offline on an air-gapped machine; age-encrypted copies on two USB sticks in the safe. Generate signing keys on the daily and backup YubiKeys (OpenPGP signature slot, Ed25519, touch `fixed`). Root certifies both plus the server command key; root signs the first `TrustManifest`.
2. **Enroll a device:** an admin creates an enrollment token (client + site, expiry, max uses, reattach allowed?). The installer runs `msiexec /i agent.msi ENROLL_TOKEN=...`. The agent generates its key, enrolls over HTTPS, receives the trust bundle, connects to NATS over WSS 443, and starts heartbeat and inventory.
3. **Publish an action definition:** the GUI prepares a definition and shows a diff; the technician runs `rmm-sign definition <file>` with the YubiKey (touch); the signature is uploaded. The server can now invoke it but cannot alter it.
4. **Run an action:** the technician clicks; the API signs a `Command{Invoke{definition, params}}` with the command key; JetStream delivers it (even if the agent was offline, within TTL); the agent verifies the chain, runs pre-check, snapshot, execute, verify, rollback-on-failure, and returns a signed result.
5. **Open a shell:** the technician clicks Open shell, and the browser runs a WebAuthn ceremony over the grant hash with the technician's hardware key. The API wraps grant + assertion in a signed `ShellOpen`. The agent verifies both signatures and the technician list, spawns ConPTY, and shows "IT is connected" via the session helper. The session is recorded.
6. **Onboard a technician:** register a WebAuthn credential (hardware AAGUID allowlist), then `rmm-sign techlist` (diff, touch) publishes the new `TechnicianList`.
7. **Release an update:** a tag builds the MSI and binaries on the Windows runner plus an unsigned `ReleaseManifest`; the owner signs it with `rmm-sign`; agents fetch the artifact by hash over HTTPS; the watchdog swaps the A/B slot and rolls back if the health check fails.

## Technical Direction

### Workspace layout

```
crates/
  rmm-proto       wire types, deterministic CBOR codec, IDs, NATS subject builders, IPC messages
  rmm-trust       verification: envelopes, cert chain, manifest, revocation, commands, techlist,
                  WebAuthn assertions; pure fns (clock + replay state injected); feature "sign"
  rmm-recipe      action-definition schema, param validation, static recipe validator
                  (no loops, bounded retries, known blocks, capability groups), policy schema
  rmm-platform    Platform trait + windows.rs / linux.rs / macos.rs: inventory, metrics, services,
                  PTY (portable-pty), KeyStore (DPAPI), pipe peer verification; only crate allowing unsafe
  rmm-agent-core  transport, executor + building blocks, collectors, local store, shell, reconciler stub
  rmm-agent       bin: Windows service entry (windows-service), `enroll`, `run`, `diag`
  rmm-watchdog    bin: sync std, no tokio, no network; depends only on proto + trust + windows
  rmm-session     bin: session helper (phase 1: "IT is connected" indicator + pipe client)
  rmm-db          sqlx pool, migrations/, `Scoped` transaction wrapper, roles
  rmm-api         axum + utoipa routes, WebAuthn (webauthn-rs), shell relay to browser WebSocket
  rmm-server      bin: subcommands api | ingest | authd | migrate (separate processes, separate DB roles)
  rmm-sign        bin: openpgp-card + card-backend-pcsc; file-key backend for root
xtask/            msi, release-manifest draft, test vectors, openapi export
```

- Dependency direction: `proto ← trust ← recipe`; `platform` stands alone; `agent-core` uses all four; server crates never depend on `platform` or `agent-core`. Enforce with cargo-deny `bans` and a `cargo tree` CI check.
- The agent builds `rmm-trust` without the `sign` feature, so no signing code ships on endpoints.
- Must compile for `x86_64-pc-windows-msvc`: proto, trust, recipe, platform, agent-core, agent, watchdog, session, sign. `aarch64-pc-windows-msvc`: build check only.

### Signing chain

| Key | Holder | Roles | Lifetime |
| --- | --- | --- | --- |
| Root (×1, threshold-ready) | Offline, air-gapped generation; age-encrypted copies in the safe | `root`: certs, key revocations, trust manifest | ~10 y; yearly ceremony |
| Signing key (daily YubiKey) | OpenPGP signature slot, Ed25519, touch fixed, PIN per signature | `catalog`, `release`, `techlist`, `artifact-revoke` | Cert 2 y |
| Signing key (backup YubiKey) | Separate key on its own card, also root-certified | Same | Cert 2 y |
| Server command key | Ed25519 file on API host (HSM later) | `command`, `policy` | Cert 90 d, rotated |
| Agent key | Device, DPAPI-wrapped | Signs results and NATS connection proofs | Until re-enrolled |

- **Envelope:** `{v:1, type, payload: bstr, sigs:[{key_id, alg, sig}]}`; message = `"RMMSIG1" || SHA-256(PAE(type, payload))`. Verify received bytes; never re-serialize.
- **TrustManifest:** `{seq, issued_at, expires_at ≤ 13 mo, root_keys, root_threshold, certs, thresholds, revoked_keys, console_rp_id, console_origins, capability_ceiling}`. Root rotation requires the threshold of both old and new roots.
- **ArtifactRevocations:** `{seq, expires_at 45 d, revoked_hashes}`, re-signed monthly. When stale, the agent refuses everything except trust updates and read-only diagnostics and reports `trust_stale`.
- **Rollback protection:** highest `seq` per document stored in the local store and an ACL-protected HKLM value.
- **Command:** `{cmd_id (16 B nonce), agent_id, client_id, issued_at, expires_at, policy_hash, body: Invoke{definition, params} | ShellOpen{grant, assertion} | TrustUpdate | Collect}`. Default TTL 10 min; definitions may allow `max_queue_ttl` up to 7 d; ±5 min skew.
- **Agent verification order:** chain + role + not revoked → agent/client binding → time window → replay cache (SQLite, pruned after expiry + skew) → inline definition catalog-signed, not revoked, `min_agent_version` ok → param schema → capability group allowed by signed policy **and** root-signed `capability_ceiling`.
- **Shell co-sign:**
  - The API builds `ShellGrant{grant_id, agent_id, client_id, tech_id, cred_id, issued_at, open_by +60 s, max_duration ≤ 4 h, shell, record:true, e2e_pubkey:null}`.
  - The WebAuthn challenge is `SHA-256("RMMSHELL1" || grant_bytes)`, with user verification required.
  - The agent checks:
    - `clientDataJSON` type, challenge and origin (origin must be in the manifest);
    - the rpIdHash;
    - the UP and UV flags;
    - the signature over `authData || SHA-256(clientDataJSON)` (ES256 via `p256`, or EdDSA);
    - that the credential is in the current techlist-role-signed `TechnicianList`, with this client in the technician's scope.
- **Bootstrap:** the root public keys and threshold are compiled in. Enrollment delivers the manifest, revocations, technician list and command cert. Updates arrive via `TrustUpdate` or `svc.trust.latest` on connect, and both paths are verified the same way.

### Enrollment and identity
- Token `rmmenr_` + 160-bit base32, scoped to client and site, with an expiry, a max use count and `allow_reattach`. Only its SHA-256 is stored. It is passed as an MSI property and never written to disk.
- The agent key is Ed25519 from OsRng, wrapped with DPAPI in the SYSTEM user scope (**not** `CRYPTPROTECT_LOCAL_MACHINE`), in a SYSTEM-only ACL file. Threat model: local admin = device compromise.
- `POST /v1/enroll {token, agent_pubkey, hw_facts, os, version, ts}` plus a proof-of-possession signature, rate-limited at Nginx. It returns `{agent_id, device_id, client_id, nats_url, trust_bundle}`.
- Fingerprint = SHA-256 of normalized SMBIOS UUID + system serial + baseboard serial, with the raw parts stored. Junk values (zero/FF UUIDs, "To be filled by O.E.M.", "Default string", …) make it weak.

| Situation | Action |
| --- | --- |
| Strong match, same client, old agent unseen > 24 h, token allows reattach | Reattach; old agent `superseded`; `device_event: agent_reinstalled` |
| Strong match, old agent still alive | New device `pending_review`, `possible_clone_of`; restricted until merged or split |
| Match in a different client | Never cross clients; new device, flagged |
| Weak fingerprint | Never auto-reattach |
| Changed strong fingerprint on an existing agent, or concurrent connections with one key | `suspect_clone`; deny; require re-enrollment |

- **authd:**
  - The agent connects with its key as an nkey, signs the nonce, and sends a signed `{agent_id, fp, version, ts}` in `auth_token`.
  - authd checks `status=active`, that the client is active, and the fingerprint. It returns a 1-hour user JWT with `allowed_connection_types:[WEBSOCKET]` and these permissions:
    - pub `telemetry.<c>.<a>.>`, `result.<c>.<a>`, `shell.<a>.*.out`, `svc.trust.latest`, `$JS.API.CONSUMER.MSG.NEXT.CMD.agent_<a>`, `$JS.ACK.CMD.agent_<a>.>`;
    - sub `_INBOX_<a>.>`, `shell.<a>.*.in`, `shell.<a>.*.ctl`.
  - Only authd may read `$SYS.REQ.USER.AUTH`, and callout requests are xkey-encrypted.
  - The API and ingest services are static `auth_users`.
  - Revocation kicks the connection through `$SYS`.

### NATS / JetStream (spec's `tenant` renamed to `client`)

| Stream / subject | Purpose | Config |
| --- | --- | --- |
| `CMD`: `agent.*.cmd` | Signed commands, offline delivery | File storage, max_age 7 d, dedupe on `Nats-Msg-Id = cmd_id`. One durable pull consumer per agent, created by the server at enrollment. The agent acks once the command is persisted locally |
| `TELEM`: `telemetry.<c>.<a>.{hb,inv,metric,event}` | Heartbeat, inventory, metrics, events | max_age 3 d. Heartbeat uses plain publish; the rest use JetStream publish. Consumer `ingest` pulls batches of 500 |
| `RESULT`: `result.<c>.<a>` | Agent-signed action results | max_age 14 d; consumer `results` |
| Core NATS: `shell.<a>.<sid>.{in,out,ctl}` | Live shell | Not persisted |
| `svc.trust.latest` | Trust refresh on connect | Request/reply |

- Update artifacts are served over HTTPS (`GET /v1/artifacts/<sha256>`). They are signed, so the channel does not need to be trusted.
- **Offline:** commands wait in `CMD` within their TTL. Telemetry and results queue in SQLite and drain on reconnect: oldest first, results before metrics. IDs are UUIDv7, deduped in the stream (2 h window) and in the DB (unique `event_id`).
- **Shell backpressure:**
  - Output chunks are up to 16 KiB or 20 ms of output, each with a sequence number.
  - The relay returns `ctl{ack, window}`, and the agent keeps at most 256 KiB in flight. When credit runs out it stops reading the PTY, so ConPTY blocks the child process.
  - The relay pings every 15 s. The agent tears the session down after 45 s without a ping or at `max_duration`.
  - Recordings are asciicast v2.

### Database and RLS
- `tenant.*` tables: `client_id NOT NULL`, ENABLE + FORCE RLS, policy `client_id = ANY(rmm.scope())` from `current_setting('rmm.client_ids')`.
- `msp.*` (users, technicians, roles, trust artifacts, `action_definition`): no `client_id`, a **documented exception** with narrow grants.
- A `Scoped` transaction wrapper always runs `BEGIN` and then `set_config('rmm.client_ids', $1, true)` plus `rmm.actor`. Clippy `disallowed_methods` bans the raw pool. RLS is defense in depth against query bugs, not against a compromised API.
- Roles:

  | Role | Purpose / grants |
  | --- | --- |
  | `rmm_owner` | Owns tables; used only by migrate |
  | `rmm_api` | NOBYPASSRLS; no UPDATE/DELETE on `audit_event` or `device_event` (a trigger also blocks them) |
  | `rmm_ingest` | INSERT only on telemetry and metrics |
  | `rmm_authd` | SELECT on agent/device status |
  | `rmm_ai_ro` | Read-only AI role (later) |

- **Timescale workaround:**
  - `ts_private.metrics` is a hypertable compressed with `segmentby = client_id, device_id`, with no RLS and no grants to the API or AI roles.
  - It is read only through `tenant.metrics_v` (security_barrier, owner-executed, filtered by `client_id = ANY(rmm.scope())`). Continuous aggregates get the same treatment.
  - Ingest takes `client_id` from the JWT-authenticated subject, never from the payload.
  - A CI test checks that `rmm_api` is denied on `ts_private` and that client A sees zero client-B rows, compressed chunks included.
- Migrations are sqlx, forward-only, in `crates/rmm-db/migrations`, run by `rmm-server migrate`. The `.sqlx` offline data is committed and checked by `cargo sqlx prepare --check`.

### Dev environment (docker compose)
- `timescale/timescaledb:latest-pg17`.
- `nats:2.11`: JetStream on; WebSocket on `:8080` with `no_tls` on the internal network only; accounts RMM, AUTH, SYS; an auth_callout block.
- `nginx`: TLS 443 with an mkcert dev CA. `/nats` is a WebSocket upgrade (read timeout 1 h, buffering off); `/api` and `/v1/enroll` go to the API.
- `api`, `ingest`, `authd`, and a one-shot `migrate`.
- Debug-only agent setting `extra_ca` to trust the dev CA. A Win11 / Server 2022 VM outside compose serves as the real target.
- Developer speed: the mold linker, cargo-watch, sqlx offline mode.

### CI (GitHub Actions)

| Job | Runner | Contents |
| --- | --- | --- |
| `lint` | ubuntu | fmt, clippy `-D warnings`, cargo-deny (licenses, bans, layering), `sqlx prepare --check`, utoipa OpenAPI export diff |
| `windows-cross` | ubuntu | Cached cargo-xwin SDK; `cargo xwin clippy` + `build` for agent, watchdog, session, sign (x86_64-msvc); build check for aarch64 |
| `test-linux` | ubuntu + service containers | Unit tests, golden vectors, fuzz smoke, RLS suite, authd tests, agent-core end-to-end with the Linux `Platform` against real NATS |
| `test-windows` | windows-latest | Tests for DPAPI, SCM, named pipes and ConPTY; installs the agent as a LocalSystem service (session-0 shell); spooler action end to end |
| `release` (tag) | windows-latest | Native release build, WiX MSI, unsigned ReleaseManifest draft for human signing with `rmm-sign` |

### Phase 1 milestones

1. **M0 Skeleton.** Workspace, toolchain pin, lints, compose, CI.
   - *Accept:* `cargo xwin build` produces `rmm-agent.exe`; compose is healthy; all CI jobs are green.
2. **M1 Trust core.** Codec, envelopes, certs, manifest, revocations, commands, techlist, WebAuthn verify; `rmm-sign` with file and card backends; ceremony runbook.
   - *Accept:* golden vectors pass both directions; a YubiKey signature (with touch) verifies; fuzz and property tests reject non-canonical input; the ceremony dry run is done.
3. **M2 Enrollment + NATS auth.** Tokens, `/v1/enroll`, DPAPI KeyStore, authd, scoped JWTs, WSS through Nginx.
   - *Accept:* the Windows VM enrolls and connects; publishing to another agent's subject is denied; a revoked agent is refused and kicked; a reinstall reattaches; the clone scenario is flagged.
4. **M3 Telemetry.** Heartbeat, inventory with `device_event` diffs, compressed metrics behind views, ingest.
   - *Accept:* the two-client RLS suite passes, compressed chunks included; a RAM change writes a `device_event`.
5. **M4 Local store + offline.** AEAD SQLite queue, replay cache, trust and policy cache.
   - *Accept:* after 1 h offline, all data arrives with no duplicates; a lower `seq` is rejected after a restart.
6. **M5 Commands + first action.** Command signing, per-agent consumers, executor pipeline, `service.*` and `files.quarantine/restore` blocks, signed results, `action_run`, `audit_event`.
   - *Accept:* the spooler restart with queue clear works end to end; a forced verify failure rolls back; expired, replayed, tampered, revoked and unsigned-definition commands are each rejected by a test.
7. **M6 Shell with co-sign.** WebAuthn registration, techlist signing, grant, ConPTY as SYSTEM, relay, backpressure, recording, session-helper indicator.
   - *Accept:* no shell opens without a valid assertion; a removed technician is locked out after the next sync; printing a 1 GB file keeps agent memory under 50 MB; `max_duration` is enforced.
8. **M7 Watchdog + A/B updater.**
   - *Accept:* an update applies; a failed health check rolls back within 5 min; a downgrade is rejected; a tampered artifact is rejected; a killed core restarts within 10 s.
9. **M8 MSI** (parallel from M2). Installs both services, takes the `ENROLL_TOKEN` property, uninstalls cleanly.
   - *Accept:* a silent install enrolls on Win10, Win11, Server 2019 and Server 2022.

### Spec gaps and risky assumptions (ranked)

1. **Remote shell is arbitrary execution:** resolved by technician co-sign. A residual risk remains: a compromised server can inject keystrokes into an open session. Mitigation: short sessions, a visible indicator, E2E encryption later.
2. **The effective policy is signed by the server key**, so a compromised server could widen capability groups. Mitigation: a root-signed `capability_ceiling` that policy can only narrow.
3. **The server can withhold revocation updates.** Mitigation: expiry plus fail-closed; an optional out-of-band mirror (open question).
4. **Timescale compression breaks RLS:** private schema plus scoped views.
5. **RLS depends on a scope the app sets itself:** state in the threat model that it is defense in depth.
6. **The build-phases embed is unrendered:** phase 1 is defined here; the six phases are needed for the roadmap.
7. **Console login is unspecified:** resolved: Entra ID OIDC + PKCE with MFA through Conditional Access, plus WebAuthn for shells.
8. **VM clones with duplicate SMBIOS:** the fingerprint rules above now; TPM keys later.
9. **Encrypted SQLite:** app-level AEAD instead of SQLCipher (metadata stays readable).
10. **Command TTL vs offline delivery:** 10 min default, `max_queue_ttl` per definition.
11. **The "IT is connected" indicator needs the session helper:** a minimal helper in M6.
12. **OpenPGP card EdDSA input size and `openpgp-card` maturity:** week-1 spike, with PIV Ed25519 (fw 5.7+) as the fallback.
13. **Clock skew:** ±5 min tolerance, skew reported in the heartbeat.
14. **MSI repair/upgrade can clobber the A/B slots:** the MSI owns only the watchdog and a bootstrap slot.
15. **No Authenticode in phase 1:** Defender/SmartScreen may flag the agent; use an MDE indicator on internal machines.
16. **Retention and privacy of session recordings:** resolved: 1 year, audited access.
17. **JetStream consumer per agent at scale:** revisit before 10k agents.
18. **Spec path mismatch** (`docs/spec.md` vs the root file): move the spec to `docs/spec.md` in M0.

## Open Questions

Resolved in discussion (2026-10-31):
- **Console login:** Entra ID OIDC + PKCE, MFA via Conditional Access (API validates Entra tokens; WebAuthn stays separate for shell co-sign).
- **Revocation mirror:** deferred; `TrustManifest` reserves a `revocation_mirrors[]` field. Phase 1 relies on expiry + fail-closed.
- **Session recordings:** retained 1 year, then purged by a scheduled job; access is audited.
- **Shell authenticators:** hardware only. `rmm-sign techlist` enforces an AAGUID allowlist (YubiKey 5 series) and rejects synced passkeys.

| Question | Resolution path |
| --- | --- |
| Paste the six build phases from the spec's embed | User provides; feeds ROADMAP.md at `/triad:start` |
| App-level AEAD instead of SQLCipher? | Default yes; revisit if a compliance requirement demands full-file encryption |
| Where the root key lives and who attends ceremonies | Owner decision before M1 dry run |
| E2E-encrypted shell after phase 1? | Confirmed deferred; field reserved |
| ConPTY under LocalSystem in session 0 | Spike in M0/M1 via `test-windows` |
| OpenPGP card EdDSA digest signing via `openpgp-card` | Week-1 spike; fallback PIV Ed25519 |
| async-nats nonce access for nkey auth with a callout | M2 spike |

## Start Input

Greenfield Rust Cargo workspace (`ace027/custom-rmm`) for a security-first RMM backend; the web UI lives elsewhere, so this repo exports an OpenAPI spec via utoipa. Approach B (balanced):

- **Crates:** `rmm-proto`, `rmm-trust`, `rmm-recipe`, `rmm-platform`, `rmm-agent-core`, `rmm-agent`, `rmm-watchdog`, `rmm-session`, `rmm-db`, `rmm-api`, `rmm-server` (api|ingest|authd|migrate), `rmm-sign`.
- **Trust:** deterministic-CBOR DSSE-style envelopes; offline Ed25519 root plus a root-signed TrustManifest with multi-sig thresholds; YubiKey OpenPGP Ed25519 signing keys (daily + backup) for catalog/release/techlist/revocations; server command key that can only invoke signed definitions; expiring signed revocation list with fail-closed and seq rollback protection.
- **Shell:** technician-co-signed WebAuthn grants verified on the agent (hardware authenticators only, AAGUID allowlist); recordings kept 1 year.
- **Auth:** Entra ID OIDC + PKCE for console/API login; revocation mirror deferred with a reserved manifest field.
- **Agent:** Ed25519 key wrapped with DPAPI; NATS over WSS 443 with a Rust auth-callout service issuing scoped JWTs; per-agent JetStream command consumers.
- **Data:** Postgres + TimescaleDB with RLS on `tenant.*`, and metrics in a private compressed hypertable behind scoped views.
- **Dev and CI:** docker compose (Timescale, NATS, Nginx TLS); CI with lint, cargo-xwin Windows cross-compile, Linux tests and native Windows tests.
- **Phase 1:** M0 skeleton → M1 trust core + `rmm-sign` → M2 enrollment + NATS auth → M3 heartbeat/inventory/metrics → M4 encrypted local store/offline → M5 signed commands + print-spooler action → M6 co-signed remote shell → M7 watchdog + A/B updater → M8 MSI.
- **Non-goals for phase 1:** AI, MCP, policy engine, remote desktop, Linux/macOS agents, Authenticode, n8n.
- **Constraints:** no AI on endpoints; no obfuscation or EncodedCommand; outbound-only agent; `client_id` on every tenant table.
