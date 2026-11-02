# Phase 7: Co-signed remote shell -- Context

## Phase Goal
Technicians open a recorded ConPTY shell only with a hardware-key WebAuthn co-signature that the agent verifies against the YubiKey-signed TechnicianList.

## Requirements Covered
- REQ-18
- REQ-19

## What Already Exists (from prior phases)
- rmm-trust: ShellGrant, TechnicianList/Technician/Credential (aaguid, cose_pubkey, alg), CommandBody::ShellOpen{grant, assertion}, webauthn.rs (shell_challenge with RMMSHELL1 prefix, Assertion, Expected{challenge, rp_id, origins, require_uv}, verify_assertion, parse_cose_key), TrustManifest.console_rp_id/console_origins
- rmm-sign: DocType::Techlist signing (no AAGUID allowlist yet)
- rmm-agent-core: commands.rs verify() and dispatch (only Invoke handled; ShellOpen rejected), TrustStore holds techlist (store.rs techlist()), replay cache, signed results, dedicated-inbox JetStream intake
- rmm-server natsjwt.rs already grants agents pub shell.<a>.*.out and sub shell.<a>.*.in / shell.<a>.*.ctl; static api NATS user has no shell grants yet (deploy/nats)
- rmm-api: axum + utoipa, Claims/Admin/RequireRole extractors, AppState{pool, authenticator, nats, roots, nats_public_url, command_key}, actions.rs signs and publishes Command envelopes to CMD
- rmm-db: migrations 0001-0005, Scoped tx with RLS, msp.* exception tables
- rmm-session crate: stub main.rs
- CI: lint, windows-cross, test-linux (service containers, e2e scripts), test-windows; scripts/e2e-actions.sh pattern with dev-trust.sh

## Key Design Decisions
- PTY: portable-pty 0.9 behind an rmm-platform Pty trait (ConPTY on Windows, openpty on unix for dev/e2e); FakePty for tests
- Shell allowlist on the agent: grant.shell must be 'cmd' (%SystemRoot%\System32\cmd.exe), 'powershell' (%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo, never -EncodedCommand) on Windows, or 'sh' (/bin/sh) on unix; anything else is rejected
- Wire format on core NATS shell.<a>.<sid>.{in,out,ctl}, sid = lowercase hex of grant_id, canonical CBOR types in rmm-proto::shell: ShellOut{seq,data}|Exit{code}|Closed{reason}; ShellIn{data}|Resize{cols,rows}; ShellCtl Ack{seq}|Window{bytes}|Ping|Close
- Backpressure: output chunks <= 16 KiB or 20 ms; agent keeps <= 256 KiB unacked in flight and stops reading the PTY when out of credit
- Liveness: relay pings every 15 s; agent tears down after 45 s with no ping, and at max_duration (<= 14400 s, checked by API and agent)
- Agent ShellOpen checks, in order after the existing command checks: grant decodes; grant.agent_id/client_id match the agent and the command; now <= open_by + 30 s; max_duration <= 14400; shell in allowlist; grant_id not seen (replay cache); tech in current TechnicianList, in_scope(client_id), cred_id among tech creds; verify_assertion with challenge = shell_challenge(grant bytes), rp_id/origins from the manifest, require_uv true; at most 2 concurrent sessions
- A TechnicianList update that removes a technician or credential closes that technician's open sessions on the agent (Closed{reason:'tech_removed'})
- Hardware-only: API registration requires packed attestation with an x5c chain to a configured attestation root (RMM_WEBAUTHN_ATTESTATION_ROOTS PEM) and an AAGUID in RMM_WEBAUTHN_AAGUIDS; rmm-sign techlist rejects any credential whose AAGUID is not in its compiled YubiKey 5 allowlist plus repeatable --allow-aaguid HEX; the agent trusts the signed techlist
- Browser relay auth: the open endpoint returns a single-use ws ticket (32 random bytes, hash stored, 60 s expiry) passed as ?ticket= on the WebSocket
- Recordings: asciicast v2 written by the API relay (output 'o' and input 'i' events) to RMM_RECORDING_DIR/<client_id>/<sid>.cast with a tenant.shell_session row (sha256, bytes); a daily task deletes recordings and rows older than 365 days
- Indicator: agent runs an indicator server (Windows named pipe \\.\pipe\rmm-session-indicator, SYSTEM write, interactive users read; unix socket path from RMM_INDICATOR_SOCKET) sending JSON lines {state:'connected'|'idle', tech}; rmm-session shows a tray icon with tooltip 'IT is connected' on Windows and prints the line on unix
- Residual risk accepted (design doc): a compromised server can inject keystrokes into an open session; mitigated by short sessions, the indicator, and E2E later (e2e_pubkey stays null)
- Architecture proposals and board quick-assess skipped in the autonomous run (board had too few scoring members; spec not triggered)

## Plan Structure
- **Plan 07-01 (Wave 1)**: Shell wire types, PTY abstraction and session indicator -- Add the shell wire protocol to rmm-proto, a Pty trait with ConPTY/openpty and fake implementations to rmm-platform, and the session indicator server plus the rmm-session helper.
- **Plan 07-02 (Wave 1)**: Hardware-only WebAuthn registration, shell tables and techlist allowlist -- Add migration 0006 for technicians, WebAuthn credentials, challenges, shell sessions and ws tickets; API registration that only accepts hardware authenticators via packed attestation and an AAGUID allowlist; a techlist draft export; and an AAGUID allowlist in rmm-sign techlist.
- **Plan 07-03 (Wave 2)**: Agent shell: co-sign verification, ConPTY session pump and lockout -- Handle ShellOpen on the agent: verify the grant and the technician's WebAuthn assertion against the signed TechnicianList, run the PTY session over NATS with credit backpressure, liveness and max_duration, drive the indicator, and lock out removed technicians.
- **Plan 07-04 (Wave 3)**: Grant API, browser relay, recordings and end-to-end shell -- Add the grant and open endpoints, the browser WebSocket relay over NATS with credit acks and pings, asciicast recording with one-year retention, a fake hardware authenticator for dev, and an end-to-end shell script in CI.
