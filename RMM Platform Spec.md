# RMM Platform Spec

Oct 30, 2026 · @Dyllan

## Overview

Build an AI-native, white-label RMM that replaces NinjaOne for Dean IT Services first and could later run as a separate instance for Silicon Plains. It is designed around AI from day one: a desired-state policy engine, a signed action catalog, and graduated AI autonomy with human approval.

**Goals**

- Replace NinjaOne for Dean IT's fleet, after running in parallel on internal machines for several months.
- Beat existing RMMs on safety and AI: every action reversible where possible, every AI decision explained and audited.
- Stay neutral: no company names in code; branding and signing identity come from deployment config.

**Principles**

- API-first: the web GUI, MCP, and integrations all use the same public API.
- AI proposes; humans approve. AI never holds signing keys.
- The agent executes; the server reasons. No AI runs on endpoints.
- A compromised server must not be able to run arbitrary code on endpoints (the Kaseya lesson).

**Deployment model**

- One instance per MSP: its own database, NATS, keys, and branding. Multi-tenancy covers clients within one MSP, not multiple MSPs.
- Build for Dean IT; architect so a second instance needs config, not code changes.
- Before Silicon Plains uses it, get IP ownership confirmed in writing (check the employment agreement).

## System architecture

Agents connect outbound only, over one long-lived TLS connection to NATS on port 443. The browser never talks to agents directly: it calls the API, which enforces auth, RBAC, and audit, then publishes to NATS.

&#91;embedded content: system architecture · control path and media path\]

| Component | Technology | Role |
| --- | --- | --- |
| Agent | Rust (tokio, async-nats, sysinfo, windows-rs) | Runs on endpoints; executes signed actions, reconciles policy |
| API | Rust (axum, sqlx, async-nats), sharing a crate with the agent (Go was used in the earlier prototype) | Auth, RBAC, audit, policy compile, autonomy gate |
| Messaging | NATS + JetStream over WebSocket | Commands to agents, telemetry back; durable queue for offline agents |
| Database | PostgreSQL + TimescaleDB | Core data with row-level security; metrics hypertables |
| AI gateway | Server-side service | All model calls, routing, redaction, logging |
| MCP server | Streamable HTTP adapter over the API | Read, propose, and execute tools for Claude and others |
| Remote media | WebRTC + self-hosted coturn | Remote desktop video; NATS carries only signaling |
| Web GUI | React + TypeScript + shadcn/ui | Technician console |
| Infra | Docker Compose, Nginx, Ubuntu 24.04 LTS | Replicable per-MSP deployment |

**NATS subjects**

- `agent.<id>.cmd`: signed commands to one agent.
- `telemetry.<tenant>.<id>`: metrics, heartbeats, inventory, and results.
- Live dashboard updates reach the browser over a WebSocket from the API.

**Server in Rust**: one Cargo workspace split into crates (shared types and signature checks, API, policy compiler, autonomy gate), so the agent and server share one implementation of the envelope, recipe validator, and policy schema. Development speed: use the mold linker, `cargo-watch`, sqlx offline mode, and `utoipa` to generate an OpenAPI spec for the React client.

## Agent

The agent is Rust, cross-platform (Windows, Linux, macOS; x86\_64 and arm64), and built from scratch. Windows ships first, then Linux, then Mac.

**Processes**

1. **Core service** (SYSTEM / root): does all real work. The only privileged component.
2. **Watchdog and updater**: tiny, rarely changes. Restarts the core; applies signed updates into A/B slots and rolls back if health checks fail.
3. **Session helper** (logged-in user, on demand): tray app, user prompts, self-service chat, screen capture. Talks to the core over a named pipe / Unix socket; the core verifies the caller. No elevated rights.

**Core modules** (independent async tasks on internal channels)

| Module | Responsibility |
| --- | --- |
| Transport | NATS connection, reconnect with backoff, message envelope |
| Reconciler | Desired-state loop: check, compare, apply (within autonomy level), report compliance |
| Conditions | Local evaluation of compound conditions, windowed state for durations |
| Executor | Catalog actions through pre-check, snapshot, execute, verify, rollback; signed scripts with timeouts and output caps |
| Collectors | Metrics and inventory behind a per-OS `Platform` trait |
| Local store | Encrypted SQLite: policy cache, offline queue, snapshots, condition state |

**Cross-platform structure**: a platform-agnostic core behind a `Platform` trait, with `windows.rs`, `linux.rs`, and `macos.rs` selected by `#[cfg(target_os)]`. Services via the Windows SCM, systemd, and launchd (`service-manager` crate). Packaging: MSI, .deb/.rpm, .pkg (consider `cargo-dist`). Mac builds need a CI macOS runner.

**Design principles**

- No AI on the endpoint. User chat is relayed to the server; the agent only receives signed commands.
- Verify every command independently: server-signed, with expiry and nonce, checked against the cached signed policy.
- Keep enforcing policy and evaluating conditions offline; queue results and sync on reconnect.
- Generate the agent's private key on the device; store it in DPAPI/TPM (Windows), Keychain (Mac), or a root-only file (Linux).
- Be a good guest: CPU and memory caps, low priority, random jitter on schedules.
- Look like what it is: no packers, obfuscation, or `-EncodedCommand`; never touch LSASS or inject into processes; prefer OS APIs over shelling out.

**Platform gotchas**

- Windows remote desktop needs a helper launched into the user session (`WTSQueryUserToken` + `CreateProcessAsUser`), plus the Winlogon secure desktop for UAC and login screens.
- macOS needs TCC permissions (Screen Recording, Accessibility), granted by the user or a PPPC profile from MDM.
- Linux Wayland requires per-session portal consent; support X11 first.
- Patching is a separate project per OS: Windows Update Agent COM API; apt, dnf, zypper; `softwareupdate`.

## Trust and signing

The agent accepts only what is signed by a chain rooted in an offline key. Even a fully compromised server can only invoke fixes already signed, within their limits.

**Key hierarchy**

- **Root key** (Ed25519, offline in a safe): its public key is compiled into the agent. Signs signing keys and revocations only.
- **Signing key** on a daily YubiKey, plus a backup YubiKey stored with the root. Touch required for every signature. Signs action definitions, agent updates, and high-risk scripts.
- **Server command key**: separate; signs each command (invoke definition X with params), with expiry and nonce. Cannot create definitions.
- **Signed revocation list**: kills a compromised signing key or a bad definition fleet-wide.
- **Multi-signature ready**: the format holds several signatures and a required count; 1 of 1 today, 2 of N possible later.

**Signing workflow**: the GUI prepares a definition and shows a readable diff; a local CLI signs it with the YubiKey; the signature is uploaded. The private key never leaves the YubiKey.

**Building blocks vs definitions**

- The agent ships 30–50 compiled **building blocks**: small, typed, guarded operations (`service.restart`, `files.quarantine`, `pkg.install`, `registry.set` with auto-snapshot).
- **Action definitions** are signed recipes of blocks: parameters, pre-checks, steps, verify, rollback, max autonomy, minimum agent version.
- The recipe language allows sequences, conditions, and bounded retries; no loops, no arbitrary execution.
- Blocks belong to **capability groups** (`files.write`, `pkg`, `registry`); policy decides which groups a device allows.
- `script.run(signed_script_id)` is a block in its own capability group, capped at L1 by default.
- Prefer reversible variants: `files.quarantine` (purged after N days) instead of delete.

**OS code signing and antivirus** (separate from the trust chain above; antivirus never sees YubiKey signatures)

- Windows: Authenticode-sign every binary and the MSI via **Azure Artifact Signing** (\~$10/month, HSM-held key, CI integration). EV no longer grants instant SmartScreen trust.
- macOS: Apple Developer ID + notarization. Linux: GPG-signed packages and repository.
- Keep one publisher identity forever; ship fewer, stable releases; submit each release to Microsoft Security Intelligence before rollout.
- On managed clients, allow the agent with an **MDE certificate indicator**, not folder exclusions. Test ASR rules in the lab ring.
- CI stage: install each build on machines running MDE and other common AV, run the full catalog, and fix behavior or file false positives before release.

## Data model

A flat client → site → device hierarchy, with tags and dynamic groups for everything that cuts across it, and `client_id` on every table so Postgres row-level security enforces scope.

| Entity | Key fields | Notes |
| --- | --- | --- |
| `client` | id, name, psa\_company\_id, ai\_privacy\_tier | Tier: cloud, local-only, or off |
| `site` | id, client\_id, timezone | No arbitrary nesting |
| `device` | id, client\_id, site\_id, hw\_fingerprint, os\_family, typed inventory columns, inventory JSONB | Survives reinstalls and reimages |
| `agent` | id, device\_id, version, credential\_pubkey, last\_seen | The software currently on the device |
| `tag`, `dynamic_group` | name / saved query | Groups recompute as devices change |
| `policy`, `policy_item` | parent\_policy\_id; kind, settings, locked | Templates with inheritance |
| `policy_assignment` | policy\_id, target (group / client / site / device), priority | Targeting is separate from content |
| `device_event` | device\_id, type, before/after, time | Append-only change history |
| `alert`, `incident` | condition, device, grouping | AI groups alerts into incidents |
| `action_definition`, `action_run` | signed recipe; snapshot, result, verification | Feeds trust scores |
| `audit_event` | actor chain, action, target, reasoning, model + prompt version | Append-only |
| `metrics` | TimescaleDB hypertable | Backtesting, baselines, anomalies |

**Rules**

- Device and agent are separate. A hardware fingerprint (SMBIOS UUID + serial) reattaches a reinstalled agent to the same device, keeping its history.
- Commonly queried inventory (OS, RAM, disk, last boot) lives in typed columns so AI-generated SQL is reliable; platform detail goes in JSONB.
- Every inventory change writes a `device_event`, which answers "what changed before this broke?"
- RLS scopes technicians, the AI's read-only role, and MCP tokens to their allowed clients.

## Policy system

Policies declare a desired end state; the agent continuously reconciles toward it and reports drift. NinjaOne-style templates with parent-child inheritance are the authoring layer on top.

**Desired state**

- A policy says what should be true (BitLocker on, Chrome installed, disk alert at 10%), not steps to run.
- Every setting has a check function and an apply function, so every setting is also a compliance check.
- Drift is either fixed (within the autonomy level) or flagged.

**Targeting and stacking**

- What (policy content) is separate from who (targeting). Targets: global, client, site, tag, dynamic group, device.
- Multiple policies per device, ordered by priority. **Additive** items (monitors, scheduled scripts, required software) combine; **single-value** settings (patch window, reboot behavior) take the highest priority; `locked` settings from a higher level always win.
- The server compiles the effective policy, stores it with a version hash, signs it, and pushes it. The agent never resolves inheritance.
- The **effective policy view** shows each setting, its source policy, and conflicts.

**Compound conditions**

- Stored as an expression tree: ALL OF, ANY OF, NONE OF, with durations ("for 10 minutes"), time windows, and dependencies ("don't alert if the device is offline").
- Device-level conditions run on the agent; fleet-level conditions (e.g., 3+ devices offline at one site → one "site down" alert) run on the server.
- **Backtesting** against TimescaleDB history shows how often a condition would have fired before it is saved.
- AI can draft conditions from plain English as JSON trees for human review.

**Policy as code**

- Every change is a versioned draft with a diff.
- Staged rollout: internal lab → pilot ring → everyone, with wait times per stage.
- Auto-pause if compliance drops or alerts spike at any stage; one-click rollback to the previous version.

## Autonomy model

AI acts only through signed catalog actions, at a level set by policy and earned trust. It launches in shadow mode: deciding, logging, and comparing against what technicians did, before touching any machine.

| Level | Behavior |
| --- | --- |
| L0 | Off: AI does nothing for this action |
| L1 | Suggest: AI proposes, a human approves |
| L2 | Act and notify: runs immediately, notifies, undo window |
| L3 | Act silently: runs and logs |

**Effective level** = the lowest of: the policy ceiling (per client, group, or time window), earned trust for that action in that scope, and the action's own maximum. Irreversible actions are permanently capped at L1.

**Trust**: each run's verification result updates a success score per action and scope. Consistent wins produce a promotion *recommendation* that a human approves. Any failure, rollback, or technician override demotes automatically.

**Execution pipeline**

1. Trigger: alert, condition, or user request.
2. Diagnosis: AI picks an action and records its evidence.
3. Gate check against the effective autonomy level.
4. Snapshot current state.
5. Execute.
6. Verify within a time window.
7. Roll back automatically if verification fails and the action is reversible.
8. Record the outcome; update trust.

**Guardrails**: fleet-wide circuit breakers when an action's failure rate spikes; rate limits (N devices per hour per action); global and per-client kill switches; approval cards with evidence, planned change, and undo plan, with expiry and batch approval. Pre-checks include an active-user check, so disruptive actions wait, prompt the user, or drop to L1.

**First catalog slice** (proves every pipeline stage)

1. Restart print spooler and clear the queue.
2. Disk cleanup with fixed rules: temp files, Windows Update cache, recycle bin older than N days, browser caches; never Downloads or user folders.
3. Restart a stuck service from a policy allowlist.
4. Flush DNS / renew IP lease.
5. Kill a hung process (active-user pre-check).
6. Force Group Policy update or Intune sync.
7. Reset Windows Update components, then retry the update (tests chaining).

**Later waves**: clear Teams/Outlook/browser cache, clock re-sync, restart agent components, clear one printer's jobs; workstation reboot, winget repair/reinstall, network stack reset, Search index rebuild, OneDrive reset, remap drives/printers, Defender scan, VPN restart. Fixed at L1: server reboots, profile rebuilds, uninstalls, domain trust repairs, disabling users, device isolation (proposed fast from MDE alerts).

## AI layer

One server-side AI gateway handles every AI feature (self-service chat, alert triage, diagnosis, script drafting, MCP), so routing, privacy, logging, and cost live in one place. Start with the Claude API; add local models once the core works.

**Rules first, models second**: known problems (e.g., a specific Windows Update error code) map deterministically to recipes. The LLM handles what rules can't.

**Model routing**

- Fast, cheap model (Haiku-class): intent parsing, alert summaries, grouping alerts into incidents.
- Strong model (Sonnet/Opus-class): diagnosis, multi-step troubleshooting, script drafting, policy suggestions.
- A **provider interface** from day one with only the Claude implementation behind it. Nothing calls Claude directly. Prompts are versioned per provider.

**Diagnosis**: an investigation loop with read-only tools (inventory, metrics, device events, recent changes, read-only diagnostic blocks on the device). Output is structured (hypothesis, evidence, proposed catalog action, confidence) and validated against the catalog, so the model cannot invent actions.

**Context assembly**: device fact sheet, recent changes, similar past incidents with outcomes, and client docs from Hudu.

**Privacy tiers** (per client, in the data model now)

- Cloud allowed: usernames, hostnames, and IPs replaced with placeholders before leaving the server, restored in the response.
- Local only: requests go only to self-hosted models. Until local support exists, these clients get AI off.
- Off: rules and the button catalog still work.

**Safety**

- The model is never the security boundary. Device text, file names, and user chat are untrusted input.
- Model output must match a strict schema; the policy gate enforces autonomy regardless of what the model says.
- Every decision records model and prompt version. Before upgrading either, replay past incidents and compare against real outcomes.
- Per-client monthly AI budgets, cached context, batched low-priority work.

**Self-service flow**: the tray chat relays text to the server with the device and OS-reported user. The AI maps it to a catalog action (e.g., `install_app(zoom)`); the gate checks the approved software list and self-service autonomy. Pass → signed command; fail → ticket in the PSA and an approval card. A button catalog sits beside the chat; offline, the chat says so and offers cached actions.

## MCP server

The MCP server is a thin adapter over the public API with no special privileges: every call runs with the caller's own credentials, so RBAC, RLS, the autonomy gate, and audit all apply. The internal AI gateway uses the same tools. First use: ad hoc questions from Claude.

| Tier | Tools | Notes |
| --- | --- | --- |
| Read | `client_health_summary`, `search_devices`, `get_device`, `list_alerts`, `get_alert_context`, `get_device_changes`, `query_metrics`, `get_compliance`, `get_effective_policy`, `list_catalog_actions`, `get_action_outcomes`, read-only fleet views | Pre-aggregated answers beat paging records |
| Propose | `propose_action`, `propose_policy_change`, `draft_script` | Creates approval cards, draft versions, unsigned drafts |
| Execute | `run_action` | Through the normal gate; MCP tokens default to an L1 ceiling |

**Never exposed**: signing, publishing policies, creating catalog definitions, RBAC changes, credential management.

**Auth**: Streamable HTTP with OAuth per the MCP spec, Entra ID as the identity provider. Scoped tokens carry tier, allowed clients, autonomy ceiling, and expiry. Audit records the full chain (e.g., Claude Desktop via MCP for Dyllan, token X).

**Also expose**: resources (device fact sheets, the action catalog, client runbooks) and prompts (triage an alert, client health summary, patch compliance report).

**Safety**: paginated and size-limited results; device-sourced text labeled untrusted; per-token rate limits; risky actions go through the platform's approval flow, never only the client's confirm prompt.

**Build order**

1. `search_devices`, `get_device`, `list_alerts`, `client_health_summary`.
2. `get_device_changes`, `query_metrics`.
3. `get_compliance`, `get_effective_policy`, read-only fleet views.
4. `propose_action`, once approval cards exist in the GUI.

**Access**: start with Claude Desktop over Tailscale or VPN (nothing public). Add a public OAuth-protected endpoint for claude.ai and mobile once read tools are proven; check current connector requirements then.

## Remote access

Remote access ships in three tiers, easiest first: shell, then file transfer, then desktop.

1. **Remote shell**: the agent spawns a PTY (ConPTY on Windows) and streams it over NATS to xterm.js. Ships first.
2. **File transfer**: chunked over the same channel.
3. **Remote desktop**: video over WebRTC (`webrtc-rs` or `str0m`), NATS only for signaling, self-hosted coturn as relay. Capture with DXGI Desktop Duplication (Windows), ScreenCaptureKit (Mac), X11/PipeWire (Linux). Hardware H.264 where available, openh264 fallback.

**Background tools** in the session view: processes, services, registry, event log.

**Session security**

- MFA required to start a session.
- Server-issued short-lived signed session tokens, verified by the agent.
- Visible "IT is connected" indicator for the end user; optional per-client consent.
- Every session recorded and logged.
- The AI assist panel only suggests read-only commands or catalog actions; it never types into the shell itself.

**Shortcut option**: RustDesk (Rust, self-hostable) could ship alongside the agent at first. Review its AGPL obligations before modifying or redistributing it.

## Web GUI

The technician console has ten screens, mocked up in the [RMM Technician Console](https://claude.ai/artifact/Q7jPoy4menUp7y1MdNLvZB) canvas. Use it as the visual reference: graphite sidebar, single teal accent, IBM Plex Sans and Mono, `[PRODUCT NAME]` where branding goes.

| Screen | What it shows |
| --- | --- |
| Fleet overview | Natural-language fleet query bar, key numbers, client health table, AI activity feed with Undo and Why |
| AI approvals | Approval cards: evidence, planned change, verify/undo, autonomy level, track record; batch approve; trust promotions |
| Device detail | Effective policy with source and conflicts, drift, recent changes timeline, remote and diagnose buttons |
| Alerts | AI-grouped incidents with summary and proposed fix; fleet-level and anomaly alerts |
| Policy editor | Template tree, dynamic-group targeting, compound condition builder, backtest, staged rollout |
| Action catalog | Signed actions with risk, max level, success rate, signature status; recipe view; per-client earned autonomy |
| Remote session | Shell/desktop tabs, MFA and recording indicators, AI assist panel |
| Audit log | Filter by technicians, AI, MCP tokens, end users, signing events; reasoning and snapshots |
| Compliance | CMMC L2 / 800-171 practices mapped to agent checks, gaps, POA&M, evidence export |
| End-user tray app | Self-service chat plus Get apps and Quick fixes tabs |

**Behavior**

- Sidebar collapses to an icon rail on desktop and stays pinned while scrolling.
- Under 900px it becomes a top bar with a menu button that hides on scroll down and returns on scroll up.
- The "Pause all AI actions" kill switch is in the sidebar on every screen.
- Branding (name, logo, colors, favicon, login page, email templates) comes from runtime config. Agent display names and installer metadata are stamped per deployment at build time.

## Build phases

Six phases, each usable on its own. Everything runs on internal machines for several months, alongside NinjaOne, before any client endpoint is enrolled.

&#91;embedded content: build roadmap · 6 phases, 1 gate\]

Shadow mode starts in phase 2, so the AI has months of decision history before it acts on anything.

## Open questions

- What criteria graduate the platform from internal machines to the first client?
- When does PSA integration land, and does it target the custom PSA or Autotask first?
- Build remote desktop in-house, or ship RustDesk alongside the agent at first?
- How long should quarantined files from disk cleanup be kept before purge?
