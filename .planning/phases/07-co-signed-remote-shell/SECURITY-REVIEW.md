# Phase 7: Security Review

**Verdict**: CAUTION
**Unresolved blockers for ship**: 0

## OWASP Top 10
Plan-stage: A1 Injection PASS (fixed shell allowlist, no user args, no -EncodedCommand); A2 Broken Auth PASS (agent verifies WebAuthn assertion vs signed techlist with UV; single-use tickets/challenges); A3 Sensitive Data WARN (recordings contain session data: 0600 files, RLS rows, 1-year retention; at-rest encryption not planned); A4 XXE PASS (no XML); A5 Access Control PASS (client scope checked by API and agent, RLS on tenant tables); A6 Misconfiguration WARN (dev attestation root/AAGUID must never be configured in production; documented); A7 XSS PASS (no HTML served); A8 Deserialization PASS (strict canonical CBOR, bounded chunk size); A9 Known Vulns WARN (new deps portable-pty, x509-cert gated by cargo-deny); A10 Logging PASS (signed results with stable reject reasons, session status in DB).

## STRIDE
| Boundary | Threat | Category | Attack Vector | Mitigation | Status |
|---|---|---|---|---|---|
| Server -> agent | Server opens a shell alone | Elevation | Compromised API signs ShellOpen | Agent requires technician hardware assertion vs YubiKey-signed techlist | MITIGATED |
| Server -> agent | Keystroke injection into open session | Tampering | Compromised server/relay | Short sessions, indicator, E2E later (accepted residual) | PARTIAL |
| Browser -> API | Ticket replay | Spoofing | Reuse of ws ticket | Hash stored, single use, 60 s expiry | MITIGATED |
| Authenticator -> API | Synced passkey registration | Spoofing | Software authenticator | Packed attestation chain + AAGUID allowlist, rmm-sign allowlist | MITIGATED |
| Agent -> relay | Memory exhaustion | DoS | Relay never acks | 256 KiB credit cap, liveness, max_duration | MITIGATED |
| Local user -> agent | Indicator pipe abuse | Tampering | Write to pipe | Outbound-only pipe, server ignores input | MITIGATED |

## Attack Surface
Plan-stage review (code not yet written). New surfaces: API WebAuthn registration (attestationObject CBOR + x5c parsing), grant/open endpoints, browser WebSocket relay with single-use tickets, recording files on disk, NATS shell.<a>.<sid>.{in,out,ctl} core subjects, agent ShellOpen verification and PTY spawn as SYSTEM, local indicator pipe/socket, rmm-session helper, xtask fake authenticator (dev only).

### Dependency Vulnerability Findings
_none_
- cargo-audit unavailable (verdict at most CAUTION)

### Secret Detection Findings
_none_

### Supply Chain Findings
_none_

## Findings
| ID | OWASP Cat | Severity | Finding | File(s) | Remediation | Status |
|----|-----------|----------|---------|---------|-------------|--------|
| SEC-001 | A9:Known Vulnerabilities | MEDIUM | cargo-audit not installed; Cargo.lock dependencies not audited | Cargo.lock | Install cargo-audit and re-run the security review. | OPEN |
| SEC-002 | A3:Sensitive Data | LOW | Shell recordings stored as plaintext files (0600) for 1 year | crates/rmm-api/src/recording.rs (planned) | Consider at-rest encryption of recordings in a later phase; disk encryption on the server host meanwhile | OPEN |
| SEC-003 | A6:Misconfiguration | LOW | Dev attestation root and AAGUID would allow software authenticators if configured in production | deploy/.env.example (planned) | Runbook warns; production config uses only Yubico roots and AAGUIDs | OPEN |
