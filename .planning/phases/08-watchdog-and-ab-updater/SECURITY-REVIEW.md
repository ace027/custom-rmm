# Phase 8: Security Review

**Verdict**: CAUTION
**Unresolved blockers for ship**: 0

## OWASP Top 10
Plan-stage: A1 PASS (no shell-out; fixed paths); A2 PASS (releases need the offline release role; watchdog verifies against compiled roots independently of agent and server); A3 PASS (artifacts are public binaries; no secrets); A4 PASS; A5 WARN (pending/ and slots/ must be writable only by SYSTEM/Administrators on Windows; DACL planned for the root, agent runs as SYSTEM too); A6 WARN (unauthenticated download endpoint needs nginx rate limiting); A7 PASS; A8 PASS (strict CBOR, size caps, semver parse); A9 WARN (no new crates planned beyond workspace ones); A10 PASS (watchdog logs every transition and reject reason).

## STRIDE
| Boundary | Threat | Category | Attack Vector | Mitigation | Status |
|---|---|---|---|---|---|
| Server -> agent | Malicious build pushed by compromised server | Tampering | Upload artifact + fake release | Release role signature verified by agent and by watchdog against compiled roots | MITIGATED |
| Server -> agent | Downgrade to a vulnerable signed build | Tampering | Replay old signed release | semver > active and seq floor in watchdog state | MITIGATED |
| Local -> watchdog | Plant files in pending/ | Elevation | Local non-admin writes pending | Root DACL SYSTEM+Administrators; watchdog re-verifies everything | MITIGATED |
| Network -> API | Artifact download abuse | DoS | Flood /v1/artifacts | nginx rate limit (add) | PARTIAL |
| Bad build -> fleet | Bricked agents | DoS | Signed but broken build | Health trial + rollback + bad_hashes; bootstrap slot untouched | MITIGATED |

## Attack Surface
Plan-stage review. New surfaces: admin artifact upload (256 MiB), unauthenticated artifact download by hash, NATS svc.trust.latest / svc.release.latest responders, agent download into pending/, watchdog verification and slot swap running as LocalSystem, state.json on disk.

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
| SEC-002 | A6:Misconfiguration | LOW | Unauthenticated artifact download endpoint should be rate-limited at nginx like enrollment | deploy/nginx/nginx.conf (planned) | Add a limit_req zone for /v1/artifacts/ in 08-01 | OPEN |
| SEC-003 | A5:Access Control | LOW | state.json floor is stored on disk; an administrator could reset it and allow a downgrade | crates/rmm-watchdog/src/state.rs (planned) | Accepted: local admin equals device compromise per the threat model; an HKLM ACL-protected copy of the floor can follow | OPEN |
