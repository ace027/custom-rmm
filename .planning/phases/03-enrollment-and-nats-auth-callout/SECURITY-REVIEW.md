# Phase 3: Security Review

**Verdict**: CAUTION
**Unresolved blockers for ship**: 0

## OWASP Top 10
| # | Category | Result | Evidence |
|---|---|---|---|
| A1 | Injection | PASS | All SQL bound; format! only splices constants (repo.rs:297,318); role names whitelisted (scope.rs:55,61) |
| A2 | Broken Auth | WARN | JWT RS256-only, exp/aud/iss pinned, dev issuer flag-gated (auth.rs:281-315); PoP before token use (enroll.rs:185-190). Static NATS password users bypass callout and are reachable via public /nats WebSocket (nats.conf:47, nginx.conf:30-38) |
| A3 | Sensitive Data | WARN | Tokens SHA-256 hashed (enroll.rs:193); 0600 key file, DPAPI + protected DACL; agent does not enforce wss:// NATS URL (transport.rs:104) |
| A4 | XXE | N/A | No XML parsing |
| A5 | Access Control | WARN | RequireRole<Admin> on all admin routes; RLS service bypass is a settable GUC (0002_identity.sql:9-10); cross-tenant fingerprint existence leak (enroll.rs:87-91,357) |
| A6 | Misconfiguration | WARN | No allowed_connection_types on static NATS users; no nginx rate limits; dev flag hardcoded in compose; floating image tags |
| A7 | XSS | N/A | JSON-only API |
| A8 | Deserialization | PASS | Typed serde, 16 KiB enroll / 64 KiB JWT caps, verify_strict |
| A9 | Known Vulns | WARN | cargo-audit unavailable; cargo-deny in CI with two age-only ignores; actions tag-pinned |
| A10 | Logging | WARN | Append-only audit via triggers; failed technician auth/403 not audited; no retention; unauthenticated attempts grow audit table |

## STRIDE
| Boundary | Threat | Category | Attack Vector | Mitigation | Status |
|---|---|---|---|---|---|
| agent -> /v1/enroll | Forged enrollment | S | Stolen/guessed token | 160-bit token, hashed, max_uses, expiry, per-IP limit | PARTIAL (no token revoke API) |
| agent -> /v1/enroll | Key not owned | S | Submit another key | verify_strict over CBOR digest incl. token, ts, pubkey | MITIGATED |
| agent -> /v1/enroll | Replay | S/T | Resend request | ±300 s ts, 409 on reused pubkey, spent token | MITIGATED |
| agent -> /v1/enroll | Hardware spoofing | S/E | Claim known HW IDs with reattach token | 24 h rule, active device, same client | PARTIAL (unattested facts) |
| agent -> /v1/enroll | Cross-tenant leak | I | 'flagged' status reveals foreign device | none | UNMITIGATED (LOW) |
| agent -> /v1/enroll | Audit/DB flooding | D | Mass failed enrolls | 10/min per IP | PARTIAL |
| technician -> API | Token forgery | S | alg confusion/none/aud | RS256, iss/aud pinned, kid from JWKS | MITIGATED |
| technician -> API | Dev issuer abuse | S/E | Forge with dev key | RMM_AUTH_ALLOW_DEV=1 + key file | PARTIAL (accepted dev) |
| technician -> API | Escalation | E | Admin routes without role | role extractor | MITIGATED |
| technician -> API | Auth DoS | D | JWKS outage under mutex | 5 s timeout | PARTIAL |
| agent -> NATS (callout) | Impersonate agent | S | Pubkey without private key | nonce sig verify, DB row active, nkey match, websocket only | MITIGATED |
| agent -> NATS (callout) | Static-user login over WS | S/E | Brute-force api/ingest/authd/sys passwords via wss /nats | passwords only | UNMITIGATED (MEDIUM) |
| agent -> NATS (callout) | Cross-tenant pub/sub | I/T | Compromised agent | per-agent allow-lists, 1 h TTL | MITIGATED (limits -1 residual) |
| agent -> NATS (callout) | Revoked agent connected | E | Connection outlives revoke | connz/KICK, 1 h JWT | MITIGATED (single server) |
| agent -> NATS (callout) | Callout flood | D | Unauthenticated connects -> DB + audit | 256 in-flight, 2 s timeout | PARTIAL |
| authd <-> DB | Over-privilege | E | authd compromise | minimal grants, NOBYPASSRLS | PARTIAL (superuser+SET ROLE until phase 4) |
| authd <-> DB | Audit tampering | T/R | Edit/delete audit | triggers, no grants | MITIGATED |
| API <-> DB (RLS) | Cross-tenant read | I | Injection / missed scope | FORCE RLS, bound queries | PARTIAL (GUC bypass) |
| agent key at rest | Theft (Unix/Windows) | I | Local user | 0600 / DPAPI + DACL | MITIGATED |
| agent key at rest | State-dir squat (Windows) | T/D | Pre-create %ProgramData%\RMM | none | UNMITIGATED (LOW) |

## Attack Surface
- Internet via nginx :443 (all interfaces): POST /v1/enroll (unauthenticated: token + PoP, 16 KiB, per-IP limit); /api/* admin routes (JWT + RMM.Admin); /nats WebSocket proxy to NATS (no rate limit, static users allowed); /healthz.
- Loopback/internal: NATS 4222/8222 and Postgres 5432 on 127.0.0.1; authd :8082 and ingest :8081 health on compose network; $SYS.REQ.USER.AUTH and rmm.internal.agent.revoked restricted by permissions.
- Secrets: NATS static passwords (.env), authd issuer seed, dev RSA key (gitignored deploy/dev/auth), Postgres superuser (dev, accepted). Outbound: Entra discovery/JWKS.
- Agent: agent.key, identity.json, trust envelopes in the state dir; outbound HTTPS enroll and wss NATS with a server-supplied URL.
- Build/CI: tag-pinned GitHub Actions, cargo-deny, floating Docker tags, e2e script runs as root in a mount namespace.

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
| SEC-001 | A2:Broken Auth | MEDIUM | Static NATS users api, ingest, authd and sys bypass the auth callout and authenticate with passwords on every listener, including the WebSocket port nginx exposes at /nats; no connection-type restriction or rate limit. sys controls the system account. dev-up.sh copies the public .env.example passwords and nginx binds 0.0.0.0. | deploy/nats/nats.conf:19-49, deploy/nginx/nginx.conf:30-38, deploy/compose.yaml:143, scripts/dev-up.sh:6-9 | Add allowed_connection_types ["STANDARD"] to static users (or an internal-only listener), nginx limit_req/limit_conn on /nats, random dev passwords in dev-up.sh, bind nginx to 127.0.0.1 for dev. | OPEN |
| SEC-002 | A10:Logging | MEDIUM | Every unauthenticated callout attempt (even precheck failures) opens a DB transaction and writes an audit row; no rate limit or audit retention. A flood beyond 256 in-flight requests drops legitimate agents and grows msp.audit_event without bound; /v1/enroll failures likewise. | crates/rmm-server/src/authd.rs:43,176-219,367-371, crates/rmm-api/src/enroll.rs:204-221 | Rate-limit /nats upgrades in nginx, aggregate precheck failures instead of a row per attempt, add audit retention/partitioning, shared limiter for multiple API replicas. | OPEN |
| SEC-003 | A9:Known Vulnerabilities | MEDIUM | cargo-audit not installed; Cargo.lock dependencies not audited | Cargo.lock | Install cargo-audit and re-run the security review. | OPEN |
| SEC-004 | A5:Access Control | LOW | Cross-tenant oracle: an enrollment with another tenant's (non-secret) hardware IDs returns status 'flagged' and stores the foreign device id in possible_clone_of, revealing the device exists elsewhere. | crates/rmm-api/src/enroll.rs:87-91,195,223,288-296,357 | Return a neutral status; keep the foreign device id only in the audit event. | OPEN |
| SEC-005 | A4:Insecure Design | LOW | Reattach trusts self-asserted hardware facts: a reattach-enabled token plus known IDs supersedes an active device's agent unseen for 24 h. | crates/rmm-api/src/enroll.rs:57-93,192,265-267 | Default allow_reattach false, admin approval for reattach, alert on supersede; TPM attestation later. | OPEN |
| SEC-006 | A3:Sensitive Data | LOW | Agent accepts a non-TLS nats_url (ws:// or nats://) from the server; plaintext leg exposes traffic and allows nonce-signature relay. | crates/rmm-agent-core/src/transport.rs:104-106, crates/rmm-agent-core/src/enroll.rs:365-370 | Reject non-wss:// URLs in release builds at enroll and load; optionally require host match with server_url. | OPEN |
| SEC-007 | A5:Access Control | LOW | Windows state-directory squat: an existing %ProgramData%\RMM is left untouched and identity/trust files get no DACL, so a low-privilege user who pre-creates it can delete the key or edit nats_url. | crates/rmm-platform/src/windows.rs:164-197, crates/rmm-agent-core/src/identity.rs:41-69 | Verify owner/DACL of an existing directory and reset or fail; apply the DACL to identity files; installer creates the directory. | OPEN |
| SEC-008 | A4:Insecure Design | LOW | Enrollment tokens (up to 720 h, 1000 uses) cannot be revoked via the API; the revoked column is never set by any route. | crates/rmm-api/src/admin.rs:84-153, crates/rmm-api/src/lib.rs:148-171 | Add POST /api/v1/enrollment-tokens/{id}/revoke with audit; lower default max_uses. | OPEN |
| SEC-009 | A6:Misconfiguration | LOW | JWKS refresh under one mutex retries a 5 s fetch on every request after TTL or failure, so an Entra outage stalls all authentication. | crates/rmm-api/src/auth.rs:319-329,335-378 | Back off on failure, serve stale keys for a bounded time, fetch outside the lock. | OPEN |
| SEC-010 | A6:Misconfiguration | INFO | Compose hardcodes RMM_AUTH_ALLOW_DEV=1 and mounts the dev private key into the api container (only the public key is needed); dev tokens are not refused when an Entra tenant is configured. | deploy/compose.yaml:97-101, crates/rmm-api/src/auth.rs:218-225 | Mount only dev-pub.pem in api; refuse the dev flag with RMM_ENTRA_TENANT_ID set; compose override for dev. | OPEN |
| SEC-011 | A5:Access Control | INFO | RLS service bypass is the settable GUC rmm.service, so RLS does not contain an injected or compromised session. | crates/rmm-db/migrations/0002_identity.sql:9-10, crates/rmm-db/src/scope.rs:41 | Phase 4: role-checked policies or SECURITY DEFINER functions instead of the GUC bypass. | OPEN |
| SEC-012 | A5:Access Control | INFO | Agent JWT limits are unlimited (subs/data/payload -1) and reply subjects are unconstrained. | crates/rmm-server/src/natsjwt.rs:287-289 | Set finite limits. | OPEN |
| SEC-013 | A8:Integrity | INFO | Agent applies the enrollment trust bundle with an empty sequence store and release builds accept empty RMM_ROOT_PUBKEYS (fails closed for non-empty bundles). | crates/rmm-agent-core/src/enroll.rs:19-28,203-230 | Reject empty roots at build time; persist the sequence floor (phase 5 local store). | OPEN |
| SEC-014 | A6:Misconfiguration | INFO | client_ip trusts X-Real-IP unconditionally and the enroll client follows 307/308 redirects (re-POSTing the token). | crates/rmm-api/src/enroll.rs:121-128, crates/rmm-agent-core/src/enroll.rs:120-127 | Trusted-proxy config; redirect(Policy::none()) for the enroll client. | OPEN |
