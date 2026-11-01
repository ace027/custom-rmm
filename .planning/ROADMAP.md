# custom-rmm — Roadmap

## Phases

- [x] Phase 1: Workspace, dev environment and CI (3 plans)
- [x] Phase 2: Trust core and signing CLI (4 plans)
- [x] Phase 3: Enrollment and NATS auth callout (4 plans)
- [ ] Phase 4: Heartbeat, inventory and metrics (3 plans)
- [ ] Phase 5: Encrypted local store and offline sync (2 plans)
- [ ] Phase 6: Signed commands and first catalog action (4 plans)
- [ ] Phase 7: Co-signed remote shell (4 plans)
- [ ] Phase 8: Watchdog and A/B updater (3 plans)
- [ ] Phase 9: MSI packaging (2 plans)

## Phase Details

### Phase 1: Workspace, dev environment and CI
**Goal**: A compiling workspace skeleton with all 12 crates, enforced layering, a healthy docker compose stack and green CI including Windows cross-compile
**Requirements**: REQ-01, REQ-02, REQ-03, REQ-23
**Recommended Agents**: engineering-infrastructure-devops, engineering-backend-architect
**Success Criteria**:
- [ ] cargo xwin build produces rmm-agent.exe for x86_64-pc-windows-msvc
- [ ] docker compose up brings Timescale, NATS (JetStream + WebSocket), nginx TLS and server services to healthy
- [ ] All CI jobs (lint, windows-cross, test-linux, test-windows) are green
- [ ] A layering violation (server crate depending on rmm-platform) fails CI
- [ ] Spec moved to docs/spec.md
**Plans**: 3

### Phase 2: Trust core and signing CLI
**Goal**: Verifiable signing chain: canonical CBOR envelopes, certificates, trust manifest, revocations, command and technician-list types, WebAuthn verification, and rmm-sign with file and YubiKey backends
**Requirements**: REQ-04, REQ-05, REQ-06, REQ-07
**Recommended Agents**: engineering-security-engineer, engineering-senior-developer, testing-qa-verification-specialist
**Success Criteria**:
- [ ] Golden test vectors pass in both directions
- [ ] A YubiKey OpenPGP Ed25519 signature (with touch) verifies in rmm-trust
- [ ] Fuzz and property tests reject non-canonical encodings
- [ ] Lower seq and expired documents are rejected; threshold counting ignores revoked and wrong-role keys
- [ ] Root ceremony dry run documented
- [ ] The agent build excludes the sign feature
**Plans**: 4

### Phase 3: Enrollment and NATS auth callout
**Goal**: A Windows agent enrolls with a device-generated DPAPI-protected key and connects to NATS over WSS 443 with a scoped JWT from the auth callout service
**Requirements**: REQ-08, REQ-09, REQ-10, REQ-20
**Recommended Agents**: engineering-backend-architect, engineering-security-engineer
**Success Criteria**:
- [ ] Windows VM enrolls with a token and connects through nginx on 443
- [ ] Publishing to another agent's subject is denied
- [ ] A revoked agent is refused and its connection kicked
- [ ] Reinstall reattaches to the same device; the clone scenario is flagged pending_review
- [ ] Technician API login via Entra ID OIDC works
**Plans**: 4

### Phase 4: Heartbeat, inventory and metrics
**Goal**: Agents report heartbeat, inventory and metrics that land in Postgres/Timescale under enforced client scoping
**Requirements**: REQ-11, REQ-12, REQ-13
**Recommended Agents**: engineering-backend-architect, engineering-security-engineer, engineering-infrastructure-devops
**Success Criteria**:
- [ ] Two-client RLS suite passes, including compressed metric chunks
- [ ] rmm_api is denied on ts_private
- [ ] A RAM change writes a device_event
- [ ] Ingest takes client_id from the authenticated subject, never the payload
**Plans**: 3

### Phase 5: Encrypted local store and offline sync
**Goal**: The agent keeps working offline and syncs on reconnect, with an encrypted local store holding the queue, replay cache and trust cache
**Requirements**: REQ-14
**Recommended Agents**: engineering-backend-architect, engineering-senior-developer
**Success Criteria**:
- [ ] After 1 hour offline all queued telemetry and results arrive with no duplicates
- [ ] A lower trust seq is rejected after agent restart
- [ ] Store values are unreadable without the DPAPI-wrapped key
**Plans**: 2

### Phase 6: Signed commands and first catalog action
**Goal**: The server invokes a signed definition through a signed command and the agent runs the print spooler action through the full executor pipeline
**Requirements**: REQ-15, REQ-16, REQ-17
**Recommended Agents**: engineering-senior-developer, engineering-security-engineer, testing-qa-verification-specialist
**Success Criteria**:
- [ ] Restart spooler and clear queue works end to end on Windows
- [ ] A forced verify failure triggers rollback
- [ ] Expired, replayed, tampered, revoked and unsigned-definition commands are each rejected by a test
- [ ] action_run and audit_event rows are written with the agent-signed result
**Plans**: 4

### Phase 7: Co-signed remote shell
**Goal**: Technicians open a recorded ConPTY shell only with a hardware-key co-signature the agent verifies
**Requirements**: REQ-18, REQ-19
**Recommended Agents**: engineering-senior-developer, engineering-security-engineer, testing-performance-benchmarker
**Success Criteria**:
- [ ] No shell opens without a valid WebAuthn assertion from a listed hardware credential
- [ ] A removed technician is locked out after the next TechnicianList sync
- [ ] Printing a 1 GB file keeps agent memory under 50 MB
- [ ] max_duration and liveness timeouts are enforced
- [ ] The 'IT is connected' indicator shows during sessions; recordings are stored
**Plans**: 4

### Phase 8: Watchdog and A/B updater
**Goal**: Agents update themselves from signed releases and recover automatically from bad builds or crashes
**Requirements**: REQ-21
**Recommended Agents**: engineering-senior-developer, engineering-infrastructure-devops
**Success Criteria**:
- [ ] A signed update applies
- [ ] A build failing its health check rolls back within 5 minutes
- [ ] Downgrade and tampered artifacts are rejected
- [ ] A killed core restarts within 10 seconds
**Plans**: 3

### Phase 9: MSI packaging
**Goal**: A silent MSI install enrolls an internal Windows machine end to end
**Requirements**: REQ-22
**Recommended Agents**: engineering-infrastructure-devops, testing-qa-verification-specialist
**Success Criteria**:
- [ ] Silent install with ENROLL_TOKEN enrolls on Win10, Win11, Server 2019 and Server 2022
- [ ] Uninstall is clean
- [ ] MSI repair does not overwrite updater-owned A/B slots
**Plans**: 2

## Progress

| Phase | Plans | Completed | Status |
|-------|-------|-----------|--------|
| 1 | 3 | 3 | Complete |
| 2 | 4 | 4 | Complete |
| 3 | 5 | 5 | Complete |
| 4 | 3 | 2 | Partial |
| 5 | 2 | 0 | Pending |
| 6 | 4 | 0 | Pending |
| 7 | 4 | 0 | Pending |
| 8 | 3 | 0 | Pending |
| 9 | 2 | 0 | Pending |
