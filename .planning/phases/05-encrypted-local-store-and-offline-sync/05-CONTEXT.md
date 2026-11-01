# Phase 5: Encrypted local store and offline sync -- Context

## Phase Goal
The agent keeps working offline and syncs on reconnect, with an encrypted local store holding the queue, replay cache and trust cache

## Requirements Covered
- REQ-14

## What Already Exists (from prior phases)
- Phase 2: rmm_trust::verify::{TrustStore, SeqStore, ReplayCache, DocKind, Clock}; MemorySeqStore/MemoryReplayCache are in-memory only
- Phase 3: rmm_platform::keystore(state_dir) -> Box<dyn KeyStore> storing the agent seed as agent.key (DPAPI on Windows, 0600 file on Unix, KEY_FILE const in crates/rmm-platform/src/keystore.rs); rmm_agent_core::identity (identity.json + trust/*.env in the state dir); enrollment verifies the trust bundle with a fresh MemorySeqStore (crates/rmm-agent-core/src/enroll.rs ~line 208)
- Phase 4: rmm_agent_core::telemetry::Publisher sends heartbeats (core publish) and metrics/inventory (JetStream with Nats-Msg-Id = msg_id, UUIDv7) and only logs failed publishes; ingest (crates/rmm-server/src/ingest.rs, write() ~line 505) inserts metrics with no dedupe beyond the TELEM stream's 2-minute duplicate window; phase 4 review deferred F-001 (no durable msg_id dedupe); migrations 0001-0003; scripts/e2e-enroll.sh and e2e-telemetry.sh run in CI test-linux

## Key Design Decisions
- Store: one SQLite file agent-store.db in the agent state dir via rusqlite (feature bundled; WAL; 0600 on Unix, under the protected state dir on Windows). Values are encrypted at the application level with XChaCha20-Poly1305 (chacha20poly1305 crate): random 24-byte nonce per value, AAD = table name || 0x00 || row key, stored as nonce||ciphertext. Keys, timestamps and sizes stay in clear (accepted: metadata readable)
- Store key: a separate random 32-byte key in store.key, protected exactly like agent.key (DPAPI SYSTEM scope on Windows, 0600 on Unix) through a new rmm_platform::keystore_named(state_dir, name); the agent seed is never reused as the store key
- Tables: outbox(seq integer primary key autoincrement, msg_id blob unique, subject text, priority int, created_at int, payload blob), replay(cmd_id_hash blob primary key, expires_at int), seq_floor(kind text primary key, seq int, content_id blob), trust(kind text primary key, envelope blob), policy(key text primary key, value blob); payload, content_id, envelope and value are encrypted
- Outbox: metrics and inventory are always written to the outbox first, then published; a row is deleted only after the JetStream ack. Drain order: priority asc (0 results [phase 6], 1 inventory, 2 metrics), then seq asc; at most 200 in flight. Bound: 50000 rows or 64 MiB of payload, dropping the oldest priority-2 rows first and counting drops. Heartbeats are never queued
- Duplicates: the agent re-publishes with the same msg_id after reconnect, so the stream's 2-minute window is not enough; ingest keeps durable dedupe in ts_private.ingested_msg(msg_id uuid primary key, received_at timestamptz) with a 7-day retention job, and skips (acks) any message whose msg_id is already recorded, inside the same transaction that writes it
- Trust: enrollment and later trust updates use the persisted SeqStore (seq_floor) and store the envelopes in the trust table, so a lower seq is rejected after an agent restart
- Offline e2e: the 1-hour offline criterion is exercised with a shortened window (nginx stopped for 60 s with fast debug intervals); the queue logic does not depend on wall-clock duration, and unit tests cover queue bounds and ordering
- Light process for this phase: board, domain, spec, persona gate and plan-stage security scan skipped; personas from the roadmap recommendations

## Plan Structure
- **Plan 05-01 (Wave 1)**: Encrypted local store -- Add the agent's encrypted SQLite store (outbox, replay cache, persisted trust sequence floors, trust and policy cache) with a separate DPAPI/0600-protected store key, implement rmm-trust's SeqStore and ReplayCache on it, and use it for enrollment trust verification.
- **Plan 05-02 (Wave 2)**: Offline outbox, drain and server-side dedupe -- Route metrics and inventory through the encrypted outbox with drain-on-reconnect, add durable msg_id dedupe in ingest, and prove an offline period ends with every sample delivered exactly once.
