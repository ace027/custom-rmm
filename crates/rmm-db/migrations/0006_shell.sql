-- Co-signed remote shell: technicians and their hardware WebAuthn
-- credentials, registration challenges, shell sessions (grants, status and
-- recordings) and single-use browser WebSocket tickets.
--
-- msp.* tables hold MSP-wide data (technicians are not tenant rows), so like
-- msp.trust_artifact and msp.action_definition they carry no row level
-- security; only the rmm_api role is granted access. Tenant tables enforce
-- RLS on client_id like every other tenant.* table.

CREATE TABLE msp.technician (
    tech_id      text PRIMARY KEY CHECK (tech_id <> ''),
    display_name text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Clients a technician may act on; feeds client_scope of the techlist draft.
CREATE TABLE msp.technician_client (
    tech_id   text NOT NULL REFERENCES msp.technician (tech_id),
    client_id uuid NOT NULL REFERENCES tenant.client (id),
    PRIMARY KEY (tech_id, client_id)
);

CREATE TABLE msp.webauthn_challenge (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tech_id    text NOT NULL REFERENCES msp.technician (tech_id),
    challenge  bytea NOT NULL CHECK (octet_length(challenge) BETWEEN 16 AND 64),
    purpose    text NOT NULL CHECK (purpose IN ('register')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX webauthn_challenge_tech_idx ON msp.webauthn_challenge (tech_id, expires_at);

CREATE TABLE msp.webauthn_credential (
    cred_id         bytea PRIMARY KEY CHECK (octet_length(cred_id) BETWEEN 1 AND 1023),
    tech_id         text NOT NULL REFERENCES msp.technician (tech_id),
    alg             int NOT NULL CHECK (alg IN (-7, -8)),
    cose_pubkey     bytea NOT NULL,
    aaguid          bytea NOT NULL CHECK (octet_length(aaguid) = 16),
    sign_count      bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    attestation_fmt text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz
);
CREATE INDEX webauthn_credential_tech_idx ON msp.webauthn_credential (tech_id);

CREATE TABLE tenant.shell_session (
    grant_id         bytea PRIMARY KEY CHECK (octet_length(grant_id) = 16),
    client_id        uuid NOT NULL REFERENCES tenant.client (id),
    agent_id         uuid NOT NULL REFERENCES tenant.agent (id),
    tech_id          text NOT NULL REFERENCES msp.technician (tech_id),
    cred_id          bytea NOT NULL REFERENCES msp.webauthn_credential (cred_id),
    shell            text NOT NULL,
    max_duration     int NOT NULL CHECK (max_duration > 0 AND max_duration <= 14400),
    grant_cbor       bytea NOT NULL,
    status           text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'opening', 'open', 'closed', 'expired', 'rejected')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    opened_at        timestamptz,
    closed_at        timestamptz,
    close_reason     text,
    recording_path   text,
    recording_sha256 bytea CHECK (recording_sha256 IS NULL OR octet_length(recording_sha256) = 32),
    recording_bytes  bigint CHECK (recording_bytes IS NULL OR recording_bytes >= 0),
    -- Lets shell_ws_ticket pin its client_id to the session's.
    UNIQUE (grant_id, client_id)
);
CREATE INDEX shell_session_client_idx ON tenant.shell_session (client_id, created_at DESC);
CREATE INDEX shell_session_created_idx ON tenant.shell_session (created_at);

CREATE TABLE tenant.shell_ws_ticket (
    ticket_hash bytea PRIMARY KEY CHECK (octet_length(ticket_hash) = 32),
    client_id   uuid NOT NULL,
    grant_id    bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    FOREIGN KEY (grant_id, client_id)
        REFERENCES tenant.shell_session (grant_id, client_id) ON DELETE CASCADE
);
CREATE INDEX shell_ws_ticket_grant_idx ON tenant.shell_ws_ticket (grant_id);

ALTER TABLE tenant.shell_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.shell_session FORCE ROW LEVEL SECURITY;
CREATE POLICY shell_session_scope ON tenant.shell_session
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

ALTER TABLE tenant.shell_ws_ticket ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.shell_ws_ticket FORCE ROW LEVEL SECURITY;
CREATE POLICY shell_ws_ticket_scope ON tenant.shell_ws_ticket
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

-- API only: registration, techlist drafts, grants, the relay and retention.
GRANT SELECT, INSERT ON msp.technician TO rmm_api;
GRANT UPDATE (display_name) ON msp.technician TO rmm_api;
GRANT SELECT, INSERT, DELETE ON msp.technician_client TO rmm_api;
GRANT SELECT, INSERT ON msp.webauthn_challenge TO rmm_api;
GRANT UPDATE (used_at) ON msp.webauthn_challenge TO rmm_api;
GRANT SELECT, INSERT ON msp.webauthn_credential TO rmm_api;
GRANT UPDATE (sign_count, revoked_at) ON msp.webauthn_credential TO rmm_api;
GRANT SELECT, INSERT, DELETE ON tenant.shell_session TO rmm_api;
GRANT UPDATE (status, opened_at, closed_at, close_reason,
              recording_path, recording_sha256, recording_bytes)
    ON tenant.shell_session TO rmm_api;
GRANT SELECT, INSERT, DELETE ON tenant.shell_ws_ticket TO rmm_api;
GRANT UPDATE (used_at) ON tenant.shell_ws_ticket TO rmm_api;
