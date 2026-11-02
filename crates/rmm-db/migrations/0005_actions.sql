-- Signed actions: the catalog of catalog-signed definitions and the record of
-- every command issued to an agent with its agent-signed outcome.

CREATE TABLE msp.action_definition (
    content_id  bytea PRIMARY KEY CHECK (octet_length(content_id) = 32),
    id          text NOT NULL,
    version     int NOT NULL CHECK (version > 0),
    capability  text NOT NULL,
    envelope    bytea NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    uploaded_by text NOT NULL
);
CREATE INDEX action_definition_id_idx ON msp.action_definition (id, version);

CREATE TABLE tenant.action_run (
    cmd_id                uuid PRIMARY KEY,
    client_id             uuid NOT NULL REFERENCES tenant.client (id),
    agent_id              uuid NOT NULL REFERENCES tenant.agent (id),
    device_id             uuid NOT NULL REFERENCES tenant.device (id),
    definition_content_id bytea NOT NULL REFERENCES msp.action_definition (content_id),
    params                jsonb NOT NULL DEFAULT '{}'::jsonb,
    requested_by          text NOT NULL,
    status                text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'succeeded', 'failed', 'rolled_back', 'rejected', 'expired')),
    reason                text,
    stages                jsonb NOT NULL DEFAULT '[]'::jsonb,
    result_envelope       bytea,
    created_at            timestamptz NOT NULL DEFAULT now(),
    finished_at           timestamptz
);
CREATE INDEX action_run_client_idx ON tenant.action_run (client_id, created_at DESC);
CREATE INDEX action_run_agent_idx ON tenant.action_run (agent_id, created_at DESC);

ALTER TABLE tenant.action_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.action_run FORCE ROW LEVEL SECURITY;
CREATE POLICY action_run_scope ON tenant.action_run
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

-- API: upload definitions, issue and read runs.
GRANT SELECT, INSERT ON msp.action_definition TO rmm_api;
GRANT SELECT, INSERT ON tenant.action_run TO rmm_api;

-- Ingest: verify results against the run and record the outcome and audit.
GRANT USAGE ON SCHEMA msp TO rmm_ingest;
GRANT SELECT ON msp.action_definition TO rmm_ingest;
GRANT SELECT ON tenant.action_run TO rmm_ingest;
GRANT UPDATE (status, reason, stages, result_envelope, finished_at) ON tenant.action_run TO rmm_ingest;
GRANT INSERT ON msp.audit_event TO rmm_ingest;
GRANT USAGE ON SEQUENCE msp.audit_event_id_seq TO rmm_ingest;
