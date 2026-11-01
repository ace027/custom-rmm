-- Identity schema: clients, sites, devices, agents, enrollment tokens,
-- trust artifacts and an append-only audit log, with row level security.

CREATE FUNCTION rmm.scope() RETURNS uuid[]
    LANGUAGE sql STABLE
    AS $$ SELECT coalesce(nullif(current_setting('rmm.client_ids', true), '')::uuid[], '{}'::uuid[]) $$;

CREATE FUNCTION rmm.is_service() RETURNS boolean
    LANGUAGE sql STABLE
    AS $$ SELECT coalesce(current_setting('rmm.service', true) = 'on', false) $$;

CREATE TABLE tenant.client (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant.site (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id uuid NOT NULL REFERENCES tenant.client (id),
    name      text NOT NULL,
    timezone  text NOT NULL DEFAULT 'UTC'
);
CREATE INDEX site_client_idx ON tenant.site (client_id);

CREATE TABLE tenant.device (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id        uuid NOT NULL REFERENCES tenant.client (id),
    site_id          uuid NOT NULL REFERENCES tenant.site (id),
    hw_fingerprint   bytea NOT NULL,
    fp_strength      text NOT NULL CHECK (fp_strength IN ('strong', 'weak')),
    smbios_uuid      text,
    system_serial    text,
    board_serial     text,
    os_family        text NOT NULL,
    hostname         text NOT NULL,
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending_review', 'flagged')),
    possible_clone_of uuid REFERENCES tenant.device (id),
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_hw_fingerprint_idx ON tenant.device (hw_fingerprint);
CREATE INDEX device_client_idx ON tenant.device (client_id);

CREATE TABLE tenant.agent (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id         uuid NOT NULL REFERENCES tenant.client (id),
    device_id         uuid NOT NULL REFERENCES tenant.device (id),
    credential_pubkey bytea NOT NULL UNIQUE CHECK (octet_length(credential_pubkey) = 32),
    nkey              text NOT NULL UNIQUE,
    version           text NOT NULL,
    status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded', 'revoked', 'suspect_clone')),
    last_seen         timestamptz,
    enrolled_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_device_idx ON tenant.agent (device_id);
CREATE INDEX agent_client_idx ON tenant.agent (client_id);

CREATE TABLE tenant.enrollment_token (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id      uuid NOT NULL REFERENCES tenant.client (id),
    site_id        uuid NOT NULL REFERENCES tenant.site (id),
    token_hash     bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at     timestamptz NOT NULL,
    max_uses       int NOT NULL CHECK (max_uses > 0),
    uses           int NOT NULL DEFAULT 0 CHECK (uses >= 0),
    allow_reattach boolean NOT NULL DEFAULT false,
    revoked        boolean NOT NULL DEFAULT false,
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrollment_token_client_idx ON tenant.enrollment_token (client_id);

CREATE TABLE msp.trust_artifact (
    kind        text NOT NULL CHECK (kind IN ('manifest', 'revocations', 'techlist')),
    seq         bigint NOT NULL,
    content_id  bytea NOT NULL,
    envelope    bytea NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    uploaded_by text NOT NULL,
    PRIMARY KEY (kind, seq)
);

CREATE TABLE msp.audit_event (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    actor     text NOT NULL,
    action    text NOT NULL,
    client_id uuid,
    target    text NOT NULL,
    detail    jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE FUNCTION msp.audit_event_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN RAISE EXCEPTION 'msp.audit_event is append-only'; END $$;

CREATE TRIGGER audit_event_no_update
    BEFORE UPDATE OR DELETE ON msp.audit_event
    FOR EACH ROW EXECUTE FUNCTION msp.audit_event_immutable();
CREATE TRIGGER audit_event_no_truncate
    BEFORE TRUNCATE ON msp.audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION msp.audit_event_immutable();

-- Row level security: enforced even for the table owner.
ALTER TABLE tenant.client ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.client FORCE ROW LEVEL SECURITY;
CREATE POLICY client_scope ON tenant.client
    USING (id = ANY (rmm.scope()) OR rmm.is_service())
    WITH CHECK (id = ANY (rmm.scope()) OR rmm.is_service());

ALTER TABLE tenant.site ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.site FORCE ROW LEVEL SECURITY;
CREATE POLICY site_scope ON tenant.site
    USING (client_id = ANY (rmm.scope()) OR rmm.is_service())
    WITH CHECK (client_id = ANY (rmm.scope()) OR rmm.is_service());

ALTER TABLE tenant.device ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.device FORCE ROW LEVEL SECURITY;
CREATE POLICY device_scope ON tenant.device
    USING (client_id = ANY (rmm.scope()) OR rmm.is_service())
    WITH CHECK (client_id = ANY (rmm.scope()) OR rmm.is_service());

ALTER TABLE tenant.agent ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.agent FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_scope ON tenant.agent
    USING (client_id = ANY (rmm.scope()) OR rmm.is_service())
    WITH CHECK (client_id = ANY (rmm.scope()) OR rmm.is_service());

ALTER TABLE tenant.enrollment_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.enrollment_token FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_token_scope ON tenant.enrollment_token
    USING (client_id = ANY (rmm.scope()) OR rmm.is_service())
    WITH CHECK (client_id = ANY (rmm.scope()) OR rmm.is_service());

-- Roles (cluster-wide, so created idempotently and race-safe).
DO $$
BEGIN
    BEGIN
        CREATE ROLE rmm_api NOLOGIN NOSUPERUSER NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END;
    BEGIN
        CREATE ROLE rmm_authd NOLOGIN NOSUPERUSER NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END;
END
$$;

GRANT USAGE ON SCHEMA rmm, tenant, msp TO rmm_api, rmm_authd;

GRANT SELECT, INSERT, UPDATE ON
    tenant.client, tenant.site, tenant.device, tenant.agent, tenant.enrollment_token
    TO rmm_api;
GRANT SELECT, INSERT ON msp.trust_artifact TO rmm_api;
GRANT INSERT ON msp.audit_event TO rmm_api;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA msp, tenant TO rmm_api, rmm_authd;

GRANT SELECT ON tenant.client, tenant.device, tenant.agent TO rmm_authd;
GRANT UPDATE (last_seen) ON tenant.agent TO rmm_authd;
GRANT SELECT ON msp.trust_artifact TO rmm_authd;
GRANT INSERT ON msp.audit_event TO rmm_authd;
