-- Telemetry: typed inventory columns, device events, the metrics hypertable,
-- the scoped metrics view, ingest/service roles and role-gated RLS bypass.

ALTER TABLE tenant.device
    ADD COLUMN os_version        text,
    ADD COLUMN cpu_model         text,
    ADD COLUMN cpu_cores         int,
    ADD COLUMN ram_bytes         bigint,
    ADD COLUMN disk_total_bytes  bigint,
    ADD COLUMN disk_free_bytes   bigint,
    ADD COLUMN last_boot         timestamptz,
    ADD COLUMN inventory         jsonb,
    ADD COLUMN inventory_hash    bytea,
    ADD COLUMN inventory_at      timestamptz;

CREATE TABLE tenant.device_event (
    id        bigserial PRIMARY KEY,
    client_id uuid NOT NULL REFERENCES tenant.client (id),
    device_id uuid NOT NULL REFERENCES tenant.device (id),
    at        timestamptz NOT NULL DEFAULT now(),
    type      text NOT NULL,
    before    jsonb,
    after     jsonb
);
CREATE INDEX device_event_device_at_idx ON tenant.device_event (device_id, at DESC);

CREATE FUNCTION tenant.device_event_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN RAISE EXCEPTION 'tenant.device_event is append-only'; END $$;

CREATE TRIGGER device_event_no_update
    BEFORE UPDATE OR DELETE ON tenant.device_event
    FOR EACH ROW EXECUTE FUNCTION tenant.device_event_immutable();
CREATE TRIGGER device_event_no_truncate
    BEFORE TRUNCATE ON tenant.device_event
    FOR EACH STATEMENT EXECUTE FUNCTION tenant.device_event_immutable();

-- Metrics hypertable, not reachable by API roles except through the view.
CREATE TABLE ts_private.metrics (
    time      timestamptz      NOT NULL,
    client_id uuid             NOT NULL,
    device_id uuid             NOT NULL,
    metric    text             NOT NULL,
    value     double precision NOT NULL
);
SELECT create_hypertable('ts_private.metrics', by_range('time', INTERVAL '1 day'));
ALTER TABLE ts_private.metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'client_id, device_id',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('ts_private.metrics', INTERVAL '7 days', if_not_exists => true);
SELECT add_retention_policy('ts_private.metrics', INTERVAL '90 days', if_not_exists => true);
CREATE INDEX metrics_client_device_time_idx ON ts_private.metrics (client_id, device_id, time DESC);

-- No service bypass here: callers only ever see their own clients' samples.
CREATE VIEW tenant.metrics_v WITH (security_barrier) AS
    SELECT time, client_id, device_id, metric, value
    FROM ts_private.metrics
    WHERE client_id = ANY (rmm.scope());

-- Roles.
DO $$
BEGIN
    BEGIN
        CREATE ROLE rmm_ingest NOLOGIN NOSUPERUSER NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END;
    BEGIN
        CREATE ROLE rmm_service NOLOGIN NOSUPERUSER NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END;
END
$$;

GRANT rmm_service TO rmm_api, rmm_authd, rmm_ingest;

-- Row level security: the service bypass needs the GUC and role membership.
ALTER TABLE tenant.device_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant.device_event FORCE ROW LEVEL SECURITY;

DROP POLICY client_scope ON tenant.client;
CREATE POLICY client_scope ON tenant.client
    USING (id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

DROP POLICY site_scope ON tenant.site;
CREATE POLICY site_scope ON tenant.site
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

DROP POLICY device_scope ON tenant.device;
CREATE POLICY device_scope ON tenant.device
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

DROP POLICY agent_scope ON tenant.agent;
CREATE POLICY agent_scope ON tenant.agent
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

DROP POLICY enrollment_token_scope ON tenant.enrollment_token;
CREATE POLICY enrollment_token_scope ON tenant.enrollment_token
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

CREATE POLICY device_event_scope ON tenant.device_event
    USING (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')))
    WITH CHECK (client_id = ANY (rmm.scope()) OR (rmm.is_service() AND pg_has_role(current_user, 'rmm_service', 'MEMBER')));

-- Grants.
REVOKE ALL ON SCHEMA ts_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ts_private FROM PUBLIC;

GRANT USAGE ON SCHEMA rmm, tenant, ts_private TO rmm_ingest;
GRANT SELECT ON tenant.agent, tenant.device TO rmm_ingest;
GRANT UPDATE (last_seen) ON tenant.agent TO rmm_ingest;
GRANT UPDATE (os_version, cpu_model, cpu_cores, ram_bytes, disk_total_bytes,
              disk_free_bytes, last_boot, inventory, inventory_hash, inventory_at)
    ON tenant.device TO rmm_ingest;
GRANT INSERT ON tenant.device_event TO rmm_ingest;
GRANT INSERT ON ts_private.metrics TO rmm_ingest;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA tenant TO rmm_ingest, rmm_api;

GRANT SELECT ON tenant.device_event TO rmm_api;
GRANT SELECT ON tenant.metrics_v TO rmm_api;
