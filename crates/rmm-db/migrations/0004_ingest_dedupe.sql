-- Durable ingest dedupe: every inventory and metric msg_id that was written is
-- recorded in the same transaction, so a redelivery (lost ack, agent re-send
-- after an outage, ingest crash before the ack) is acked without writing again.
-- Rows older than the retention (pruned by ingest) are no longer needed for
-- samples ingest still accepts: the retention (7 days) matches the age beyond
-- which ingest drops samples as samples_dropped. The agent outbox is bounded by
-- rows and bytes, not age, and the stream keeps messages 3 days, so dedupe
-- relies on the 7-day sample window, not on an agent-side age limit.

CREATE TABLE ts_private.ingested_msg (
    msg_id      uuid        PRIMARY KEY,
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ingested_msg_received_at_idx ON ts_private.ingested_msg (received_at);

REVOKE ALL ON ts_private.ingested_msg FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON ts_private.ingested_msg TO rmm_ingest;
