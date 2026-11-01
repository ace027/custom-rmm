-- Durable ingest dedupe: every inventory and metric msg_id that was written is
-- recorded in the same transaction, so a redelivery (lost ack, agent re-send
-- after an outage, ingest crash before the ack) is acked without writing again.
-- Rows older than the retention (pruned by ingest) are no longer needed because
-- agents never queue longer than the stream keeps messages.

CREATE TABLE ts_private.ingested_msg (
    msg_id      uuid        PRIMARY KEY,
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ingested_msg_received_at_idx ON ts_private.ingested_msg (received_at);

REVOKE ALL ON ts_private.ingested_msg FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON ts_private.ingested_msg TO rmm_ingest;
