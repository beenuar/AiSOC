-- Remediation phase 4 — a recovery record for a fused alert that was made
-- durable in Postgres but never reached `aisoc.alerts.fused`.
--
-- The window
-- ----------
-- `services/fusion` persists the alert row first and publishes second, so a
-- downstream consumer never sees a row id that does not exist. The publish
-- and the input-offset commit cannot be made atomic, which leaves two
-- orderings:
--
--   * The process dies between the durable row and the publish. The input
--     offset was never committed, Kafka re-delivers, the sink answers a
--     verified DUPLICATE, and the publish is retried. Re-delivery is the
--     recovery and it works.
--
--   * The publish fails until the consumer's retry budget is gone. The
--     message is then dead-lettered and the offset *is* committed, which is
--     correct — a dead letter is a durable capture. But the alert row
--     exists, the offset has moved past the source event, and nothing will
--     ever publish the envelope: a dead letter is a triage record, and
--     nothing re-drives it. That alert sits in Postgres invisible to
--     auto-triage for as long as the row lives.
--
-- This table is the record for the second case. A row is written only once a
-- publish has definitively failed, and always before the consumer is allowed
-- to acknowledge the message.
--
-- Why not a transactional outbox
-- ------------------------------
-- Because the first ordering is already covered by an offset that has not
-- moved. Writing a row for every alert on the happy path — an extra INSERT
-- inside the alert insert's transaction and a DELETE after the ack — would
-- make every alert pay for a window that re-delivery closes for free. The
-- guarantee is stated as at-least-once either way; a transactional outbox
-- would not make it exactly-once, it would only move the duplicate.
--
-- Rows are deleted on delivery rather than flagged, so the table *is* the
-- set of alerts still owing a notification: the backlog is count(*), not a
-- filtered scan over delivery history.

CREATE TABLE IF NOT EXISTS fusion_alert_outbox (
    id              BIGSERIAL PRIMARY KEY,
    -- Carried so the table can be tenant-scoped by the same policy shape as
    -- everything else, and so a per-tenant backlog is answerable.
    tenant_id       UUID NOT NULL,
    -- The durable alerts row this notification is for. Not a foreign key:
    -- retention may purge the alert before a relay that has been down for
    -- days gets to it, and a cascade would silently delete the evidence that
    -- the notification was owed.
    alert_id        UUID NOT NULL,
    topic           TEXT NOT NULL,
    -- The Kafka message key: the canonical alert id, so every republication
    -- lands on one partition and a consumer can collapse duplicates.
    dedupe_key      TEXT NOT NULL,
    -- The fused envelope as it would have been published. Stored whole
    -- rather than rebuilt from the alerts row, because rebuilding it would
    -- re-derive fusion's verdict from a row that no longer carries the
    -- inputs, and a notification that differs from the one that failed is a
    -- different message under the same id.
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Lease, not a lock. A relay that dies mid-publish must not strand the
    -- row behind a connection that is gone; the next replica may claim it
    -- once this passes.
    claimed_until   TIMESTAMPTZ,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT
);

-- One pending notification per alert. A second failure for the same alert
-- bumps `attempts` instead of adding a row, so a long broker outage cannot
-- turn a bounded backlog into an unbounded one.
CREATE UNIQUE INDEX IF NOT EXISTS fusion_alert_outbox_alert_uniq ON fusion_alert_outbox (tenant_id, alert_id);

-- The relay's claim predicate, in the order it reads them.
CREATE INDEX IF NOT EXISTS fusion_alert_outbox_claimable ON fusion_alert_outbox (created_at) WHERE claimed_until IS NULL;

DO $$
BEGIN
    EXECUTE 'ALTER TABLE fusion_alert_outbox ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE fusion_alert_outbox FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON fusion_alert_outbox';
    -- The unbound-session arm is the same shape 079/081/104/114/117/118 use,
    -- and it is load-bearing here rather than inherited: the only writer and
    -- the only reader are fusion's consumer and its relay, both GUC-less
    -- worker sessions that span tenants by construction. Without it the
    -- journal could never be written under the runtime role, and the failure
    -- would look like "no alerts are undelivered".
    EXECUTE
        'CREATE POLICY tenant_isolation ON fusion_alert_outbox '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON fusion_alert_outbox TO aisoc_app';
        -- BIGSERIAL owns a sequence, and INSERT on the table is not INSERT on
        -- its sequence: without this the runtime role can read and delete
        -- rows it can never create.
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE fusion_alert_outbox_id_seq TO aisoc_app';
    END IF;
END
$$;
