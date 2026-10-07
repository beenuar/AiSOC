-- 097_outbound_webhooks.sql — signed outbound event webhooks, their retries
-- and the dead letters nobody could see.
--
-- Depth plan 5.2. AiSOC can be told things (`/v1/inbox/{token}`, the ITSM
-- webhook) and could not tell anybody anything: there was no outbound event
-- webhook in the tree at all, so a tenant wanting an alert in their own
-- system had to poll the API.
--
-- Two tables, because they answer different questions
-- ---------------------------------------------------
-- `aisoc_outbound_webhooks` is configuration: where to send, what to send,
-- and the shared secret the signature is computed with. One row per
-- destination, and `enabled` defaults FALSE for the same reason every
-- outbound surface in this wave does.
--
-- `aisoc_outbound_deliveries` is history: one row per attempt-set, carrying
-- the payload, the attempt count, the next due time and the last response.
-- It is the retry queue *and* the dead-letter view, because they are the
-- same rows at different points on one ladder — a separate dead-letter
-- table would mean a row moving between them, which is a window where a
-- delivery is in neither.
--
-- Why the payload is stored and not recomputed
-- --------------------------------------------
-- A retry must send what the first attempt sent. Recomputing from the
-- source row would silently change the body between attempts — an alert
-- re-serialised after triage has a different verdict — and the signature
-- covers the body, so the receiver would see two differently-signed
-- messages claiming to be the same event.
--
-- Why the secret is a vault token and the signature is HMAC-SHA256
-- ----------------------------------------------------------------
-- The receiver has to be able to prove the message came from this
-- deployment and was not modified. HMAC over the raw body with a shared
-- secret is what every webhook sender a SOC already integrates uses
-- (Stripe, GitHub, Slack), so the verifying code on the other side is one
-- they have written before.
--
-- Reversible: DROP TABLE IF EXISTS, children first.

CREATE TABLE IF NOT EXISTS aisoc_outbound_webhooks (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    name            TEXT        NOT NULL,
    url             TEXT        NOT NULL,

    -- Which events this destination wants. Empty means every event, which
    -- is the only sensible reading of "subscribed to nothing in
    -- particular" for a destination somebody deliberately created.
    event_types     TEXT[]      NOT NULL DEFAULT '{}',

    -- `vault:` token. The signing secret never sits here in clear, and the
    -- API never returns it: rotation issues a new one rather than showing
    -- the old one, the same rule the connector wizard follows.
    secret          TEXT        NOT NULL DEFAULT '',

    enabled         BOOLEAN     NOT NULL DEFAULT FALSE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS aisoc_outbound_webhooks_tenant
    ON aisoc_outbound_webhooks (tenant_id);

CREATE TABLE IF NOT EXISTS aisoc_outbound_deliveries (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    webhook_id      UUID        NOT NULL REFERENCES aisoc_outbound_webhooks(id) ON DELETE CASCADE,

    event_type      TEXT        NOT NULL,
    -- The exact body the first attempt sent. See the header: a retry that
    -- re-serialises is a different message under the same event id.
    payload         JSONB       NOT NULL DEFAULT '{}'::jsonb,

    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'delivered', 'failed', 'dead')),

    attempts        INTEGER     NOT NULL DEFAULT 0,
    -- NULL once the delivery reaches a terminal state, so the worker's
    -- "what is due" query cannot pick up something it has finished with.
    next_attempt_at TIMESTAMPTZ,

    last_status_code INTEGER,
    last_error      TEXT        NOT NULL DEFAULT '',

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at    TIMESTAMPTZ
);

-- The worker's query. Partial on `pending`, because delivered rows
-- accumulate and a scan whose cost grows with history rather than with
-- work is a scheduler that gets slower every week.
CREATE INDEX IF NOT EXISTS aisoc_outbound_deliveries_due_idx
    ON aisoc_outbound_deliveries (next_attempt_at)
    WHERE status = 'pending';

-- The dead-letter view's query.
CREATE INDEX IF NOT EXISTS aisoc_outbound_deliveries_dead_idx
    ON aisoc_outbound_deliveries (tenant_id, created_at DESC)
    WHERE status = 'dead';

CREATE INDEX IF NOT EXISTS aisoc_outbound_deliveries_webhook_idx
    ON aisoc_outbound_deliveries (webhook_id, created_at DESC);

COMMENT ON TABLE aisoc_outbound_deliveries IS
    'Retry queue and dead-letter list in one table: the same rows at different points on one '
    'ladder. A separate dead-letter table would mean a row moving between them, which is a '
    'window where a delivery is in neither.';

-- Written out per table rather than looped with `format()`. The loop was
-- shorter and it made the policy invisible to `grep` and to
-- `scripts/check_tenant_query_predicates.py`, which reads migrations to
-- learn which tables carry one — so both tables were graded as having no
-- RLS at all. A control a tool cannot see is a control nobody can audit.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_outbound_webhooks ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_outbound_webhooks FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_outbound_webhooks';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_outbound_webhooks '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    EXECUTE 'ALTER TABLE aisoc_outbound_deliveries ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_outbound_deliveries FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_outbound_deliveries';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_outbound_deliveries '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_outbound_webhooks TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_outbound_deliveries TO aisoc_app';
    END IF;
END
$$;
