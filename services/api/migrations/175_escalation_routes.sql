-- per-tenant escalation routing through the outbound webhooks.
--
-- `services/escalations` watches for unacknowledged critical cases and
-- fires ONE deployment-wide webhook — its own docstring records that
-- "per-tenant routing is exactly what the native outbound-webhook
-- [subsystem] is for", and that subsystem's `enqueue_event` had **no
-- production caller**. This table is the routing half, and the
-- `escalation_router` worker is the first real caller: an overdue case
-- escalates to the destinations ITS tenant configured, filtered by the
-- responsibility matrix's owner for the case's class, with the
-- deployment-wide bridge kept as the operator's own fallback channel.

-- lane allocation: migration 175

CREATE TABLE IF NOT EXISTS escalation_routes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Which party's work this route carries. '*' routes regardless of the
    -- matrix's answer.
    responsibility  TEXT        NOT NULL DEFAULT '*'
        CHECK (responsibility IN ('*', 'provider', 'customer', 'shared')),
    -- Escalate cases at or above this severity.
    min_severity    TEXT        NOT NULL DEFAULT 'high'
        CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    -- Minutes a case may sit unacknowledged before escalating.
    unacked_minutes INTEGER     NOT NULL DEFAULT 30
        CHECK (unacked_minutes BETWEEN 5 AND 1440),
    webhook_id      UUID        NOT NULL REFERENCES aisoc_outbound_webhooks(id) ON DELETE CASCADE,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE escalation_routes IS
    'Per-tenant escalation destinations: overdue cases route to the '
    'tenant''s own outbound webhooks, optionally filtered by the '
    'responsibility matrix''s owner. The deployment-wide escalations bridge '
    'stays as the operator fallback.';

CREATE INDEX IF NOT EXISTS idx_escalation_routes_tenant
    ON escalation_routes (tenant_id) WHERE enabled;

-- Escalation nags: one escalation per case per route, not one per tick.
CREATE TABLE IF NOT EXISTS escalation_nags (
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id         UUID        NOT NULL,
    route_id        UUID        NOT NULL REFERENCES escalation_routes(id) ON DELETE CASCADE,
    escalated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, case_id, route_id)
);

COMMENT ON TABLE escalation_nags IS
    'Dedup ledger for the escalation router: a case escalates once per '
    'route, not once per worker tick.';

ALTER TABLE escalation_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_routes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS escalation_routes_tenant ON escalation_routes;
CREATE POLICY escalation_routes_tenant ON escalation_routes
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE escalation_nags ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_nags FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS escalation_nags_tenant ON escalation_nags;
CREATE POLICY escalation_nags_tenant ON escalation_nags
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON escalation_routes TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON escalation_nags TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS escalation_nags;
--     DROP TABLE IF EXISTS escalation_routes;
--
-- The deployment-wide escalations bridge is untouched either way.
