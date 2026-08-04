-- Wave 5 — data lifecycle + self-service pipelines.
--
-- retention_policies: per-tenant retention windows (days) per data class (W5.1).
-- custom_parsers:      per-tenant named transform pipelines — the runtime
--                      custom parser (W5.2), a validated list of transform ops
--                      (W5.3 DSL) applied to reshape events onto OCSF.

CREATE TABLE IF NOT EXISTS retention_policies (
    tenant_id        UUID PRIMARY KEY,
    raw_events_days  INTEGER NOT NULL DEFAULT 90,
    alerts_days      INTEGER NOT NULL DEFAULT 365,
    audit_days       INTEGER NOT NULL DEFAULT 730,
    updated_by       UUID,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS retention_policies_tenant ON retention_policies;
CREATE POLICY retention_policies_tenant ON retention_policies
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE TABLE IF NOT EXISTS custom_parsers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    name         TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'generic',
    transforms   JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_custom_parsers_tenant ON custom_parsers(tenant_id);

ALTER TABLE custom_parsers ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_parsers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS custom_parsers_tenant ON custom_parsers;
CREATE POLICY custom_parsers_tenant ON custom_parsers
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
