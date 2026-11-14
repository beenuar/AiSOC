-- Migration 007: MTTD/MTTR/MTTC SLA tracking
-- Adds tenant_sla_config and alert_sla_events tables

BEGIN;

-- Per-tenant SLA configuration
CREATE TABLE IF NOT EXISTS tenant_sla_config (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    severity    TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    mttd_target INTEGER NOT NULL DEFAULT 60,    -- minutes: mean time to detect
    mttr_target INTEGER NOT NULL DEFAULT 240,   -- minutes: mean time to respond/resolve
    mttc_target INTEGER NOT NULL DEFAULT 480,   -- minutes: mean time to close
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, severity)
);

-- Alert SLA lifecycle events (immutable)
CREATE TABLE IF NOT EXISTS alert_sla_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    alert_id    UUID NOT NULL,
    severity    TEXT NOT NULL,
    event_type  TEXT NOT NULL CHECK (event_type IN ('detected','acknowledged','resolved','closed')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id    UUID,
    metadata    JSONB NOT NULL DEFAULT '{}'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sla_config_tenant   ON tenant_sla_config(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sla_events_tenant   ON alert_sla_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sla_events_alert    ON alert_sla_events(alert_id);
CREATE INDEX IF NOT EXISTS idx_sla_events_type     ON alert_sla_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sla_events_time     ON alert_sla_events(occurred_at DESC);

-- RLS: tenants see only their own data
ALTER TABLE tenant_sla_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_sla_events  ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'tenant_sla_config' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON tenant_sla_config
            USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'alert_sla_events' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON alert_sla_events
            USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
    END IF;
END
$$;

-- Seed default SLA targets
INSERT INTO tenant_sla_config (tenant_id, severity, mttd_target, mttr_target, mttc_target)
SELECT t.id, s.severity, s.mttd, s.mttr, s.mttc
FROM tenants t
CROSS JOIN (
    VALUES
        ('critical', 15,  60,  120),
        ('high',     30, 120,  240),
        ('medium',   60, 240,  480),
        ('low',     120, 480, 1440)
) AS s(severity, mttd, mttr, mttc)
ON CONFLICT (tenant_id, severity) DO NOTHING;

COMMIT;
