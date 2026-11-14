-- Migration 012: MSSP parent-tenant console
-- Adds parent_tenant_id to support MSSP hierarchies (parent manages multiple child tenants).
-- Also adds tenant-level rollup metrics view used by the MSSP console.

BEGIN;

-- 1. Parent-tenant relationship -----------------------------------------------
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS parent_tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS mssp_role TEXT NOT NULL DEFAULT 'standalone'
        CHECK (mssp_role IN ('standalone', 'parent', 'child'));

CREATE INDEX IF NOT EXISTS idx_tenants_parent ON tenants (parent_tenant_id)
    WHERE parent_tenant_id IS NOT NULL;

-- 2. MSSP console cross-tenant notes / annotations ----------------------------
CREATE TABLE IF NOT EXISTS mssp_tenant_notes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    child_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    body        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mssp_notes_parent ON mssp_tenant_notes (parent_id);
CREATE INDEX IF NOT EXISTS idx_mssp_notes_child  ON mssp_tenant_notes (child_id);

-- 3. Cross-tenant delegation grants -------------------------------------------
-- Allows a parent-tenant user to act on behalf of a child tenant
-- without sharing credentials.
CREATE TABLE IF NOT EXISTS mssp_delegations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    child_tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    granted_role     TEXT NOT NULL DEFAULT 'soc_analyst',
    granted_by_user  UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at       TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (parent_tenant_id, child_tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_mssp_del_parent ON mssp_delegations (parent_tenant_id);
CREATE INDEX IF NOT EXISTS idx_mssp_del_child  ON mssp_delegations (child_tenant_id);

-- 4. Rollup metrics snapshot (written by the agents service every 15 min) -----
CREATE TABLE IF NOT EXISTS mssp_tenant_metrics (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    open_alerts     INT NOT NULL DEFAULT 0,
    critical_alerts INT NOT NULL DEFAULT 0,
    open_cases      INT NOT NULL DEFAULT 0,
    mttr_minutes    FLOAT,          -- mean time-to-resolve (last 24 h)
    sla_breaches    INT NOT NULL DEFAULT 0,
    connector_count INT NOT NULL DEFAULT 0,
    health_score    FLOAT,          -- 0.0–1.0 composite
    raw_data        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_mssp_metrics_tenant_ts
    ON mssp_tenant_metrics (tenant_id, snapshot_at DESC);

-- Latest snapshot per tenant (used by the console overview)
CREATE OR REPLACE VIEW mssp_tenant_latest_metrics AS
SELECT DISTINCT ON (tenant_id) *
FROM mssp_tenant_metrics
ORDER BY tenant_id, snapshot_at DESC;

COMMIT;
