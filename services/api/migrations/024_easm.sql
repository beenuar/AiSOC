-- Tier 3.6: External Attack Surface Management (EASM) tables.

BEGIN;

-- Enum for externally-discovered asset types.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'external_asset_type') THEN
        CREATE TYPE external_asset_type AS ENUM (
            'domain', 'subdomain', 'ip', 'cert', 'web_service', 'api_endpoint'
        );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS external_assets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_type    external_asset_type NOT NULL,
    value         VARCHAR(512) NOT NULL,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_easm_tenant_type ON external_assets (tenant_id, asset_type);
CREATE INDEX IF NOT EXISTS idx_easm_value       ON external_assets (value);

CREATE UNIQUE INDEX IF NOT EXISTS uq_easm_tenant_type_value
    ON external_assets (tenant_id, asset_type, value);

CREATE TABLE IF NOT EXISTS external_asset_drift (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_asset_id UUID NOT NULL REFERENCES external_assets(id) ON DELETE CASCADE,
    drift_type        VARCHAR(64) NOT NULL,
    details           JSONB NOT NULL DEFAULT '{}'::jsonb,
    detected_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_easm_drift_tenant ON external_asset_drift (tenant_id);
CREATE INDEX IF NOT EXISTS idx_easm_drift_asset  ON external_asset_drift (external_asset_id);

-- RLS (mirrors other tenant-scoped tables).
ALTER TABLE external_assets      ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_asset_drift ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'external_assets' AND policyname = 'easm_tenant_isolation'
    ) THEN
        EXECUTE 'CREATE POLICY easm_tenant_isolation ON external_assets
                 USING (tenant_id = current_setting(''app.current_tenant_id'')::uuid)';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'external_asset_drift' AND policyname = 'easm_drift_tenant_isolation'
    ) THEN
        EXECUTE 'CREATE POLICY easm_drift_tenant_isolation ON external_asset_drift
                 USING (tenant_id = current_setting(''app.current_tenant_id'')::uuid)';
    END IF;
END $$;

COMMIT;
