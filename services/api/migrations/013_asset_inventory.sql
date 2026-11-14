-- Migration 013: Asset inventory + vuln-to-alert correlation
-- Stores discovered assets, vulnerability scan findings, and links them to alerts.

BEGIN;

-- 1. Asset table ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_type      TEXT NOT NULL DEFAULT 'host'
        CHECK (asset_type IN ('host', 'container', 'cloud_resource', 'user_account', 'service', 'network_device', 'domain', 'ip')),
    name            TEXT NOT NULL,
    fqdn            TEXT,
    ip_addresses    TEXT[],
    cloud_provider  TEXT,           -- aws / gcp / azure / other
    cloud_region    TEXT,
    cloud_account   TEXT,
    os              TEXT,
    os_version      TEXT,
    criticality     TEXT NOT NULL DEFAULT 'medium'
        CHECK (criticality IN ('critical', 'high', 'medium', 'low', 'info')),
    tags            TEXT[],
    owner_email     TEXT,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_name   ON assets (tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_assets_fqdn   ON assets (tenant_id, fqdn) WHERE fqdn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_type   ON assets (tenant_id, asset_type);
-- GIN index for fast text-array lookups on ip_addresses and tags
CREATE INDEX IF NOT EXISTS idx_assets_ips    ON assets USING GIN (ip_addresses);
CREATE INDEX IF NOT EXISTS idx_assets_tags   ON assets USING GIN (tags);

-- 2. Vulnerability findings ---------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id          TEXT,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score      FLOAT,
    cvss_vector     TEXT,
    epss_score      FLOAT,         -- Exploit Prediction Scoring System (0-1)
    is_exploited    BOOLEAN NOT NULL DEFAULT false,
    source          TEXT NOT NULL, -- scanner name: tenable / qualys / trivy / etc.
    external_id     TEXT,          -- scanner-native finding ID
    first_found     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_found      TIMESTAMPTZ NOT NULL DEFAULT now(),
    remediated_at   TIMESTAMPTZ,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vulns_tenant  ON asset_vulnerabilities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_vulns_asset   ON asset_vulnerabilities (asset_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve     ON asset_vulnerabilities (cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vulns_sev     ON asset_vulnerabilities (tenant_id, severity);

-- 3. Vuln-to-alert correlation links ------------------------------------------
CREATE TABLE IF NOT EXISTS alert_asset_correlations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id    UUID NOT NULL,        -- FK to alerts.id (no hard FK to avoid cross-schema dep)
    asset_id    UUID REFERENCES assets(id) ON DELETE SET NULL,
    vuln_id     UUID REFERENCES asset_vulnerabilities(id) ON DELETE SET NULL,
    match_field TEXT NOT NULL DEFAULT 'ip',  -- how the link was derived
    confidence  FLOAT NOT NULL DEFAULT 1.0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_aacorel_alert  ON alert_asset_correlations (tenant_id, alert_id);
CREATE INDEX IF NOT EXISTS idx_aacorel_asset  ON alert_asset_correlations (asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_aacorel_vuln   ON alert_asset_correlations (vuln_id)  WHERE vuln_id IS NOT NULL;

-- 4. Trigger to keep assets.updated_at current --------------------------------
CREATE OR REPLACE FUNCTION update_asset_ts()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_asset_ts ON assets;
CREATE TRIGGER trg_asset_ts
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_asset_ts();

COMMIT;
