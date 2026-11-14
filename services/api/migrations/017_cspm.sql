-- Migration 017: Cloud Security Posture Management (CSPM / KSPM)
-- Stores posture findings, compliance framework mappings, and drift events.

BEGIN;

-- 1. Posture findings (CSPM / KSPM) ---------------------------------------------
CREATE TABLE IF NOT EXISTS posture_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- cloud context
    cloud_provider      TEXT NOT NULL CHECK (cloud_provider IN ('aws','azure','gcp','k8s','other')),
    cloud_account       TEXT,
    cloud_region        TEXT,
    resource_type       TEXT NOT NULL,   -- e.g. 's3_bucket', 'k8s_pod', 'iam_role'
    resource_id         TEXT NOT NULL,
    resource_name       TEXT,
    -- finding details
    rule_id             TEXT NOT NULL,   -- e.g. 'CIS-AWS-1.4', 'NSA-K8S-5.2'
    rule_title          TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL DEFAULT 'medium'
                            CHECK (severity IN ('critical','high','medium','low','info')),
    status              TEXT NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open','resolved','suppressed','investigating')),
    -- compliance framework tags
    frameworks          TEXT[],     -- e.g. ['CIS','SOC2','PCI-DSS']
    control_ids         TEXT[],     -- framework control IDs
    -- evidence
    evidence            JSONB NOT NULL DEFAULT '{}',
    remediation_guide   TEXT,
    auto_remediated     BOOLEAN NOT NULL DEFAULT false,
    -- lifecycle
    first_detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    suppressed_at       TIMESTAMPTZ,
    suppressed_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    suppress_reason     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_posture_tenant    ON posture_findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_posture_status    ON posture_findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_posture_severity  ON posture_findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_posture_resource  ON posture_findings (tenant_id, resource_id);
CREATE INDEX IF NOT EXISTS idx_posture_rule      ON posture_findings (tenant_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_posture_provider  ON posture_findings (tenant_id, cloud_provider);

-- 2. CSPM scan runs --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS posture_scan_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cloud_provider  TEXT NOT NULL,
    cloud_account   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running','completed','failed')),
    findings_total  INT NOT NULL DEFAULT 0,
    findings_new    INT NOT NULL DEFAULT 0,
    findings_closed INT NOT NULL DEFAULT 0,
    error_message   TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scan_tenant ON posture_scan_runs (tenant_id, started_at DESC);

-- 3. Drift snapshots -------------------------------------------------------------
-- Records configuration state at a point in time so we can detect drift.
CREATE TABLE IF NOT EXISTS posture_drift_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    cloud_provider  TEXT NOT NULL,
    change_type     TEXT NOT NULL CHECK (change_type IN ('created','modified','deleted')),
    attribute_path  TEXT NOT NULL,
    old_value       TEXT,
    new_value       TEXT,
    severity        TEXT NOT NULL DEFAULT 'medium',
    linked_finding  UUID REFERENCES posture_findings(id) ON DELETE SET NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_drift_tenant   ON posture_drift_events (tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_drift_resource ON posture_drift_events (tenant_id, resource_id);

-- 4. Updated-at trigger ----------------------------------------------------------
CREATE OR REPLACE FUNCTION update_posture_ts()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_posture_ts ON posture_findings;
CREATE TRIGGER trg_posture_ts
    BEFORE UPDATE ON posture_findings
    FOR EACH ROW EXECUTE FUNCTION update_posture_ts();

COMMIT;
