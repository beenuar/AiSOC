-- Migration 019: Auto-generated board / executive reports
-- Stores scheduled report definitions and generated report artefacts.

BEGIN;

-- 1. Report template definitions -------------------------------------------------
CREATE TABLE IF NOT EXISTS report_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    report_type     TEXT NOT NULL CHECK (report_type IN (
                        'board_summary', 'executive_monthly', 'soc_weekly',
                        'compliance_quarterly', 'incident_postmortem', 'custom'
                    )),
    -- schedule in cron syntax (UTC). NULL means on-demand only.
    cron_schedule   TEXT,
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    -- content config
    sections        JSONB NOT NULL DEFAULT '[]',  -- ordered list of section configs
    recipients      TEXT[],                        -- email addresses
    output_format   TEXT NOT NULL DEFAULT 'pdf'
                        CHECK (output_format IN ('pdf', 'html', 'json')),
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_rpt_template_tenant ON report_templates (tenant_id);

-- 2. Generated report artefacts --------------------------------------------------
CREATE TABLE IF NOT EXISTS report_artefacts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id     UUID REFERENCES report_templates(id) ON DELETE SET NULL,
    report_type     TEXT NOT NULL,
    title           TEXT NOT NULL,
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    output_format   TEXT NOT NULL DEFAULT 'pdf',
    -- storage: content stored as base64 in body_b64 for small reports,
    -- or as an object-store key in storage_key for large ones.
    body_b64        TEXT,
    storage_key     TEXT,
    file_size_bytes BIGINT,
    -- structured data snapshot for re-rendering or API consumers
    data_snapshot   JSONB NOT NULL DEFAULT '{}',
    -- delivery
    delivered_to    TEXT[],
    delivered_at    TIMESTAMPTZ,
    generated_by    TEXT NOT NULL DEFAULT 'system',
    -- status
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','generating','completed','failed')),
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rpt_artefact_tenant   ON report_artefacts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rpt_artefact_template ON report_artefacts (template_id);
CREATE INDEX IF NOT EXISTS idx_rpt_artefact_status   ON report_artefacts (tenant_id, status);

-- 3. Updated-at trigger ----------------------------------------------------------
CREATE OR REPLACE FUNCTION update_rpt_template_ts()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_rpt_template_ts ON report_templates;
CREATE TRIGGER trg_rpt_template_ts
    BEFORE UPDATE ON report_templates
    FOR EACH ROW EXECUTE FUNCTION update_rpt_template_ts();

COMMIT;
