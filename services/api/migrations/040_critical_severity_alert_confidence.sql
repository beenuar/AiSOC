-- Migration 040: SOC console parity — critical severity tier + alert.confidence
-- Implements W2 (critical severity tier) and W3 (alert-level confidence) from
-- the v1.5 SOC Console Parity plan.
--
-- Changes:
--   1. tenant_sla_config: extend severity CHECK constraint to include 'info'
--      and seed default SLA targets for info-tier alerts. The other tables in
--      the system (alerts, cases, detection_rules) already accept the full
--      5-tier ladder because they use plain VARCHAR(20) without a CHECK
--      constraint.
--   2. alerts: add three new columns to carry the confidence signal that the
--      fusion service computes:
--        - confidence (INTEGER 0-100) — the canonical score the API surfaces
--        - confidence_label (TEXT) — 'high' | 'medium' | 'low' (nullable)
--        - confidence_rationale (JSONB) — structured contribution list
--   3. Backfill: keep existing rows' confidence NULL on purpose — these are
--      legacy alerts created before the fusion service started emitting
--      confidence; downstream code already treats NULL as "unknown".
--
-- Idempotent — safe to re-run.

BEGIN;

-- ──────────────────────────────────────────────────────────────────────────────
-- 1. Extend tenant_sla_config to support 'info' tier
-- ──────────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    legacy_constraint RECORD;
BEGIN
    -- Drop any legacy severity CHECK constraint that does not yet include
    -- 'info'. Migration 007 created the constraint with an auto-generated
    -- name, so we look it up by table + content rather than guess the name.
    -- This stays robust across fresh deploys (where 040 is the first chance
    -- to widen) and re-runs.
    FOR legacy_constraint IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        WHERE t.relname = 'tenant_sla_config'
          AND c.contype = 'c'
          AND pg_get_constraintdef(c.oid) ILIKE '%severity%'
          AND pg_get_constraintdef(c.oid) NOT ILIKE '%info%'
    LOOP
        EXECUTE format(
            'ALTER TABLE tenant_sla_config DROP CONSTRAINT IF EXISTS %I',
            legacy_constraint.conname
        );
    END LOOP;
END
$$;

-- Add the 5-tier constraint with a stable, explicit name so future migrations
-- can target it deterministically.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_tenant_sla_config_severity_v2'
    ) THEN
        ALTER TABLE tenant_sla_config
            ADD CONSTRAINT ck_tenant_sla_config_severity_v2
            CHECK (severity IN ('critical','high','medium','low','info'));
    END IF;
END
$$;

-- Seed info-tier defaults for every existing tenant. Info alerts get the
-- loosest SLA (4h detect, 24h respond, 72h close) — they exist for awareness
-- but never page anyone.
INSERT INTO tenant_sla_config (tenant_id, severity, mttd_target, mttr_target, mttc_target)
SELECT t.id, 'info', 240, 1440, 4320
FROM tenants t
ON CONFLICT (tenant_id, severity) DO NOTHING;

-- ──────────────────────────────────────────────────────────────────────────────
-- 2. Add alerts.confidence, alerts.confidence_label, alerts.confidence_rationale
-- ──────────────────────────────────────────────────────────────────────────────

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS confidence INTEGER,
    ADD COLUMN IF NOT EXISTS confidence_label TEXT,
    ADD COLUMN IF NOT EXISTS confidence_rationale JSONB;

-- Constrain confidence to [0, 100] for any non-NULL value. Legacy rows stay
-- NULL until they're re-fused or re-evaluated.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_alerts_confidence_range'
    ) THEN
        ALTER TABLE alerts
            ADD CONSTRAINT ck_alerts_confidence_range
            CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100));
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_alerts_confidence_label_enum'
    ) THEN
        ALTER TABLE alerts
            ADD CONSTRAINT ck_alerts_confidence_label_enum
            CHECK (confidence_label IS NULL OR confidence_label IN ('high','medium','low'));
    END IF;
END
$$;

-- Index for "show me high-confidence critical alerts" and other filter combos
-- that combine severity + confidence (the bread and butter of the queue
-- workbench in PR-5).
CREATE INDEX IF NOT EXISTS idx_alerts_confidence
    ON alerts(tenant_id, confidence DESC NULLS LAST)
    WHERE confidence IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_severity_confidence
    ON alerts(tenant_id, severity, confidence DESC NULLS LAST);

COMMIT;
