-- the hypothesis scheduler's per-tenant switch, cadence and budget.
--
-- Three deterministic schedulers already run (saved-hunt cron, corpus
-- cadence, retro-hunts); none SELECTS hypotheses or dispatches the LLM hunt
-- agent. This table is the selection layer's configuration: a tenant turns
-- campaigns on (default OFF — an LLM agent asking questions of the estate
-- on a schedule is automation a tenant opts into), sets a cadence and a
-- budget, and the scheduler records every selection with its reason.
--
-- `hunt_source_reports` (migration 155) also gains `campaigned_at`: an
-- APPROVED hunt request is a selection source, and a request that already
-- launched a campaign must not launch one per tick.

-- lane allocation: migration 179

CREATE TABLE IF NOT EXISTS hunt_campaign_policies (
    tenant_id       UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled         BOOLEAN     NOT NULL DEFAULT FALSE,
    cadence_minutes INTEGER     NOT NULL DEFAULT 1440
        CHECK (cadence_minutes BETWEEN 60 AND 10080),
    -- Per-campaign budgets, validated by the agents service against its own
    -- CampaignBudgets shape; absent keys mean its defaults.
    budgets         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- How many campaigns one tick may launch for this tenant.
    max_per_tick    INTEGER     NOT NULL DEFAULT 2 CHECK (max_per_tick BETWEEN 1 AND 10),
    last_run_at     TIMESTAMPTZ,
    updated_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE hunt_campaign_policies IS
    'Per-tenant hypothesis-scheduler policy. Off until a row enables '
    'it; every selection the scheduler makes is recorded with its reason.';

ALTER TABLE hunt_source_reports
    ADD COLUMN IF NOT EXISTS campaigned_at TIMESTAMPTZ;

COMMENT ON COLUMN hunt_source_reports.campaigned_at IS
    'When the scheduler launched a campaign from this approved request; one '
    'request launches one campaign.';

ALTER TABLE hunt_campaign_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE hunt_campaign_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS hunt_campaign_policies_tenant ON hunt_campaign_policies;
CREATE POLICY hunt_campaign_policies_tenant ON hunt_campaign_policies
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON hunt_campaign_policies TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS hunt_campaign_policies;
--     ALTER TABLE hunt_source_reports DROP COLUMN IF EXISTS campaigned_at;
