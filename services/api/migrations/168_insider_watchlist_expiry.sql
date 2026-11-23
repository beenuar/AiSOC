-- 168: the insider watchlist becomes a control instead of a checkbox.
--
-- `user_risk_profiles.is_watchlisted` has existed since migration 014 and the
-- console wrote it — and that was the whole feature. Nothing consumed the
-- flag (no elevation, no expiry, no review), so watchlisting a departing
-- employee changed nothing anywhere. Three schema changes make the halves
-- real; the behaviour lives in `app/services/insider_watchlist.py`.
--
-- 1. Expiry on the watchlist row. A watchlist is never indefinite: the
--    service refuses a new row without a future `watchlist_expires_at`, and
--    the sweep worker flips expired rows off. Legacy watchlisted rows (if
--    any) are backfilled with a 90-day horizon rather than letting the
--    absence of a column keep meaning "forever".
--
-- 2. A machine-owned rule document beside the analyst's. Elevation reuses
--    the existing business-context path (same engine, same application point
--    in the auto-triage worker) — but `yaml_text` is the analyst's verbatim
--    artifact, kept unparsed so their comments and ordering round-trip. A
--    console save must never clobber machine rules and a watchlist change
--    must never clobber analyst comments, so the managed rules get their own
--    column. The applier parses both and concatenates.
--
-- 3. A per-tenant policy row for the HR door, default OFF: watching the HR
--    store (`workforce_members`, migration 131) and auto-watchlisting
--    departing members is automation a tenant opts into.

-- lane allocation: migration 168 (orchestrator lane)

-- ── 1. expiry + source on the profile row ──────────────────────────────────

ALTER TABLE user_risk_profiles
    ADD COLUMN IF NOT EXISTS watchlist_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS watchlist_source VARCHAR(20) NOT NULL DEFAULT 'manual';

-- Two doors only. A CHECK rather than an enum type: the vocabulary is tiny
-- and a bad value should be a write error naming the column.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'user_risk_profiles_watchlist_source_check'
    ) THEN
        ALTER TABLE user_risk_profiles
            ADD CONSTRAINT user_risk_profiles_watchlist_source_check
            CHECK (watchlist_source IN ('manual', 'hr_sync'));
    END IF;
END $$;

-- Backfill: any row watchlisted before this migration had no expiry at all.
-- 90 days from now, not from `watchlisted_at` — a row listed eight months
-- ago would otherwise expire retroactively the moment the sweep first runs,
-- silently dropping elevation nobody decided to drop.
UPDATE user_risk_profiles
SET watchlist_expires_at = NOW() + INTERVAL '90 days'
WHERE is_watchlisted = TRUE AND watchlist_expires_at IS NULL;

COMMENT ON COLUMN user_risk_profiles.watchlist_expires_at IS
    'When this watchlist row stops elevating. Required on every new row — '
    'a watchlist is never indefinite. The sweep worker flips expired rows.';
COMMENT ON COLUMN user_risk_profiles.watchlist_source IS
    'Which door listed this identity: ''manual'' (console, reason required) '
    'or ''hr_sync'' (the HR store said they are leaving).';

-- The sweep's scan: watchlisted rows and their deadlines.
CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_watchlist_expiry
    ON user_risk_profiles (watchlist_expires_at)
    WHERE is_watchlisted;

-- ── 2. the machine-owned half of the rule set ──────────────────────────────

ALTER TABLE aisoc_business_context_rule_sets
    ADD COLUMN IF NOT EXISTS managed_yaml TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN aisoc_business_context_rule_sets.managed_yaml IS
    'Machine-managed rules (insider watchlist elevation), regenerated whole '
    'on every watchlist change. Never hand-edited; never touched by the '
    'console save path, which owns yaml_text. The triage applier parses '
    'both documents and applies the union.';

-- ── 3. the HR door, per tenant, default off ────────────────────────────────

CREATE TABLE IF NOT EXISTS insider_watchlist_policies (
    tenant_id           UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- Watching the HR store and auto-watchlisting is automation the tenant
    -- opts into; a fresh row (and an absent row) means OFF.
    hr_sync_enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Days of elevation a manual watchlist gets when the console does not
    -- pick a date explicitly.
    default_expiry_days INTEGER     NOT NULL DEFAULT 30
        CHECK (default_expiry_days BETWEEN 1 AND 365),
    -- Elevation continues this many days past a departing member's last day.
    hr_grace_days       INTEGER     NOT NULL DEFAULT 14
        CHECK (hr_grace_days BETWEEN 1 AND 90),
    -- How far back the departure review looks.
    lookback_days       INTEGER     NOT NULL DEFAULT 30
        CHECK (lookback_days BETWEEN 1 AND 90),
    updated_by          UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE insider_watchlist_policies IS
    'Per-tenant insider-watchlist policy. hr_sync_enabled gates the HR door '
    '(workforce_members -> auto-watchlist); everything is off until a row '
    'says otherwise.';

-- RLS, mirroring triage_questions (154): the API writes under a bound
-- tenant GUC; the sweep worker reads every opted-in tenant under no GUC,
-- so the unbound arm is load-bearing in both expressions.
ALTER TABLE insider_watchlist_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE insider_watchlist_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS insider_watchlist_policies_tenant ON insider_watchlist_policies;
CREATE POLICY insider_watchlist_policies_tenant ON insider_watchlist_policies
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON insider_watchlist_policies TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     ALTER TABLE user_risk_profiles
--         DROP CONSTRAINT IF EXISTS user_risk_profiles_watchlist_source_check,
--         DROP COLUMN IF EXISTS watchlist_expires_at,
--         DROP COLUMN IF EXISTS watchlist_source;
--     ALTER TABLE aisoc_business_context_rule_sets DROP COLUMN IF EXISTS managed_yaml;
--     DROP TABLE IF EXISTS insider_watchlist_policies;
--
-- Dropping managed_yaml withdraws every managed elevation at once; the
-- authored yaml_text is untouched either way.
