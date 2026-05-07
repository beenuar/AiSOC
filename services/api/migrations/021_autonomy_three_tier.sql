-- migrations/021_autonomy_three_tier.sql
-- Tier-1 capability 1.3: configurable autonomy guardrails — three-tier
-- thresholds (auto / review / escalation) per (tenant_id, action_name).
--
-- The previous shape (`min_confidence` only) is preserved so existing
-- writers keep working; the new columns are NULLable and the agent code
-- derives missing tiers via the same `_make_thresholds` helper used for
-- YAML overrides:
--
--   review     ≈ auto - 0.10
--   escalation ≈ review - 0.20
--
-- A successful three-tier write must satisfy
-- ``escalation <= review <= auto``. We add a CHECK so a buggy admin UI
-- can't push an inverted policy that would silently broaden autonomy.

ALTER TABLE aisoc_autonomy_thresholds
    ADD COLUMN IF NOT EXISTS review_confidence DOUBLE PRECISION
        CHECK (review_confidence IS NULL OR review_confidence BETWEEN 0 AND 1),
    ADD COLUMN IF NOT EXISTS escalation_confidence DOUBLE PRECISION
        CHECK (escalation_confidence IS NULL OR escalation_confidence BETWEEN 0 AND 1);

-- Drop and re-add the ordering constraint so re-running this migration is safe.
ALTER TABLE aisoc_autonomy_thresholds
    DROP CONSTRAINT IF EXISTS aisoc_autonomy_thresholds_ordered_chk;

ALTER TABLE aisoc_autonomy_thresholds
    ADD CONSTRAINT aisoc_autonomy_thresholds_ordered_chk
    CHECK (
        (review_confidence IS NULL OR review_confidence <= min_confidence)
        AND (
            escalation_confidence IS NULL
            OR review_confidence IS NULL
            OR escalation_confidence <= review_confidence
        )
    );

-- Audit columns — useful for the admin UI's "last changed by" affordance.
ALTER TABLE aisoc_autonomy_thresholds
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'admin_ui',
    ADD COLUMN IF NOT EXISTS reason TEXT;

COMMENT ON COLUMN aisoc_autonomy_thresholds.min_confidence IS
    'Auto-execute floor (legacy column name). Maps to ActionThresholds.auto.';
COMMENT ON COLUMN aisoc_autonomy_thresholds.review_confidence IS
    'Floor for analyst-review band. NULL = derive as auto - 0.1.';
COMMENT ON COLUMN aisoc_autonomy_thresholds.escalation_confidence IS
    'Floor for senior-on-call escalation. NULL = derive as review - 0.2.';
COMMENT ON COLUMN aisoc_autonomy_thresholds.source IS
    'Where this override came from: admin_ui | api | ops_script.';
