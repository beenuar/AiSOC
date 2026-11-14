-- Alert provenance: is this row real telemetry, or did we generate it?
--
-- Until now nothing in the schema answered that question. `alerts` carried
-- ~50 columns describing what happened and none recording where the row came
-- from, so a seeded demo incident and a CrowdStrike detection were
-- indistinguishable once written. The only marker was a `"demo"` string
-- pushed into the `tags` array by some seed paths and not others — and the
-- paths that produced the most realistic-looking incidents were the ones that
-- omitted it.
--
-- That is the wrong way round. Provenance has to be a column, so it survives
-- a query the UI did not anticipate, and it has to default to the honest
-- value: rows written by the real pipeline are not synthetic, and anything
-- that wants to claim otherwise must say so explicitly.
--
-- Note the existing `detection_rules.provenance` JSONB means something
-- different (which Sigma repo a rule was imported from). This is about the
-- alert row, not the rule.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS is_synthetic BOOLEAN NOT NULL DEFAULT FALSE,
    -- Free-form, e.g. 'seed_demo', 'demo-producer', 'golden-pipeline'.
    -- NULL for real telemetry.
    ADD COLUMN IF NOT EXISTS synthetic_source TEXT,
    -- Which scenario produced it, when the generator has scenarios. Lets a
    -- reviewer clear one scenario's rows without touching another's.
    ADD COLUMN IF NOT EXISTS synthetic_scenario TEXT;

COMMENT ON COLUMN alerts.is_synthetic IS
    'TRUE when this alert was generated (seed, demo producer, test fixture) rather than ingested from a real sensor. Defaults FALSE so the real pipeline is never mislabelled.';
COMMENT ON COLUMN alerts.synthetic_source IS
    'Generator that produced a synthetic alert (seed_demo, demo-producer, golden-pipeline). NULL for real telemetry.';
COMMENT ON COLUMN alerts.synthetic_scenario IS
    'Scenario identifier within the generator, when it has one.';

-- Partial index: the common query is "show me only the real alerts", and the
-- synthetic rows are the minority, so indexing just those keeps it small.
CREATE INDEX IF NOT EXISTS idx_alerts_is_synthetic
    ON alerts (tenant_id, is_synthetic)
    WHERE is_synthetic = TRUE;
