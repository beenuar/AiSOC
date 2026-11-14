-- 046_detection_rules_cases_schema_drift_fix.sql
--
-- Reconcile the `detection_rules` and `cases` tables with the ORM models in
--   services/api/app/models/detection_rule.py
--   services/api/app/models/case.py
--
-- Why this exists (issue #492)
-- ────────────────────────────
-- docker-compose.yml mounts services/api/migrations into
-- /docker-entrypoint-initdb.d, so on a fresh compose install Postgres builds
-- the schema from 001_init.sql onward. That lineage created `detection_rules`
-- in its *pre-refactor* shape (rule_type, rule_content, hit_count, last_hit_at)
-- and never gained the columns the current DetectionRule model queries
-- (rule_language, rule_body, category, status, confidence, fp_rate,
-- suppression_config, threshold_config, total_hits, last_triggered,
-- is_builtin, created_by_id). The result is a 500 out of the box on any
-- endpoint that touches the table (e.g. GET /api/v1/detection/tuning):
--
--   asyncpg.exceptions.UndefinedColumnError:
--   column detection_rules.rule_language does not exist
--
-- `cases` has the same divergence: the Case model (and the demo seed) use
-- `resolution` and `lessons_learned`, neither of which the 001 lineage
-- created — so `python -m app.scripts.seed_demo` fails with:
--
--   UndefinedColumnError: column "resolution" of relation "cases" does not exist
--
-- 036_detection_rule_provenance.sql already reconciled the single `provenance`
-- column across both lineages; this migration finishes the job for the rest.
--
-- Dual-lineage safety (mirrors the 036 rationale)
-- ───────────────────────────────────────────────
-- Two code paths reach this table and both must survive re-running:
--   * Dev installs that bootstrap via SQLAlchemy `Base.metadata.create_all`
--     already have the model's columns — every `ADD COLUMN IF NOT EXISTS`
--     below is a no-op, and the guarded legacy fix-ups are skipped because
--     the legacy columns don't exist.
--   * Legacy / compose installs that originated from 001_init.sql get the
--     missing columns added without touching the legacy rule_type/rule_content
--     columns, plus a NULL-tolerant backfill so existing rows stay usable.
-- All clauses are idempotent, so the migration is safe on partially-migrated
-- environments too.

BEGIN;

-- ── detection_rules: add the columns the current model selects ──────────────
-- Added NULL-able (no NOT NULL) so the migration tolerates a populated legacy
-- table; the ORM always supplies these on INSERT. Stats/flags carry the same
-- defaults as the model so pre-existing legacy rows read back sensibly.
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_language      VARCHAR(30);
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_body          TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS category           VARCHAR(100);
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS status             VARCHAR(20)      DEFAULT 'testing';
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS confidence         INTEGER          DEFAULT 50;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS fp_rate            DOUBLE PRECISION DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS suppression_config JSONB   NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS threshold_config   JSONB   NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS total_hits         BIGINT           DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS last_triggered     TIMESTAMPTZ;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS is_builtin         BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS created_by_id      UUID;

CREATE INDEX IF NOT EXISTS idx_rules_category ON detection_rules(category);
CREATE INDEX IF NOT EXISTS idx_rules_status   ON detection_rules(status);

-- Legacy-lineage fix-ups. Only meaningful where the pre-refactor columns still
-- exist; on the create_all lineage the guarded block is a no-op.
DO $$
BEGIN
    -- Preserve existing rule content under the new column names so legacy rows
    -- remain readable/editable through the current model instead of surfacing
    -- as blank rules.
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'rule_content'
    ) THEN
        UPDATE detection_rules SET rule_body = rule_content
        WHERE rule_body IS NULL AND rule_content IS NOT NULL;

        -- The current model never writes rule_content, so its legacy NOT NULL
        -- constraint would reject every insert through the ORM.
        ALTER TABLE detection_rules ALTER COLUMN rule_content DROP NOT NULL;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'rule_type'
    ) THEN
        UPDATE detection_rules SET rule_language = rule_type
        WHERE rule_language IS NULL AND rule_type IS NOT NULL;
    END IF;
END $$;

-- `category` is NOT NULL in the model; give any pre-existing (or legacy) rows a
-- placeholder rather than leaving NULLs the read path doesn't expect.
UPDATE detection_rules SET category = 'uncategorized' WHERE category IS NULL;

-- ── cases: add the columns the current model uses ───────────────────────────
ALTER TABLE cases ADD COLUMN IF NOT EXISTS resolution      TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS lessons_learned TEXT;

COMMIT;
