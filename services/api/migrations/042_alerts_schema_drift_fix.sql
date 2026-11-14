-- 042_alerts_schema_drift_fix.sql
--
-- Bring the `alerts` table in line with the ORM model defined in
-- services/api/app/models/alert.py.
--
-- The model has accumulated columns over time (entity denormalization,
-- assignment, merge/parent-child relationships, enrichment, tags) that
-- were declared in code but never added to the schema via a migration.
-- That gap surfaced during the v7.3.0 founder-flow smoke test: a fresh
-- `aisoc serve` + `aisoc db upgrade` brings the stack up cleanly, but
-- `GET /api/v1/alerts` returns 500 because asyncpg can't find
-- `alerts.affected_ips`, `alerts.tags`, etc.
--
-- This migration is fully idempotent (all ADD COLUMN clauses use
-- `IF NOT EXISTS`) so it's safe to re-run on partially-migrated
-- environments.

BEGIN;

-- Entity denormalization (model: affected_ips/hosts/users/assets)
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS affected_ips     JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS affected_hosts   JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS affected_users   JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS affected_assets  JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Merge / parent-child relationships
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parent_alert_id  UUID;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS child_alert_ids  JSONB   NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS is_merged        BOOLEAN NOT NULL DEFAULT FALSE;

-- Assignment
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to_id   UUID;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_at      TIMESTAMPTZ;

-- Enrichment / tagging
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS enrichment_data  JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tags             JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMIT;
