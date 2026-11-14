-- Migration 044: Tenant isolation for aisoc_cases / aisoc_case_comments /
-- aisoc_case_tasks (P2-W1).
--
-- aisoc_cases already has a tenant_id column (migration 012) but the /cases API
-- never scoped queries by it, so any authenticated caller could read or mutate
-- another tenant's cases just by guessing UUIDs (or by guessing the short
-- case_number form like INC-001). The companion comments/tasks tables don't
-- have tenant_id at all, so even with /cases fixed an attacker could still
-- enumerate comments and tasks for foreign cases.
--
-- This migration:
--   1. Adds tenant_id to aisoc_case_comments and aisoc_case_tasks and
--      backfills from the parent aisoc_cases row.
--   2. Adds covering indexes so /cases can filter by
--      (tenant_id, …) efficiently.
--   3. Replaces the globally-unique idx_aisoc_cases_case_number with a
--      (tenant_id, case_number) unique index so two tenants can independently
--      mint INC-001 without collisions.
--
-- The API layer (services/api/app/api/v1/endpoints/cases.py) is updated in
-- the same change to add `WHERE tenant_id = :tenant_id` to every query and
-- to scope the case_number resolver by tenant.

-- ------------------------------------------------------------------
-- 1. aisoc_case_comments.tenant_id
-- ------------------------------------------------------------------
ALTER TABLE aisoc_case_comments
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE aisoc_case_comments c
   SET tenant_id = p.tenant_id
  FROM aisoc_cases p
 WHERE c.case_id = p.id
   AND c.tenant_id IS NULL;

-- ------------------------------------------------------------------
-- 2. aisoc_case_tasks.tenant_id
-- ------------------------------------------------------------------
ALTER TABLE aisoc_case_tasks
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE aisoc_case_tasks t
   SET tenant_id = p.tenant_id
  FROM aisoc_cases p
 WHERE t.case_id = p.id
   AND t.tenant_id IS NULL;

-- ------------------------------------------------------------------
-- 3. Indexes
-- ------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_aisoc_cases_tenant_created
    ON aisoc_cases (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_aisoc_case_comments_tenant_case
    ON aisoc_case_comments (tenant_id, case_id, created_at);

CREATE INDEX IF NOT EXISTS idx_aisoc_case_tasks_tenant_case
    ON aisoc_case_tasks (tenant_id, case_id, created_at);

-- ------------------------------------------------------------------
-- 4. Per-tenant uniqueness on case_number
--
-- Replace the global unique index from migration 028 with a (tenant_id,
-- case_number) one so the human-readable identifier ("INC-001") is unique
-- *within* a tenant but two tenants can share the same value. The legacy
-- index is only dropped if it exists so this migration is idempotent on
-- partially-migrated databases.
-- ------------------------------------------------------------------
DROP INDEX IF EXISTS idx_aisoc_cases_case_number;

CREATE UNIQUE INDEX IF NOT EXISTS idx_aisoc_cases_tenant_case_number
    ON aisoc_cases (tenant_id, case_number);
