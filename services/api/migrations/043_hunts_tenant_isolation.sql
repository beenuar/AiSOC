-- Migration 043: Tenant isolation for aisoc_hunts / aisoc_hunt_runs (C-2)
--
-- The legacy aisoc_hunts table (created in migration 014) had a `tenant_id`
-- column but the /hunts API never scoped queries by it, so any authenticated
-- caller could read and mutate any tenant's hunt hypotheses, runs, and
-- findings. The companion aisoc_hunt_runs table didn't even have a tenant_id
-- column. This migration:
--   1. Adds tenant_id to aisoc_hunt_runs and backfills it from aisoc_hunts.
--   2. Adds covering indexes so /hunts can filter by (tenant_id, …) efficiently.
--
-- The API layer (services/api/app/api/v1/endpoints/hunts.py) is updated in the
-- same change to add `WHERE tenant_id = :tenant_id` to every query.

-- ------------------------------------------------------------------
-- 1. aisoc_hunt_runs.tenant_id
-- ------------------------------------------------------------------
ALTER TABLE aisoc_hunt_runs
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Backfill from the parent hunt row.
UPDATE aisoc_hunt_runs r
   SET tenant_id = h.tenant_id
  FROM aisoc_hunts h
 WHERE r.hunt_id = h.id
   AND r.tenant_id IS NULL;

-- ------------------------------------------------------------------
-- 2. Indexes
-- ------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_aisoc_hunts_tenant_created
    ON aisoc_hunts (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_aisoc_hunt_runs_tenant_hunt
    ON aisoc_hunt_runs (tenant_id, hunt_id, run_at DESC);
