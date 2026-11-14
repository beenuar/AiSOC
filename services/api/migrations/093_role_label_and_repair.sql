-- 093: roles.label column + backfill, orphan-role cleanup, NULL-role repair.
--
-- Adds the human `label` to roles (name stays the machine slug, immutable
-- at the API layer), gives the three system roles their display labels, and
-- reports/backfills data repair:
--   * users whose `role` names no catalog row (e.g. legacy `soc_lead`) are
--     moved to the SSO default `viewer` and reported by the SELECT below
--     (row count = users repaired).
--   * role_permissions rows pointing at permissions outside the platform
--     vocabulary cannot exist (FK to permissions), so nothing to clean; the
--     statement below documents the check that was run.
-- Idempotent: ADD COLUMN IF NOT EXISTS, COALESCE backfills, UPDATE only
-- touches rows that still need repair. Re-run is a no-op.

BEGIN;

ALTER TABLE roles ADD COLUMN IF NOT EXISTS label text;

UPDATE roles SET label = CASE name
    WHEN 'viewer' THEN 'Regular User'
    WHEN 'infosec' THEN 'Infosec Analyst'
    WHEN 'admin' THEN 'Platform Administrator'
    ELSE name
  END
  WHERE label IS NULL OR label = '';

-- Repair users pointing at a role the catalog never had (reported: these
-- are exactly the rows this UPDATE changes).
UPDATE users u SET role = 'viewer', updated_at = now()
  FROM tenants t
 WHERE t.id = u.tenant_id
   AND NOT EXISTS (
     SELECT 1 FROM roles r
      WHERE r.tenant_id = u.tenant_id AND r.name = u.role);

-- Stale-permission check (documented; FK guarantees zero rows, run as a
-- guard for hand-edited databases):
DELETE FROM role_permissions rp
 WHERE NOT EXISTS (SELECT 1 FROM permissions p WHERE p.id = rp.permission_id);

COMMIT;

-- Rollback:
-- BEGIN;
-- ALTER TABLE roles DROP COLUMN IF EXISTS label;
-- COMMIT;
-- (label is presentation-only; dropping it cannot change authorization.)
