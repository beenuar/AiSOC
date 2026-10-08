-- 096_access_governance_permissions.sql — the permission vocabulary for
-- ABAC conditions, time-boxed elevation and workload identities.
--
-- Depth plan item 8.2. Migration 087 created `permission_conditions`,
-- `privilege_grants` and `workload_identities` and shipped no reader for
-- any of them. The readers land in this change; these are the permission
-- rows the routes administering them enforce.
--
-- Why a new migration rather than an edit to 092
-- ----------------------------------------------
-- `092_rbac_catalog_seed.sql` has already run on every deployment, and the
-- runner tracks applied files in `aisoc_schema_migrations` — editing it
-- would seed these rows on a fresh install and on nobody else. A tenant
-- that had adopted database-backed RBAC would then hold a role that grants
-- a permission the catalog has no row for, which the Roles screen renders
-- as a blank.
--
-- `services/api/tests/test_rbac_catalog_seed.py` pins the migration
-- vocabulary against `app/core/rbac_catalog.py`. It reads every migration
-- that seeds permissions rather than only 092, so the vocabulary can grow
-- the only way it safely can — in a new file — and still cannot drift.
--
-- Idempotent: every statement is ON CONFLICT-aware. No secrets.

BEGIN;

-- ─── Permission catalog additions ───────────────────────────────────────────
--
-- `elevation:*` govern time-boxed grants. Request and approve are separate
-- permissions on purpose: an approver who can also request is both parties
-- to the decision, and the control reduces to a log line.
--
-- `workload_identities:*` govern deployment-wide service credentials. They
-- are granted below to no tenant-scoped role, which is deliberate rather
-- than an omission: a workload credential authenticates before any tenant
-- is known and acts for whichever tenant it names per request, so minting
-- one from a tenant-scoped session would confer cross-tenant authority.
-- Only the wildcard roles (`admin`, `platform_admin`) hold them.
INSERT INTO permissions (name, description, category) VALUES
    ('elevation:read',            'View the tenant''s privilege elevations',             'access'),
    ('elevation:request',         'Request a time-boxed privilege elevation',            'access'),
    ('elevation:approve',         'Approve or revoke a privilege elevation',             'access'),
    ('access_conditions:read',    'View attribute conditions on permissions',            'access'),
    ('access_conditions:write',   'Add, disable or remove attribute conditions',         'access'),
    ('workload_identities:read',  'View per-service internal credentials',               'access'),
    ('workload_identities:write', 'Mint, rotate or revoke per-service credentials',      'access')
ON CONFLICT (name) DO UPDATE
   SET description = EXCLUDED.description,
       category    = EXCLUDED.category;

-- ─── Grants ─────────────────────────────────────────────────────────────────
--
-- Every tenant that has already adopted the catalog, not just the primary
-- one. 092 scoped its grants to the seed tenant because it was creating the
-- roles; here the roles already exist wherever they exist, and a tenant
-- that adopted the catalog through `POST /api/v1/rbac/roles/seed` must not
-- be left with an analyst who cannot ask for an elevation.
--
-- `admin` already holds `*` and needs no row.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON (r.name = 'infosec' AND p.name IN (
            'elevation:request'
        ))
ON CONFLICT DO NOTHING;

COMMIT;

-- Rollback (documented, not executed):
--
--   DELETE FROM role_permissions
--    WHERE permission_id IN (SELECT id FROM permissions WHERE category = 'access');
--   DELETE FROM permissions WHERE category = 'access';
--
-- Removing the rows does not disable the feature: `require_permission`
-- reads the resolved set, and a permission with no catalog row simply
-- cannot be granted through the console. To turn enforcement off, delete
-- the `permission_conditions` and `privilege_grants` rows instead — those
-- are what `CurrentUser.require_permission` reads.
