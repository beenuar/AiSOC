-- ============================================================
-- Migration 034: tenant lake API permissions (Workstream 7)
-- ============================================================
-- Adds two new global permissions to the RBAC permissions catalog
-- and backfills them onto existing role assignments so the DB-backed
-- RBAC path (deps.CurrentUser.has_permission_db) and the static
-- ROLE_PERMISSIONS fallback in app/core/security.py stay in sync.
--
-- Permissions:
--   lake:query        - execute SELECT against the warm tier via
--                       POST /api/v1/lake/sql (rewriter still enforces
--                       table allowlist + tenant predicates + LIMIT cap)
--   lake:read_schema  - GET /api/v1/lake/schema for table/column
--                       discovery (read-only, no data exposure)
--
-- Role mapping (DB-backed system roles):
--   admin    → both (already; admin auto-grants all permissions on
--              tenant seed, but we still explicit-backfill in case an
--              admin role was created without the auto-grant)
--   analyst  → both (analysts run lake queries during triage)
--   viewer   → lake:read_schema only (viewers see schema; no data
--              egress through SQL execution)
--
-- This migration is idempotent. It uses ON CONFLICT DO NOTHING and
-- predicate-based selects so it can be re-run safely.
-- ============================================================

-- 1. Seed the two new permissions into the global permissions catalog.
INSERT INTO permissions (name, description, category) VALUES
    ('lake:query',       'Execute SELECT queries against the tenant warm-tier lake', 'lake'),
    ('lake:read_schema', 'Read table and column metadata from the tenant lake',      'lake')
ON CONFLICT (name) DO NOTHING;

-- 2. Backfill onto existing roles across every tenant.
--    The seed_system_roles() function grants permissions at tenant
--    creation time, but tenants seeded before this migration won't
--    have the new permissions wired up yet. This block fixes that
--    without disturbing custom roles or non-system roles.

-- Admin: gets every permission (mirror of the seed_system_roles admin grant).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin'
  AND r.is_system = TRUE
  AND p.name IN ('lake:query', 'lake:read_schema')
ON CONFLICT DO NOTHING;

-- Analyst: gets both lake permissions (lake is a triage tool).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'analyst'
  AND r.is_system = TRUE
  AND p.name IN ('lake:query', 'lake:read_schema')
ON CONFLICT DO NOTHING;

-- Viewer: only schema reads, no SQL execution.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'viewer'
  AND r.is_system = TRUE
  AND p.name IN ('lake:read_schema')
ON CONFLICT DO NOTHING;

-- 3. Update seed_system_roles() so newly-onboarded tenants get the
--    same wiring without a follow-up backfill.
--
--    The admin grant already SELECTs every permission, so it picks
--    up lake:* automatically. The analyst grant uses an IN-list, so
--    we extend it. The viewer grant uses a `LIKE '%:read'` pattern,
--    so we add an explicit `OR name = 'lake:read_schema'` clause —
--    `lake:read_schema` doesn't end in `:read` so it would otherwise
--    be missed.

CREATE OR REPLACE FUNCTION seed_system_roles(p_tenant_id UUID) RETURNS VOID
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_admin_id   UUID;
    v_analyst_id UUID;
    v_viewer_id  UUID;
BEGIN
    -- Admin role
    INSERT INTO roles (tenant_id, name, description, is_system)
    VALUES (p_tenant_id, 'admin', 'Full access to all resources', TRUE)
    ON CONFLICT (tenant_id, name) DO NOTHING
    RETURNING id INTO v_admin_id;

    IF v_admin_id IS NULL THEN
        SELECT id INTO v_admin_id FROM roles WHERE tenant_id = p_tenant_id AND name = 'admin';
    END IF;

    -- Grant all permissions to admin (includes lake:query, lake:read_schema).
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_admin_id, id FROM permissions
    ON CONFLICT DO NOTHING;

    -- Analyst role
    INSERT INTO roles (tenant_id, name, description, is_system)
    VALUES (p_tenant_id, 'analyst', 'Read and triage access', TRUE)
    ON CONFLICT (tenant_id, name) DO NOTHING
    RETURNING id INTO v_analyst_id;

    IF v_analyst_id IS NULL THEN
        SELECT id INTO v_analyst_id FROM roles WHERE tenant_id = p_tenant_id AND name = 'analyst';
    END IF;

    -- Analyst gets read + execute on all, write on cases/alerts, plus
    -- both lake permissions for triage queries.
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_analyst_id, id FROM permissions
    WHERE name IN (
        'cases:read', 'cases:write',
        'alerts:read', 'alerts:write',
        'playbooks:read', 'playbooks:execute',
        'detections:read',
        'connectors:read',
        'audit_log:read',
        'compliance:read',
        'lake:query',
        'lake:read_schema'
    )
    ON CONFLICT DO NOTHING;

    -- Viewer role
    INSERT INTO roles (tenant_id, name, description, is_system)
    VALUES (p_tenant_id, 'viewer', 'Read-only access', TRUE)
    ON CONFLICT (tenant_id, name) DO NOTHING
    RETURNING id INTO v_viewer_id;

    IF v_viewer_id IS NULL THEN
        SELECT id INTO v_viewer_id FROM roles WHERE tenant_id = p_tenant_id AND name = 'viewer';
    END IF;

    -- Viewer gets read-only. The `%:read` pattern misses lake:read_schema
    -- (it ends in `_schema`, not `:read`), so add it explicitly.
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_viewer_id, id FROM permissions
    WHERE name LIKE '%:read'
       OR name = 'lake:read_schema'
    ON CONFLICT DO NOTHING;
END;
$$;
