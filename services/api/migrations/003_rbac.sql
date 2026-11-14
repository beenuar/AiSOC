-- AiSOC Granular RBAC migration
-- Creates roles, role_permissions, and user_roles tables for fine-grained access control.

-- ============================================================
-- Roles table
-- ============================================================
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,  -- system roles cannot be deleted
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id);

-- ============================================================
-- Permissions catalogue (static, application-defined)
-- ============================================================
CREATE TABLE IF NOT EXISTS permissions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(200) UNIQUE NOT NULL,  -- e.g. "cases:read", "alerts:write"
    description TEXT,
    category    VARCHAR(100)                   -- e.g. "cases", "alerts", "admin"
);

-- Seed built-in permissions
INSERT INTO permissions (name, description, category) VALUES
    ('cases:read',            'View cases',                           'cases'),
    ('cases:write',           'Create and update cases',              'cases'),
    ('cases:delete',          'Delete cases',                         'cases'),
    ('alerts:read',           'View alerts',                          'alerts'),
    ('alerts:write',          'Acknowledge / assign alerts',          'alerts'),
    ('alerts:delete',         'Delete alerts',                        'alerts'),
    ('playbooks:read',        'View playbooks',                       'playbooks'),
    ('playbooks:write',       'Create and update playbooks',          'playbooks'),
    ('playbooks:execute',     'Run playbooks',                        'playbooks'),
    ('playbooks:delete',      'Delete playbooks',                     'playbooks'),
    ('detections:read',       'View detection rules',                 'detections'),
    ('detections:write',      'Create and update detection rules',    'detections'),
    ('detections:delete',     'Delete detection rules',               'detections'),
    ('connectors:read',       'View connectors',                      'connectors'),
    ('connectors:write',      'Create and update connectors',         'connectors'),
    ('connectors:delete',     'Delete connectors',                    'connectors'),
    ('api_keys:read',         'View API keys',                        'api_keys'),
    ('api_keys:write',        'Create API keys',                      'api_keys'),
    ('api_keys:delete',       'Revoke API keys',                      'api_keys'),
    ('audit_log:read',        'View audit log',                       'audit'),
    ('compliance:read',       'View compliance dashboards',           'compliance'),
    ('users:read',            'View users in the tenant',             'admin'),
    ('users:write',           'Invite and update users',              'admin'),
    ('users:delete',          'Remove users from the tenant',         'admin'),
    ('roles:read',            'View roles and permissions',           'admin'),
    ('roles:write',           'Create and modify roles',              'admin'),
    ('tenant:read',           'View tenant settings',                 'admin'),
    ('tenant:write',          'Modify tenant settings',               'admin')
ON CONFLICT (name) DO NOTHING;

-- ============================================================
-- Role ↔ Permission join
-- ============================================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ============================================================
-- User ↔ Role join  (users can have multiple roles per tenant)
-- ============================================================
CREATE TABLE IF NOT EXISTS user_roles (
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id   UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

-- ============================================================
-- Seed system roles
-- We insert a sentinel tenant_id of the nil UUID.
-- Real per-tenant system roles are created by the application on tenant onboarding.
-- ============================================================

-- Helper function: get or create a system role for a tenant
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

    -- Grant all permissions to admin
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

    -- Analyst gets read + execute on all, write on cases/alerts
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_analyst_id, id FROM permissions
    WHERE name IN (
        'cases:read', 'cases:write',
        'alerts:read', 'alerts:write',
        'playbooks:read', 'playbooks:execute',
        'detections:read',
        'connectors:read',
        'audit_log:read',
        'compliance:read'
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

    -- Viewer gets read-only
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT v_viewer_id, id FROM permissions
    WHERE name LIKE '%:read'
    ON CONFLICT DO NOTHING;
END;
$$;

-- RLS on RBAC tables
ALTER TABLE roles            ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles            FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS roles_tenant ON roles;
CREATE POLICY roles_tenant ON roles
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- Permissions are global (no tenant_id) — no RLS needed.

ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permissions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rp_tenant ON role_permissions;
CREATE POLICY rp_tenant ON role_permissions
    USING (
        role_id IN (
            SELECT id FROM roles WHERE tenant_id = current_tenant_id() OR current_tenant_id() IS NULL
        )
    );

ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ur_tenant ON user_roles;
CREATE POLICY ur_tenant ON user_roles
    USING (
        role_id IN (
            SELECT id FROM roles WHERE tenant_id = current_tenant_id() OR current_tenant_id() IS NULL
        )
    );
