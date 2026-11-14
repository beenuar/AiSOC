-- 092_rbac_catalog_seed.sql — the role + permission catalog, seeded as data.
--
-- Why this migration exists
-- -------------------------
-- The RBAC tables (`roles`, `permissions`, `role_permissions`, `user_roles`)
-- shipped with schema but nobody ever seeded `roles` and `role_permissions`.
-- `permission_cache.resolve_permissions` consults the tables as soon as the
-- tenant has ANY role row, and a user with no `user_roles` row then resolves
-- to zero permissions. So the catalog seed and the membership backfill MUST
-- land in the same transaction: seeding roles alone is exactly the
-- permission-blanking failure that `091_sso_policy.sql` caused and that this
-- file permanently repairs.
--
-- Scope: the primary tenant (the one the SSO connection and the break-glass
-- admin belong to) plus any tenant that already has members AND every role
-- string its members hold is covered by the seeded catalog or backfilled to
-- `viewer`. Tenants whose members hold roles outside this catalog
-- (e.g. `soc_lead` demo fixtures) are deliberately NOT flipped to
-- database-backed mode here; they adopt the catalog through
-- `POST /api/v1/rbac/roles/seed`, which backfills atomically the same way.
--
-- Idempotent: every statement is ON CONFLICT-aware; re-running changes
-- nothing. Reversible: the rollback block at the bottom, documented in
-- docs/roles-and-permissions.md. No secrets, ever — this file contains only
-- role/permission vocabulary.

BEGIN;

-- ─── Permission catalog (platform-wide) ─────────────────────────────────────
-- Names are the strings the routes actually enforce (`require_permission`).
-- The spec aliases (`users:manage`, `investigation:run`, ...) are seeded
-- alongside so the catalog answers the product's vocabulary too; enforcement
-- reads the canonical names. `*` is a real row: the admin role's grant, so
-- the screen can show what it actually confers instead of a footnote.
INSERT INTO permissions (name, description, category) VALUES
    -- alerts
    ('alerts:read',          'View alerts',                              'alerts'),
    ('alerts:write',         'Acknowledge / triage / update alerts',   'alerts'),
    ('alerts:delete',        'Delete alerts',                           'alerts'),
    -- cases
    ('cases:read',           'View cases',                              'cases'),
    ('cases:write',          'Create and edit cases',                    'cases'),
    ('cases:delete',         'Delete cases',                            'cases'),
    ('cases:assign',         'Assign cases to people',                  'cases'),
    ('cases:note',           'Add notes to cases',                      'cases'),
    -- detections / rules
    ('detections:read',      'View detections',                         'detections'),
    ('detections:write',     'Manage detections',                       'detections'),
    ('detections:delete',    'Delete detections',                       'detections'),
    ('rules:read',           'View detection rules',                    'rules'),
    ('rules:write',          'Create and edit detection rules',         'rules'),
    -- dashboards / reports / compliance
    ('dashboards:read',      'View dashboards',                         'dashboards'),
    ('reports:read',         'View reports',                            'reports'),
    ('reports:write',        'Generate and edit reports',               'reports'),
    ('reports:export',       'Export reports',                          'reports'),
    ('compliance:read',      'View compliance posture',                 'compliance'),
    -- playbooks / actions / investigation
    ('playbooks:read',       'View playbooks',                          'playbooks'),
    ('playbooks:write',      'Edit playbooks',                          'playbooks'),
    ('playbooks:execute',    'Run playbooks',                           'playbooks'),
    ('actions:read',         'View the response-action registry',      'actions'),
    ('actions:execute',      'Execute response actions',               'actions'),
    ('investigation:run',    'Run an investigation',                    'investigations'),
    -- threat intel
    ('threat_intel:read',   'View threat intelligence',                'threat_intel'),
    ('threat_intel:write',  'Manage threat intelligence',              'threat_intel'),
    ('threatintel:manage',  'Manage threat intelligence (alias)',      'threat_intel'),
    -- connectors / lake / hunts / knowledge
    ('connectors:read',     'View connectors',                         'connectors'),
    ('connectors:write',    'Configure connectors',                    'connectors'),
    ('connectors:delete',   'Delete connectors',                       'connectors'),
    ('lake:query',          'Query the data lake',                     'lake'),
    ('lake:read_schema',    'Read the lake schema',                    'lake'),
    ('hunts:read',          'View hunts',                              'hunts'),
    ('knowledge_base:read', 'Search the knowledge base',               'knowledge_base'),
    ('graph:read',          'View the investigation graph',            'graph'),
    -- users / roles / tenant / settings / api keys / audit
    ('users:read',          'View users',                              'admin'),
    ('users:write',         'Create, edit and role-manage users',      'admin'),
    ('users:delete',        'Delete users',                            'admin'),
    ('users:manage',        'Manage users (alias)',                    'admin'),
    ('roles:read',          'View roles and permissions',              'admin'),
    ('roles:write',         'Create, edit and delete roles',           'admin'),
    ('roles:assign',        'Assign roles to users (alias)',           'admin'),
    ('tenant:read',         'View tenant settings',                     'admin'),
    ('tenant:write',        'Change tenant settings',                  'admin'),
    ('settings:read',       'Read settings',                           'admin'),
    ('settings:write',      'Change settings',                         'admin'),
    ('settings:manage',     'Manage settings (alias)',                 'admin'),
    ('sso:configure',       'Configure SSO connections',               'admin'),
    ('api_keys:read',       'View API keys',                          'api_keys'),
    ('api_keys:write',      'Create and revoke API keys',              'api_keys'),
    ('api_keys:delete',     'Delete API keys',                        'api_keys'),
    ('apikeys:manage',      'Manage API keys (alias)',                'api_keys'),
    ('audit_log:read',      'Read the audit log',                      'audit'),
    ('audit:read',          'Read the audit log (alias)',              'audit'),
    -- sla / plugins / system
    ('sla:read',            'View SLA metrics',                        'sla'),
    ('sla:write',           'Change SLA policy',                       'sla'),
    ('plugins:read',        'View plugins',                            'plugins'),
    ('plugins:admin',       'Administer plugins',                      'plugins'),
    ('plugins:execute',     'Execute plugins',                         'plugins'),
    ('*',                   'Every permission (wildcard; admin role)',   'system')
ON CONFLICT (name) DO UPDATE
   SET description = EXCLUDED.description,
       category    = EXCLUDED.category;

-- ─── Role catalog (tenant-scoped) ───────────────────────────────────────────
-- The three product roles. `is_system = TRUE` keeps them out of the
-- edit/delete paths (`update_role` / `delete_role` refuse system roles),
-- so `viewer` — the SSO default — is non-deletable by construction.
WITH seed_roles(name, description) AS (
    VALUES
        ('viewer',  'Regular User. View-only. The default role for SSO just-in-time provisioning.'),
        ('infosec', 'Infosec analyst / incident handler. Investigates, triages and responds; manages no users, roles, SSO or settings.'),
        ('admin',   'Platform administrator. Full control of this tenant, including users, roles, SSO configuration and the audit log.')
)
INSERT INTO roles (tenant_id, name, description, is_system)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, r.name, r.description, TRUE
  FROM seed_roles r
ON CONFLICT (tenant_id, name) DO UPDATE
   SET description = EXCLUDED.description;

-- ─── Role → permission grants ────────────────────────────────────────────────
-- Deny-by-default: a permission NOT granted here is denied once the tenant
-- is on database-backed RBAC. The sets mirror `ROLE_PERMISSIONS` in
-- app/core/security.py (the static bootstrap map) so the flip to the
-- database changes nothing about what any of the three roles can do.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON (
        (r.name = 'viewer' AND p.name IN (
            'alerts:read',
            'cases:read',
            'dashboards:read',
            'detections:read',
            'reports:read',
            'connectors:read',
            'threat_intel:read',
            'actions:read',
            'knowledge_base:read'
        ))
     OR (r.name = 'infosec' AND p.name IN (
            -- everything viewer holds...
            'alerts:read', 'cases:read', 'dashboards:read', 'detections:read',
            'reports:read', 'connectors:read', 'threat_intel:read',
            'actions:read', 'knowledge_base:read',
            -- ...plus the analyst/hunter working set (mirrors
            -- ROLE_PERMISSIONS["infosec"]: analyst | hunter, minus management)
            'alerts:write',
            'cases:write', 'cases:assign', 'cases:note',
            'playbooks:read', 'playbooks:execute',
            'threat_intel:write', 'threatintel:manage',
            'rules:read', 'rules:write',
            'detections:write',
            'hunts:read', 'lake:query', 'lake:read_schema',
            'graph:read',
            'actions:execute',
            'investigation:run',
            'reports:write', 'reports:export'
        ))
     OR (r.name = 'admin' AND p.name = '*')
  )
 WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'::uuid
ON CONFLICT DO NOTHING;

-- ─── Membership backfill (same transaction as the grants, see header) ──────
-- 1. Users whose `users.role` names a seeded role get that catalog row.
-- 2. Anybody else in the tenant gets `viewer`, so nobody wakes up with zero
--    permissions because the tenant just switched to database-backed RBAC.
-- `assigned_by` stays NULL: NULL means "system-seeded, not an operator
-- decision" — the rollback block uses exactly that to identify its rows,
-- and operator/console assignments always carry an actor id.
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
  FROM users u
  JOIN roles r ON r.tenant_id = u.tenant_id AND r.name = u.role
 WHERE r.is_system = TRUE
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, vr.id
  FROM users u
  JOIN roles vr ON vr.tenant_id = u.tenant_id AND vr.name = 'viewer' AND vr.is_system = TRUE
 WHERE u.tenant_id = '00000000-0000-0000-0000-000000000001'::uuid
   AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id)
ON CONFLICT DO NOTHING;

COMMIT;

-- ─── Rollback (manual; run inside one transaction) ───────────────────────────
-- Deletes only what this file seeded, identified by `assigned_by IS NULL`
-- on system-role rows. Console/provisioning assignments carry an actor id
-- or re-sync on the next SSO sign-in, so nobody is stranded either way.
-- Deleting the `roles` rows flips the tenant back to the static-map
-- bootstrap, which is exactly the pre-092 behaviour.
--
--   BEGIN;
--   DELETE FROM user_roles      WHERE assigned_by IS NULL
--     AND role_id IN (SELECT id FROM roles
--                     WHERE tenant_id = '00000000-0000-0000-0000-000000000001'::uuid
--                       AND name IN ('viewer','infosec','admin') AND is_system = TRUE);
--   DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles
--                     WHERE tenant_id = '00000000-0000-0000-0000-000000000001'::uuid
--                       AND name IN ('viewer','infosec','admin') AND is_system = TRUE);
--   DELETE FROM roles           WHERE tenant_id = '00000000-0000-0000-0000-000000000001'::uuid
--                       AND name IN ('viewer','infosec','admin') AND is_system = TRUE;
--   COMMIT;
--
-- The permission rows are platform-wide, additive, and confer nothing on
-- their own; they are left in place. Delete them only if you intend to
-- remove the vocabulary from every tenant at once.
