-- 157: `approvals:write` joins the permission vocabulary and the roles that had it.
--
-- `POST /api/v1/approvals` used to require `cases:write`. It now requires
-- `approvals:write`, so that the agents service's playbook engine — which
-- reaches the route on the shared service token — can open an approval for a
-- human to decide without that one credential also gaining case authoring and
-- case deletion. The service token is valid on every route for every tenant,
-- so widening it is not a small thing.
--
-- A permission the static map grants is not necessarily one a deployment can
-- grant. `ROLE_PERMISSIONS` is the fallback; a tenant on database-backed RBAC
-- resolves from `permissions` / `role_permissions`, and a name absent from
-- this table cannot be granted through the console at all. `hunts:read` was
-- held by no role for exactly this reason. So the vocabulary row and the
-- grants move in the same migration as the route.
--
-- Deciding an approval still requires `cases:write`. A principal that may
-- raise one must not automatically be able to answer it, and the service
-- token deliberately holds only this half.

INSERT INTO permissions (name, description, category) VALUES
    ('approvals:write', 'Raise an approval request for a human to decide', 'cases')
ON CONFLICT (name) DO NOTHING;

-- Grant 1 of 2: the seeded catalog role, in the same shape as 092 so the
-- parity test can read it. `infosec` is the only seeded non-wildcard role
-- holding `cases:write`; `admin` holds `*` and needs no row.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  CROSS JOIN permissions p
 WHERE (r.name = 'infosec' AND p.name IN (
            'approvals:write'
        ))
ON CONFLICT DO NOTHING;

-- Grant 2 of 2: every *other* role that already holds `cases:write`, which is
-- the access it had the moment before this migration ran. Derived rather than
-- named on purpose — naming `infosec` alone would cover the seeded catalog and
-- silently drop any role an operator created and granted `cases:write` to,
-- leaving that role unable to open an approval with nothing to explain why.
INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, (SELECT id FROM permissions WHERE name = 'approvals:write')
  FROM role_permissions rp
  JOIN permissions p ON p.id = rp.permission_id
 WHERE p.name = 'cases:write'
ON CONFLICT DO NOTHING;
