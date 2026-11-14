-- 091_sso_policy.sql — enterprise SSO policy columns + the `infosec` role.
--
-- SSO support spec: allowed-domain provisioning, JIT toggle, group-role mode,
-- configurable groups claim, and a branded login label, all stored per
-- connection so a second IdP can have its own policy without a redeploy.
--
-- Reversible: DROP COLUMN IF EXISTS on rollback; the role seed deletes itself.
-- Nothing here changes the fail-closed defaults: a connection that has no
-- rows, no domains, and no mappings admits nobody beyond its configured
-- default-role least-privilege grant, and `enabled` still defaults FALSE.

ALTER TABLE aisoc_sso_connections ADD COLUMN IF NOT EXISTS allowed_email_domains TEXT NOT NULL DEFAULT '';
ALTER TABLE aisoc_sso_connections ADD COLUMN IF NOT EXISTS jit_provisioning BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE aisoc_sso_connections ADD COLUMN IF NOT EXISTS group_role_mode TEXT NOT NULL DEFAULT 'first_login_only'
    CHECK (group_role_mode IN ('first_login_only', 'authoritative'));
ALTER TABLE aisoc_sso_connections ADD COLUMN IF NOT EXISTS groups_claim TEXT NOT NULL DEFAULT '';
ALTER TABLE aisoc_sso_connections ADD COLUMN IF NOT EXISTS login_label TEXT NOT NULL DEFAULT '';

-- The `infosec` role is NOT seeded into `roles` here. `roles` is the
-- per-tenant RBAC override table: its very existence for a tenant flips
-- resolve_permissions from the static map to the database, and a seeded row
-- without matching role_permissions grants every user of that tenant ZERO
-- permissions — including break-glass admin. The canonical definition of
-- `infosec` lives in app.core.security.ROLE_PERMISSIONS and
-- app.core.role_grants.GRANTABLE_ROLES, which is what assignment validates
-- against; nothing in `roles` is needed for it to be assignable.
