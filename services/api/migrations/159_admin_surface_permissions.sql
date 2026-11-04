-- The two permissions that gate the deployment-wide operator surface.
--
-- GHSA-6cwm-cx8p-h7f5.
--
-- `tenant_provision._require_admin` and `waitlist._require_admin` each allowed
-- `admin:tenants` / `admin:waitlist` OR `settings:write`. The fallback was
-- written as a bridge: "keeps existing admins unblocked while the seed-data
-- migration that introduces admin:tenants lands separately". That migration is
-- this one, and until now it did not exist -- so neither name was in any
-- catalog, no role could resolve either, and the fallback was not a fallback
-- at all but the only reachable branch.
--
-- `settings:write` is held by `tenant_admin`. The routes behind it are not
-- tenant-scoped: `GET /admin/tenants` selects every tenant on the deployment
-- with no predicate, `POST /admin/tenants/provision` creates tenants, and the
-- waitlist is a single global table of prospect PII. So one tenant's
-- administrator could enumerate and modify the whole deployment.
--
-- Seeded here rather than only declared in `app/core/rbac_catalog.py` because
-- 092 has already run everywhere and the runner tracks applied files: a new
-- permission reaches an existing catalog only through a new migration. Same
-- reasoning, and the same shape, as 123 for `platform_kill_switch:write`.
--
-- No `role_permissions` grant accompanies these, deliberately. They confer
-- authority over every tenant, so no tenant-scoped role may hold them and only
-- the wildcard roles do -- the decision `platform_kill_switch:write` and
-- `workload_identities:*` already record. They are likewise absent from
-- `VALID_SCOPES`, so no API key can be minted carrying them.

INSERT INTO permissions (name, description, category) VALUES
    ('admin:tenants',  'List and provision tenants across the deployment',   'system'),
    ('admin:waitlist', 'Read and modify the deployment-wide signup waitlist', 'system')
ON CONFLICT (name) DO NOTHING;
