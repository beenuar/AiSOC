-- 163: retire the published demo administrator from managed tenants.
--
-- The managed-tenant provisioner used to call seed_demo._ensure_user while
-- adding starter alerts and cases. That helper owns one deterministic user
-- with published credentials and an `admin` wildcard role; on every managed
-- provisioning it moved that user into the new tenant, reset the known
-- password, and activated it.
--
-- Keep the intentional canonical demo tenant working. Everywhere else, the
-- deterministic id + address + wildcard role identify the unsafe seeded
-- principal precisely. Deactivation closes password and bearer-session paths;
-- replacing the hash and role keeps a later accidental reactivation inert.
-- seed_demo._ensure_user restores every field when an operator deliberately
-- runs the demo seeder against the canonical demo tenant.

UPDATE users
SET    hashed_password = '!retired-managed-demo-login',
       role = 'viewer',
       is_active = FALSE,
       is_verified = FALSE,
       sessions_revoked_at = NOW(),
       updated_at = NOW()
WHERE  id = '00000000-0000-0000-0000-000000000002'
  AND  tenant_id <> '00000000-0000-0000-0000-0000000000de'
  AND  email = 'demo@example.com'
  AND  role = 'admin';
