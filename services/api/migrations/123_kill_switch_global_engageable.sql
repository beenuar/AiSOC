-- The platform-wide kill switch can be engaged by the runtime role.
--
-- What was wrong
-- --------------
-- 078 created `aisoc_kill_switch` with a global row (`tenant_id IS NULL`)
-- and the policy
--
--     USING      (tenant_id IS NULL OR tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
--     WITH CHECK (tenant_id = current_tenant_id())
--
-- and its own comment says the global row "is written by the platform
-- operator through a session with no tenant set". That is the one case the
-- check rejects. `current_tenant_id()` returns NULL for an unset or empty
-- setting, so the global row is judged `NULL = NULL` on an unbound session
-- and `NULL = '<uuid>'` on a bound one. Both are NULL, and a WITH CHECK
-- that does not evaluate to true refuses the row.
--
-- The effect was a stop button with two readers — `GET /kill-switch` and
-- `kill_switch_engaged` in services/agents, which consults it on every
-- alert — and no session that could ever have written it. Reproduced
-- against postgres:16 with this chain applied, connected as the
-- NOSUPERUSER NOBYPASSRLS `aisoc_app` role:
--
--     INSERT INTO aisoc_kill_switch (tenant_id, ...) VALUES (NULL, ...);
--     ERROR:  new row violates row-level security policy for table "aisoc_kill_switch"
--
-- unbound and bound alike, while the same INSERT for the session's own
-- tenant returned INSERT 0 1. The per-tenant half has always worked; only
-- the platform-wide half was unreachable.
--
-- The shape of the fix
-- --------------------
-- Dropping WITH CHECK would make the table writable and tenant isolation
-- decorative — an unbound worker could then write into any tenant. A global
-- row is legitimately not tenant-scoped, so the policy expresses that
-- distinction instead:
--
--     WITH CHECK (tenant_id = current_tenant_id()
--                 OR (tenant_id IS NULL AND current_tenant_id() IS NULL))
--
-- Read as a truth table over the two things a session can be, this says
-- "you may write exactly the row that is yours":
--
--   session     row            decision
--   ---------   ------------   ------------------------------------------
--   unbound     global         allowed  — the platform operator's own row
--   unbound     a tenant's     refused  — NULL OR FALSE is NULL
--   tenant A    global         refused  — a tenant cannot freeze everyone
--   tenant A    A's own        allowed  — unchanged from 078
--   tenant A    tenant B's     refused  — unchanged from 078
--
-- Three of those five were already refused by 078 and stay refused. The
-- only behaviour that changes is the first: an unbound session gains the
-- global row and nothing else. In particular a tenant still cannot write
-- the global row, so this does not hand any tenant administrator a switch
-- that stops every other tenant on the deployment.
--
-- `aisoc_kill_switch_audit` carries the same strict check and the same fix.
-- Without it a switch that could be thrown would still have failed on its
-- audit row, and an emergency stop nobody can account for afterwards is a
-- different defect rather than a smaller one.
--
-- The USING clauses are re-stated unchanged. They already admit the global
-- row to every session, which is deliberate: a platform-wide stop a tenant
-- cannot see reads to them as an unexplained outage.

DROP POLICY IF EXISTS tenant_isolation ON aisoc_kill_switch;
CREATE POLICY tenant_isolation ON aisoc_kill_switch
    USING (tenant_id IS NULL OR tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (
        tenant_id = current_tenant_id()
        OR (tenant_id IS NULL AND current_tenant_id() IS NULL)
    );

DROP POLICY IF EXISTS tenant_isolation ON aisoc_kill_switch_audit;
CREATE POLICY tenant_isolation ON aisoc_kill_switch_audit
    USING (tenant_id IS NULL OR tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (
        tenant_id = current_tenant_id()
        OR (tenant_id IS NULL AND current_tenant_id() IS NULL)
    );

-- ── The permission that gates the routes ────────────────────────────────
--
-- Engaging the platform-wide stop is deployment-wide authority, so it is
-- not `settings:write`: a tenant administrator holds that one, and this
-- switch stops every *other* tenant too. It is seeded here rather than only
-- declared in `app/core/rbac_catalog.py` because 092 has already run on
-- every deployment and the runner tracks applied files, so a new permission
-- reaches an existing catalog only through a new migration. Same reasoning
-- as `workload_identities:*`: no tenant-scoped role is granted it, and only
-- the wildcard roles hold it.

INSERT INTO permissions (name, description, category) VALUES
    ('platform_kill_switch:write', 'Engage or release the platform-wide kill switch', 'system')
ON CONFLICT (name) DO NOTHING;
