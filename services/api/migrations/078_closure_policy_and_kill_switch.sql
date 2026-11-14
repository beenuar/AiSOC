-- Per-tenant closure policy, and a kill switch over closure and dispatch.
--
-- Parity plan 2.1 and 2.2.
--
-- Three things were wrong before this. Closure used one process-wide
-- threshold (`AISOC_AUTO_CLOSE_THRESHOLD`, default 0.85) for every tenant
-- and every alert class. The only reader of an earned `auto_close` grant
-- selected `auto_execute` on action verbs, so a grant earned in shadow mode
-- changed nothing. And the console's per-action thresholds were read only by
-- `services/agents/app/policy/guardrails.py`, which the reachability gate
-- reports as having no production importer at all.
--
-- The kill switch is separate from the policy on purpose. A policy change is
-- a considered edit to how a tenant wants to run; a kill switch is what
-- somebody reaches for at 3am, and it has to stop closure and dispatch
-- without a restart and without reasoning about per-class rows.

-- ── Closure policy ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS aisoc_closure_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The alert class this row governs. NULL is the tenant's default, which
    -- is what a class with no row of its own falls back to.
    alert_class     TEXT,

    -- Off by default at every level. A tenant that has never opened this
    -- screen must not start closing alerts because a row appeared.
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,

    -- NULL means "use the process-wide threshold", so the change is additive
    -- and a deployment that sets neither behaves exactly as before.
    threshold       DOUBLE PRECISION
                    CHECK (threshold IS NULL OR (threshold >= 0.0 AND threshold <= 1.0)),

    -- When set, closure additionally requires an earned `auto_close` grant
    -- for this class in `autonomy_grants`. A tenant can therefore say
    -- "enabled, but only once shadow mode has earned it".
    require_grant   BOOLEAN NOT NULL DEFAULT TRUE,

    updated_by      TEXT,
    reason          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per class per tenant. The partial index covers the default row,
-- because a UNIQUE over a nullable column does not constrain NULLs.
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_closure_policies_tenant_class_idx
    ON aisoc_closure_policies (tenant_id, alert_class)
    WHERE alert_class IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_closure_policies_tenant_default_idx
    ON aisoc_closure_policies (tenant_id)
    WHERE alert_class IS NULL;

ALTER TABLE aisoc_closure_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_closure_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_closure_policies;
CREATE POLICY tenant_isolation ON aisoc_closure_policies
    -- `current_tenant_id()` rather than a raw `current_setting(...)::uuid`.
    -- It is the helper migration 002 defines and migration 069 uses, and it
    -- returns NULL for an unset *or empty* setting. Writing the guard as
    -- `setting = '' OR tenant_id = setting::uuid` failed the live
    -- two-tenant isolation test with `invalid input syntax for type uuid:
    -- ""`, because Postgres does not promise to short-circuit the OR and
    -- evaluated the cast anyway.
    --
    -- The NULL arm is required, not a loosening. The fused-alert worker in
    -- `services/agents` is the main reader and it consumes from Kafka on a
    -- connection that binds no tenant: without this it would see zero rows,
    -- fall through to the process-wide threshold, and report success. A
    -- policy nobody can read is worse than no policy, because the console
    -- would show it as set.
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    -- Writes stay strict. Only a session that has bound a tenant may write,
    -- and only its own row.
    WITH CHECK (tenant_id = current_tenant_id());

-- ── Kill switch ─────────────────────────────────────────────────────────
--
-- Global and per tenant, in one table. `tenant_id IS NULL` is the global
-- row, which is the operator-of-the-platform switch; a tenant row is the
-- tenant's own.
--
-- Deliberately NOT row-level-security scoped the same way: the global row
-- has no tenant and a tenant must be able to read that it is engaged, or a
-- platform-wide stop would look to them like an unexplained outage. Writes
-- are gated by permission at the route, and a tenant can only write its own
-- row.

CREATE TABLE IF NOT EXISTS aisoc_kill_switch (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,

    engaged         BOOLEAN NOT NULL DEFAULT FALSE,

    -- A switch with no reason is one nobody can safely disengage: the next
    -- operator cannot tell a deliberate freeze from a forgotten test.
    reason          TEXT NOT NULL,
    engaged_by      TEXT NOT NULL,
    engaged_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_by     TEXT,
    released_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS aisoc_kill_switch_tenant_idx
    ON aisoc_kill_switch (tenant_id)
    WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_kill_switch_global_idx
    ON aisoc_kill_switch ((TRUE))
    WHERE tenant_id IS NULL;

ALTER TABLE aisoc_kill_switch ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_kill_switch FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_kill_switch;
CREATE POLICY tenant_isolation ON aisoc_kill_switch
    USING (tenant_id IS NULL OR tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (
        -- A tenant writes only its own row. The global row is written by the
        -- platform operator through a session with no tenant set.
        tenant_id = current_tenant_id()
    );

-- ── Audit of every switch change ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS aisoc_kill_switch_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    action          TEXT NOT NULL CHECK (action IN ('engage', 'release')),
    reason          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    scope           TEXT NOT NULL CHECK (scope IN ('global', 'tenant')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS aisoc_kill_switch_audit_tenant_idx
    ON aisoc_kill_switch_audit (tenant_id, created_at DESC);

ALTER TABLE aisoc_kill_switch_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_kill_switch_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_kill_switch_audit;
CREATE POLICY tenant_isolation ON aisoc_kill_switch_audit
    USING (tenant_id IS NULL OR tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

-- ── Grants ──────────────────────────────────────────────────────────────
--
-- Guarded, because the role does not exist on a developer's machine and a
-- migration that fails there is a migration nobody runs.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_closure_policies TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_kill_switch TO aisoc_app;
        GRANT SELECT, INSERT ON aisoc_kill_switch_audit TO aisoc_app;
    END IF;
END
$$;
