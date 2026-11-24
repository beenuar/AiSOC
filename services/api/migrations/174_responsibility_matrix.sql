-- the co-managed responsibility matrix: who owns which act.
--
-- A co-managed SOC splits work: the provider triages, the customer approves
-- containment on crown-jewel assets, both share response on the rest. The
-- platform had no way to SAY that, let alone enforce it — every analyst
-- with a role's permissions could act wherever the role reached.
--
-- One table, and one rule that keeps it safe: a matrix row can only
-- NARROW. The enforcement point (app/services/responsibility.py) runs
-- AFTER the ordinary permission check and can refuse an act the role would
-- have allowed; it can never grant one the role refused. A tenant with no
-- rows gets exactly the behaviour they had before the table existed.
--
-- `party` is which side of the engagement a user belongs to. It is
-- resolved from the MSSP relationship: a user whose home tenant is the
-- managing parent acts as 'provider' inside the child tenant; a user whose
-- home tenant IS the tenant acts as 'customer'. 'shared' rows allow both.

-- lane allocation: migration 174

CREATE TABLE IF NOT EXISTS responsibility_matrix (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- What the row governs. '*' is the wildcard in every dimension, so a
    -- tenant can write "containment verbs are customer-only" in one row.
    activity        TEXT        NOT NULL CHECK (activity IN ('triage', 'approval', 'action')),
    alert_class     TEXT        NOT NULL DEFAULT '*',
    severity        TEXT        NOT NULL DEFAULT '*'
        CHECK (severity IN ('*', 'info', 'low', 'medium', 'high', 'critical')),
    verb            TEXT        NOT NULL DEFAULT '*',

    -- Who owns it. 'shared' means both parties may act.
    owner           TEXT        NOT NULL CHECK (owner IN ('provider', 'customer', 'shared')),

    created_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT responsibility_matrix_one_rule
        UNIQUE (tenant_id, activity, alert_class, severity, verb)
);

COMMENT ON TABLE responsibility_matrix IS
    'Per-tenant co-managed responsibility matrix: which party '
    '(provider/customer/shared) owns triage, approval and action per alert '
    'class, severity and verb. Enforcement narrows only — a row can refuse '
    'an act the role allowed, never grant one it refused.';

CREATE INDEX IF NOT EXISTS idx_responsibility_matrix_tenant
    ON responsibility_matrix (tenant_id, activity);

ALTER TABLE responsibility_matrix ENABLE ROW LEVEL SECURITY;
ALTER TABLE responsibility_matrix FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS responsibility_matrix_tenant ON responsibility_matrix;
CREATE POLICY responsibility_matrix_tenant ON responsibility_matrix
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON responsibility_matrix TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS responsibility_matrix;
--
-- Dropping the table returns every tenant to role-only authorization —
-- the widening direction, which is why the enforcement treats an absent
-- row set as "no narrowing" rather than "deny".
