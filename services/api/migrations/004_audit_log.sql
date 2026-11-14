-- AiSOC Immutable Audit Log migration
-- Creates an append-only audit_log table with Postgres-enforced immutability.

-- ============================================================
-- Audit log table
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
    actor_email  VARCHAR(255),
    actor_ip     INET,
    action       VARCHAR(200) NOT NULL,  -- e.g. "cases:create", "roles:delete"
    resource     VARCHAR(200),           -- e.g. "case", "role"
    resource_id  VARCHAR(200),           -- UUID or other identifier of affected object
    changes      JSONB,                  -- before/after or delta, optional
    metadata     JSONB,                  -- request_id, user_agent, etc.
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor         ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action        ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource      ON audit_log(resource, resource_id);

-- ============================================================
-- Immutability: deny UPDATE and DELETE via a trigger
-- ============================================================
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log rows are immutable (attempted %)' , TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- ============================================================
-- RLS: each tenant sees only its own rows
-- ============================================================
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_tenant ON audit_log;
CREATE POLICY audit_tenant ON audit_log
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);
