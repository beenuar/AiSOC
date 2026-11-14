-- AiSOC Row-Level Security (RLS) migration
-- Enables tenant isolation so that each session can only see/modify its own rows.
--
-- Prerequisites:
--   1. A low-privilege app role "aisoc_app" (created below if not present).
--   2. The application sets the session variable app.current_tenant_id before
--      executing any query (done by the SQLAlchemy RLS middleware in deps.py).
--
-- Tables covered: cases, alerts, connectors, detection_rules, api_keys,
--                 playbooks (if exists), audit_log (if exists).
--
-- IMPORTANT: tenants and users are intentionally excluded because the
-- application layer already filters by tenant_id through get_current_user().
-- RLS on users would create a chicken-and-egg problem during authentication.

-- ─── Create application role ──────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        CREATE ROLE aisoc_app LOGIN PASSWORD 'changeme';
    END IF;
END
$$;

-- Grant ownership-level access so the role can do DML on all tables
GRANT ALL ON ALL TABLES IN SCHEMA public TO aisoc_app;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO aisoc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO aisoc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO aisoc_app;

-- ─── Helper: current tenant from session variable ──────────────────────────────

-- The app sets: SET LOCAL app.current_tenant_id = '<uuid>';
-- This function returns it as UUID (NULL when not set = superuser bypass).
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v TEXT;
BEGIN
    BEGIN
        v := current_setting('app.current_tenant_id');
    EXCEPTION WHEN undefined_object THEN
        RETURN NULL;
    END;
    IF v IS NULL OR v = '' THEN
        RETURN NULL;
    END IF;
    RETURN v::UUID;
END;
$$;

-- ─── Enable RLS on each tenant-partitioned table ──────────────────────────────

-- cases
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cases_tenant ON cases;
CREATE POLICY cases_tenant ON cases
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- alerts
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alerts_tenant ON alerts;
CREATE POLICY alerts_tenant ON alerts
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- connectors
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS connectors_tenant ON connectors;
CREATE POLICY connectors_tenant ON connectors
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- detection_rules
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS detection_rules_tenant ON detection_rules;
CREATE POLICY detection_rules_tenant ON detection_rules
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- api_keys
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_keys_tenant ON api_keys;
CREATE POLICY api_keys_tenant ON api_keys
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- playbooks (conditional – table may not exist yet)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'playbooks') THEN
        EXECUTE 'ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY';
        EXECUTE 'ALTER TABLE playbooks FORCE ROW LEVEL SECURITY';
        EXECUTE 'DROP POLICY IF EXISTS playbooks_tenant ON playbooks';
        EXECUTE $p$
            CREATE POLICY playbooks_tenant ON playbooks
                USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
        $p$;
    END IF;
END
$$;

-- audit_log (conditional – created in the audit-log migration)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_log') THEN
        EXECUTE 'ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY';
        EXECUTE 'ALTER TABLE audit_log FORCE ROW LEVEL SECURITY';
        EXECUTE 'DROP POLICY IF EXISTS audit_log_tenant ON audit_log';
        EXECUTE $p$
            CREATE POLICY audit_log_tenant ON audit_log
                USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
        $p$;
    END IF;
END
$$;
