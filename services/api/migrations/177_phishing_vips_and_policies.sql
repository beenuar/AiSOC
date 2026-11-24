-- The VIP list BEC signals read, and the per-tenant
-- phishing policy switches (reporter feedback, org-level sender block).
--
-- Both policies default OFF: emailing a reporter and writing a block to the
-- tenant's mail gateway are actions a tenant opts into, never defaults.

-- lane allocation: migration 177

CREATE TABLE IF NOT EXISTS tenant_vips (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name    TEXT        NOT NULL,
    email           TEXT        NOT NULL,
    created_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tenant_vips_unique UNIQUE (tenant_id, email)
);

COMMENT ON TABLE tenant_vips IS
    'Who a BEC actor would impersonate. The vip_display_name signal '
    'fires when a sender borrows a VIP''s display name on a foreign address.';

CREATE TABLE IF NOT EXISTS phishing_policies (
    tenant_id                   UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    reporter_feedback_enabled   BOOLEAN     NOT NULL DEFAULT FALSE,
    block_sender_org_enabled    BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_by                  UUID        REFERENCES users(id) ON DELETE SET NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE phishing_policies IS
    'Per-tenant phishing switches both default OFF: reporter '
    'feedback notices and the org-level gateway sender block.';

ALTER TABLE tenant_vips ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_vips FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_vips_tenant ON tenant_vips;
CREATE POLICY tenant_vips_tenant ON tenant_vips
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE phishing_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE phishing_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS phishing_policies_tenant ON phishing_policies;
CREATE POLICY phishing_policies_tenant ON phishing_policies
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_vips TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON phishing_policies TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS tenant_vips;
--     DROP TABLE IF EXISTS phishing_policies;
