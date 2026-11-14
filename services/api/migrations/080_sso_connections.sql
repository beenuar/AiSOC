-- SSO connections: where an assertion's tenant and role mapping come from.
--
-- Parity plan 4.1.
--
-- The tenant is the whole reason this table exists. Both SSO handlers used
-- to issue a token with no tenant at all, and the obvious fix (read it from
-- the assertion) is the wrong one: an identity provider that can name its
-- own tenant can name somebody else's. So the tenant is a property of the
-- *connection*, which an administrator configured, and the assertion only
-- says who the person is.
--
-- Group mapping lives here for the same reason. An IdP group confers a role
-- only because an administrator in this deployment said it should.

CREATE TABLE IF NOT EXISTS aisoc_sso_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    provider        TEXT NOT NULL CHECK (provider IN ('oidc', 'saml')),

    -- The OIDC issuer URL, or the SAML entity id. Unique across the
    -- deployment: two tenants cannot claim the same issuer, or an assertion
    -- would be ambiguous about which tenant it provisions into.
    issuer          TEXT NOT NULL,

    display_name    TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,

    -- IdP group name to AiSOC role. `admin` and `platform_admin` are
    -- refused at the application layer: v14.0.0 made them unreachable from
    -- every API route so that only `bootstrap_admin` can mint one, and a
    -- group mapping would be a way back in.
    group_role_mapping  JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- What a user with no mapped group gets. The least-privileged role
    -- rather than nothing, because a user who authenticated and can then
    -- see nothing reads as a broken integration.
    default_role    TEXT NOT NULL DEFAULT 'viewer',

    -- Accepted by URL or by file, which the plan requires. Both nullable:
    -- an OIDC connection needs neither.
    metadata_url    TEXT,
    metadata_xml    TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One connection per issuer, deployment-wide. Not per tenant: that would
-- let a second tenant register the same issuer and race the first for every
-- sign-in.
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_sso_connections_issuer_idx
    ON aisoc_sso_connections (provider, issuer);

CREATE INDEX IF NOT EXISTS aisoc_sso_connections_tenant_idx
    ON aisoc_sso_connections (tenant_id);

ALTER TABLE aisoc_sso_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_sso_connections FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_sso_connections;
CREATE POLICY tenant_isolation ON aisoc_sso_connections
    -- The unbound arm is required and is the point: the SSO callback runs
    -- *before* there is a tenant to bind, because resolving this row is
    -- what decides the tenant. Without it the lookup would return nothing
    -- and every sign-in would fail with "no connection configured".
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    -- Writes stay bound: a tenant configures its own connection.
    WITH CHECK (tenant_id = current_tenant_id());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_sso_connections TO aisoc_app;
    END IF;
END
$$;
