-- 095_playbook_references.sql — the named destinations and endpoints a
-- playbook's `http` and `notify` steps address.
--
-- Every shipped pack addresses the outside world by *name*, never by host:
--
--     "url": "${IDP_BASE_URL}/users/{{alert.user}}/sessions"
--     "headers_env": "IDP_BEARER_HEADERS"
--     "webhook_env": "SLACK_SOC_WEBHOOK"
--     "service_key_env": "PD_SOC_KEY"
--
-- Nothing resolved any of them, so all 69 `http` steps died at the SSRF
-- guard with `scheme '' is not allowed` (urlsplit reads a string starting
-- `${` as having no scheme) and all 63 `notify` steps answered
-- `{"delivered": false, "reason": "no url"}`.
--
-- Why a name and not a URL in the playbook
-- ----------------------------------------
-- This is the security property, not a formatting convention. A pack is
-- shared content: a literal host in one is either somebody else's tenant or
-- an invitation to point a playbook wherever its author likes. With a name,
-- an author chooses which of *this tenant's* integrations to call and which
-- path under it, and cannot choose the origin. The resolved URL still goes
-- through the SSRF guard afterwards, because the stored value is tenant
-- data and therefore as untrusted as the step that asked for it.
--
-- Why one table for both halves
-- -----------------------------
-- `${IDP_BASE_URL}` and `SLACK_SOC_WEBHOOK` are the same idea twice: a
-- tenant-scoped, secret-aware, named handle on somewhere outside. Two tables
-- would be two sets of RLS policies, two CRUD surfaces and two places for a
-- credential to be stored in clear.
--
-- Off by default
-- --------------
-- `enabled` defaults FALSE. A reference that exists is not a reference a
-- playbook may use: importing a pack must not start paging an on-call rota
-- the moment somebody pastes a webhook in. The resolver treats a disabled
-- row as absent and says so.
--
-- Reversible: DROP TABLE IF EXISTS.

CREATE TABLE IF NOT EXISTS aisoc_playbook_references (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The token a playbook writes, without the `${}`. Upper snake case by
    -- convention and by the engine's own pattern, which is why the CHECK is
    -- here: a name the engine cannot parse is a row nobody will ever reach.
    name           TEXT        NOT NULL CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]*$'),

    -- What the resolved value *is*, which decides how it is handed to the
    -- step. A closed set so a new kind has to be added deliberately rather
    -- than arriving as free text that the resolver silently ignores.
    --   url          -> substituted into an `http` step's url
    --   headers      -> merged into an `http` step's request headers
    --   webhook      -> an incoming-webhook URL for slack or teams notify
    --   routing_key  -> a PagerDuty Events API v2 integration key
    --   smtp         -> relay host, port, credentials and recipients
    kind           TEXT        NOT NULL
                   CHECK (kind IN ('url', 'headers', 'webhook', 'routing_key', 'smtp')),

    -- Which notification channel a `notify` reference serves, so the
    -- dispatcher can pick the vendor arm without guessing from the name.
    -- Empty for `url` and `headers`.
    channel        TEXT        NOT NULL DEFAULT ''
                   CHECK (channel IN ('', 'slack', 'teams', 'email', 'pagerduty')),

    -- Optional binding to a connector instance. When set, a `url` reference
    -- follows that connector's configured base URL instead of carrying its
    -- own copy, so rotating a vendor's hostname is one edit rather than one
    -- per playbook. Not a cascade delete: removing a connector must not
    -- silently delete the reference and leave every playbook using it
    -- failing with "not configured" and no record of what it was.
    connector_id   UUID        REFERENCES connectors(id) ON DELETE SET NULL,

    -- The non-secret half. A base URL is configuration, not a credential,
    -- and encrypting it at rest would mean an operator cannot see which host
    -- a playbook will call without decrypting something.
    value          TEXT        NOT NULL DEFAULT '',

    -- The secret half, a `vault:` token from CredentialVault. Headers,
    -- webhook URLs (which are bearer credentials for both Slack and Teams),
    -- routing keys and SMTP passwords all live here.
    secret_value   TEXT        NOT NULL DEFAULT '',

    enabled        BOOLEAN     NOT NULL DEFAULT FALSE,

    description    TEXT        NOT NULL DEFAULT '',

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by     TEXT        NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS aisoc_playbook_references_tenant_name
    ON aisoc_playbook_references (tenant_id, name);

CREATE INDEX IF NOT EXISTS aisoc_playbook_references_tenant
    ON aisoc_playbook_references (tenant_id);

COMMENT ON TABLE aisoc_playbook_references IS
    'Named, tenant-scoped handles a playbook http/notify step addresses: ${IDP_BASE_URL}, '
    'SLACK_SOC_WEBHOOK, PD_SOC_KEY. Secrets are vault tokens in secret_value; enabled '
    'defaults FALSE so importing a pack cannot start paging anybody.';

DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_playbook_references ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_playbook_references FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_playbook_references';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_playbook_references '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_playbook_references TO aisoc_app';
    END IF;
END
$$;
