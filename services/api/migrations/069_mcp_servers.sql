-- 069: which third-party MCP servers a tenant has chosen to trust, and how far.
--
-- Gap-closure Phase 5.2.
--
-- An MCP server is somebody else's code, reached over the network, whose
-- replies land in a prompt that decides what an agent does next. That makes
-- this table a trust boundary rather than a list of endpoints, and every
-- column below exists because leaving it out would have widened that boundary
-- by default.
--
-- Why the allowlist is a column and not a setting
-- -----------------------------------------------
-- `tool_allowlist` defaults to the empty array, so a server saved with no
-- further thought advertises nothing to the model. The alternative default,
-- "everything the server offers", puts the choice of what the agent may call
-- in the hands of the server operator rather than the tenant, and a server
-- that later adds a tool would silently widen the agent's reach with no
-- change on this side. The allowlist is checked before dispatch, in the
-- agents service, so a tool outside it never reaches the network.
--
-- Why a timeout and a byte cap are stored rather than inferred
-- ------------------------------------------------------------
-- Both are the tenant's answer to "how much of my investigation budget may
-- this third party consume". A global default would be one operator's answer
-- imposed on every deployment, and an unbounded reply is a denial of service
-- against the agent loop and a way to push a payload past whatever scanning
-- is applied. They are `NOT NULL` with CHECK bounds so no row can carry
-- "unbounded" at all.
--
-- Why stdio has its own columns, and why it is off by default
-- ----------------------------------------------------------
-- A stdio MCP server is a local process the agent starts. That is a different
-- risk from an HTTP request: it is code execution on the agents container,
-- and the argument vector is attacker-influenced the moment anything derives
-- it from tenant data. `transport` defaults to `streamable_http`, and the
-- agents service refuses a stdio row outright unless an operator has both
-- enabled stdio and allowlisted the command. The columns exist so the refusal
-- can name what was configured instead of failing on a shape it cannot parse.
--
-- Why the credential is a vault token and not a column
-- ----------------------------------------------------
-- `auth_config` holds `CredentialVault` ciphertext (`vault:v1:` / `vault:v2:`)
-- under the same convention connector credentials already use, rather than a
-- bespoke `token` column. One decryption path, one rotation procedure, one
-- place a reviewer has to look.

CREATE TABLE IF NOT EXISTS aisoc_mcp_servers (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The namespace segment in `mcp.<name>.<tool>`. Constrained to the shape
    -- an OpenAI function name may take, because it becomes part of one: a
    -- name outside this set would produce a tool the provider rejects, and
    -- the failure would surface as "the model never called it".
    name               TEXT        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,38}[a-z0-9]$'),
    label              TEXT,

    transport          TEXT        NOT NULL DEFAULT 'streamable_http'
                                   CHECK (transport IN ('streamable_http', 'stdio')),
    url                TEXT,
    command            TEXT,
    args               JSONB       NOT NULL DEFAULT '[]'::jsonb,

    -- CredentialVault ciphertext, same convention as connector auth_config.
    auth_config        JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- Empty means the agent may call nothing. Deliberate: see the header.
    tool_allowlist     JSONB       NOT NULL DEFAULT '[]'::jsonb,

    timeout_seconds    INTEGER     NOT NULL DEFAULT 20
                                   CHECK (timeout_seconds BETWEEN 1 AND 120),
    max_response_bytes INTEGER     NOT NULL DEFAULT 65536
                                   CHECK (max_response_bytes BETWEEN 1024 AND 1048576),

    -- A registered server is not a reachable one. Registration and use are
    -- separate decisions so an operator can write the row down, read what it
    -- discovers, and only then let an investigation reach it.
    enabled            BOOLEAN     NOT NULL DEFAULT FALSE,

    created_by         UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, name),

    -- Three properties, and the third is conditional on purpose.
    --
    -- A row may never carry both a URL and a command, and its target may
    -- never contradict its declared transport: those are states nothing can
    -- recover from, because there is no way to tell which field the operator
    -- meant.
    --
    -- A row that names *neither* is only wrong once it is enabled. Disabled
    -- is the default and is the half-finished draft an operator saves while
    -- they go and find the URL; refusing that would make the console's own
    -- create-then-configure flow impossible. An **enabled** row naming no
    -- target is a server the agent would try to reach and cannot, so that is
    -- refused here. The API refuses it earlier with a 422 naming the field,
    -- and the agents service refuses it again at discovery with a sentence an
    -- operator can act on; this is the floor under both.
    CONSTRAINT aisoc_mcp_servers_transport_target CHECK (
        (url IS NULL OR command IS NULL)
        AND (transport <> 'streamable_http' OR command IS NULL)
        AND (transport <> 'stdio' OR url IS NULL)
        AND (NOT enabled OR COALESCE(url, command) IS NOT NULL)
    )
);

COMMENT ON TABLE aisoc_mcp_servers IS
    'Third-party MCP servers one tenant has chosen to trust, with the bounds '
    'on that trust: an explicit tool allowlist, a timeout and a response-size '
    'cap. Empty allowlist means the agent may call nothing.';
COMMENT ON COLUMN aisoc_mcp_servers.tool_allowlist IS
    'Tool names the agent may call on this server. Checked before dispatch in '
    'the agents service, so a tool outside it never reaches the network. '
    'Defaults to empty, which advertises nothing.';
COMMENT ON COLUMN aisoc_mcp_servers.auth_config IS
    'CredentialVault ciphertext under the same convention connector '
    'credentials use. Never returned to a console caller.';
COMMENT ON COLUMN aisoc_mcp_servers.transport IS
    'streamable_http | stdio. stdio starts a local process on the agents '
    'container and is refused there unless an operator has enabled it and '
    'allowlisted the command.';

CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant
    ON aisoc_mcp_servers (tenant_id, enabled);

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) reach this
-- table; dropping it makes those silently see nothing. FORCE so the table
-- owner, which is the role that runs migrations, does not walk past it.
ALTER TABLE aisoc_mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_mcp_servers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_mcp_servers_tenant ON aisoc_mcp_servers;
CREATE POLICY aisoc_mcp_servers_tenant ON aisoc_mcp_servers
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_mcp_servers TO aisoc_app;
    END IF;
END
$$;
