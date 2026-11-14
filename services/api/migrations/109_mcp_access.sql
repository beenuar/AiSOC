-- 109_mcp_access.sql — who may call which MCP tool, and the queue that holds
-- the ones a key alone is not enough for.
--
-- Depth plan 9.1 (parity 6.6). `services/mcp` was stdio-only: an MCP host
-- started it as a child process with one operator's API key in the host's
-- config file. Nothing in this repository deployed it, and nothing recorded
-- what it read. Moving it onto HTTP is what makes these two tables
-- necessary, because the transport change is also a threat-model change:
-- several tenants now share one process, and the credential arrives in the
-- request rather than in the environment.
--
-- aisoc_mcp_tool_grants — the tenant-level switch
-- -----------------------------------------------
-- A key's scopes say what a *credential* may do. This says what a *tenant*
-- has turned on, which is a different decision and belongs to a different
-- person: a tenant administrator who has decided their estate's event lake
-- is not something an assistant reaches, whatever key somebody mints.
--
-- Absence of a row is not "denied". It means "the tool's own default
-- applies", and the default is declared per tool in
-- `app/data/mcp_tool_catalog.json`: read-only tools default on, anything
-- that writes defaults off. Storing only the deliberate decisions keeps the
-- table small and, more usefully, keeps "nobody has thought about this tool"
-- distinguishable from "somebody turned it off" — which a NOT NULL boolean
-- seeded for every tool would have destroyed.
--
-- aisoc_mcp_tool_approvals — the queue for everything that is not a read
-- ---------------------------------------------------------------------
-- A tool whose registry entry says `readOnlyHint: false` cannot run on the
-- strength of a bearer token. The authorize path creates a row here instead
-- and answers the caller with its id, so the refusal is actionable rather
-- than a dead end: a human approves it in the console and the same call
-- succeeds on retry.
--
-- `argument_fingerprint` is a SHA-256 over the canonical argument *names and
-- values* the caller supplied. An approval has to be for a specific call,
-- not for a verb: approving "run an investigation on case A" must not
-- authorise "run an investigation on case B". It is a hash rather than the
-- arguments themselves because those arguments routinely carry hostnames
-- and queries, and this table is read by the console.
--
-- `expires_at` is NOT NULL for the reason every standing grant in this tree
-- is time-boxed: an approval that never expires is a permission, and nobody
-- decided to grant a permission.
--
-- Reversible: DROP TABLE IF EXISTS, either order (no FK between them).

CREATE TABLE IF NOT EXISTS aisoc_mcp_tool_grants (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Matches `name` in app/data/mcp_tool_catalog.json. Not an FK: the
    -- catalogue is a generated file held in parity with the TypeScript
    -- registry by scripts/check_mcp_over_http.py, and a row for a tool
    -- that has since been removed should survive as history rather than
    -- block the removal.
    tool_name       TEXT        NOT NULL,

    enabled         BOOLEAN     NOT NULL,

    -- Who flipped it. Free text because the actor may be a user email or an
    -- API key prefix, and an auditor reading this wants whichever it was.
    decided_by      TEXT        NOT NULL DEFAULT '',

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_mcp_tool_grants_unique UNIQUE (tenant_id, tool_name)
);

CREATE INDEX IF NOT EXISTS aisoc_mcp_tool_grants_tenant
    ON aisoc_mcp_tool_grants (tenant_id);

CREATE TABLE IF NOT EXISTS aisoc_mcp_tool_approvals (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    tool_name       TEXT        NOT NULL,
    -- SHA-256 hex over the canonicalised arguments. See the header for why
    -- this is a digest and not the arguments.
    argument_fingerprint CHAR(64) NOT NULL,

    -- The key prefix (never the key) or user email that asked.
    requested_by    TEXT        NOT NULL DEFAULT '',

    state           TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'approved', 'denied', 'consumed', 'expired')),

    decided_by      TEXT,
    decided_at      TIMESTAMPTZ,
    -- Why it was denied, or any note the approver left. Shown to the caller.
    decision_note   TEXT        NOT NULL DEFAULT '',

    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The authorize path's lookup: "is there a live approval for exactly this
-- call?". Partial on `approved` because pending and consumed rows accumulate
-- and the hot query only ever wants the one state.
CREATE INDEX IF NOT EXISTS aisoc_mcp_tool_approvals_live_idx
    ON aisoc_mcp_tool_approvals (tenant_id, tool_name, argument_fingerprint)
    WHERE state = 'approved';

-- The console's queue.
CREATE INDEX IF NOT EXISTS aisoc_mcp_tool_approvals_pending_idx
    ON aisoc_mcp_tool_approvals (tenant_id, created_at DESC)
    WHERE state = 'pending';

COMMENT ON TABLE aisoc_mcp_tool_grants IS
    'Per-tenant MCP tool switch. An absent row means the tool default in '
    'app/data/mcp_tool_catalog.json applies, which keeps "nobody decided" '
    'distinguishable from "somebody turned it off".';

COMMENT ON TABLE aisoc_mcp_tool_approvals IS
    'One row per non-read-only MCP tool call that needed a human. The '
    'fingerprint binds an approval to a specific call, so approving an '
    'investigation on one case does not authorise one on another.';

-- Written out per table rather than looped with format(): a loop is shorter
-- and makes the policy invisible to grep and to
-- scripts/check_tenant_query_predicates.py, which reads migrations to learn
-- which tables carry one.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_mcp_tool_grants ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_mcp_tool_grants FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_mcp_tool_grants';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_mcp_tool_grants '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    EXECUTE 'ALTER TABLE aisoc_mcp_tool_approvals ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_mcp_tool_approvals FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_mcp_tool_approvals';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_mcp_tool_approvals '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_mcp_tool_grants TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_mcp_tool_approvals TO aisoc_app';
    END IF;
END
$$;
