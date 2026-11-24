-- MCP manifests, versioned per (tenant, server).
--
-- A poisoned MCP server attacks through its manifest: a tool description
-- that quietly grows instructions between sessions, or a new state-changing
-- tool appearing on a server sanctioned when it only read. Drift is only
-- visible against a record of what the manifest USED to say, so the
-- recorder versions each distinct manifest it sees: same content → the
-- current version's last_seen advances; changed content → a new version
-- row, and the comparison against the previous one is the detection.
--
-- What a row holds per tool: name, the description's SHA-256 (hashed in
-- the customer's process by the SDK — the text itself never ships), the
-- annotations, and any flagged instruction-pattern names with their ≤80
-- character snippet. Full descriptions are deliberately nowhere.

-- lane allocation: migration 176

CREATE TABLE IF NOT EXISTS aisoc_ai_mcp_manifests (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    server_name     TEXT        NOT NULL,
    version         INTEGER     NOT NULL,
    -- [{name, description_sha256, annotations, flagged?, snippet?}]
    tools           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_ai_mcp_manifests_version UNIQUE (tenant_id, server_name, version)
);

COMMENT ON TABLE aisoc_ai_mcp_manifests IS
    'Versioned MCP manifests per (tenant, server) — hashes and flags '
    'only; tool description text never ships. Drift between consecutive '
    'versions is the detection.';

CREATE INDEX IF NOT EXISTS idx_ai_mcp_manifests_lookup
    ON aisoc_ai_mcp_manifests (tenant_id, server_name, version DESC);

-- RLS (154 shape): the API reads bound; the fusion recorder writes under
-- its own non-request session.
ALTER TABLE aisoc_ai_mcp_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_ai_mcp_manifests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_ai_mcp_manifests_tenant ON aisoc_ai_mcp_manifests;
CREATE POLICY aisoc_ai_mcp_manifests_tenant ON aisoc_ai_mcp_manifests
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_ai_mcp_manifests TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS aisoc_ai_mcp_manifests;
--
-- Losing the history means drift detection restarts from the next manifest
-- it sees; nothing else reads the table.
