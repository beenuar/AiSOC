-- migrations/022_institutional_memory.sql
-- Tier-1 capability 1.5: analyst-override feedback loop.
--
-- Formalizes the institutional-memory table that until now was created
-- lazily by the agents service on first write. Deployments that run only
-- the API service (or have not yet exercised an investigation) still get
-- the table, the index, and the override-tagging column. The agents
-- service uses CREATE TABLE IF NOT EXISTS so the two paths converge.
--
-- Schema deliberately matches services/agents/app/memory/institutional.py
-- so the agents service's asyncpg writer stays a drop-in.

CREATE TABLE IF NOT EXISTS aisoc_institutional_memory (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    key               TEXT NOT NULL,
    value             JSONB NOT NULL,
    tags              TEXT[] NOT NULL DEFAULT '{}',
    analyst_override  BOOLEAN NOT NULL DEFAULT FALSE,
    override_reason   TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, key)
);

CREATE INDEX IF NOT EXISTS aisoc_institutional_memory_tenant_key
    ON aisoc_institutional_memory (tenant_id, key);

CREATE INDEX IF NOT EXISTS aisoc_institutional_memory_tags
    ON aisoc_institutional_memory USING GIN (tags);

CREATE INDEX IF NOT EXISTS aisoc_institutional_memory_override
    ON aisoc_institutional_memory (tenant_id, analyst_override)
    WHERE analyst_override = TRUE;

COMMENT ON TABLE aisoc_institutional_memory IS
    'Tier-1.1 institutional memory + Tier-1.5 analyst-override store. '
    'Keyed by (tenant_id, key); analyst_override=TRUE indicates an entry '
    'that originated from a verdict correction and should be retrieved on '
    'every new alert with a matching signature.';
COMMENT ON COLUMN aisoc_institutional_memory.key IS
    'Stable signature, e.g. override:<sha1(category|connector_type|technique)>.';
COMMENT ON COLUMN aisoc_institutional_memory.tags IS
    'Free-form labels for retrieval — typically MITRE technique IDs, '
    'connector type, or a coarse category.';
