-- WS2.2 + WS2.3 — rehydration jobs and portability exports, as audited rows.
--
-- Rehydration brings an archived range back into a queryable table —
-- estimate FIRST (bytes, files, retrieval cost only when a price is
-- configured, otherwise null), then a job that loads the covered months
-- back through ClickHouse's own s3() reader into a scratch MergeTree table
-- with an expiry. Every rehydration records who asked and why: pulling
-- archived events back is exactly the operation an auditor asks about.
--
-- Portability exports reuse the same machinery pointed at a bucket the
-- TENANT names: Parquet + the signed manifest + a schema document, readable
-- with no AiSOC code (the gate proves it with DuckDB).

-- lane allocation: migration 171 (WS2)

CREATE TABLE IF NOT EXISTS lake_rehydrations (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    range_start     DATE        NOT NULL,
    range_end       DATE        NOT NULL,
    -- Optional narrowing, closed vocabulary: {"connector_type": "..."} —
    -- a filter the loader compiles into the SELECT, never caller SQL.
    filters         JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- The estimate shown before anything moved: bytes, files, months, and
    -- cost (null unless the deployment configured a price — a cost figure
    -- nobody configured would be an invented number).
    estimate        JSONB       NOT NULL DEFAULT '{}'::jsonb,

    status          TEXT        NOT NULL DEFAULT 'estimated'
        CHECK (status IN ('estimated', 'loading', 'ready', 'failed', 'expired')),
    -- The scratch ClickHouse table holding the rows while `ready`.
    table_name      TEXT        NOT NULL DEFAULT '',
    rows_loaded     BIGINT,
    failure_reason  TEXT,

    -- Audit: who asked, and why — required, not decorative.
    requested_by    UUID        REFERENCES users(id) ON DELETE SET NULL,
    reason          TEXT        NOT NULL,

    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT lake_rehydrations_range_sane CHECK (range_start <= range_end)
);

COMMENT ON TABLE lake_rehydrations IS
    'Audited rehydration jobs (WS2.2): archived months loaded back into a '
    'scratch ClickHouse table with an expiry. The estimate precedes the '
    'load; reason and requester are required.';

CREATE INDEX IF NOT EXISTS idx_lake_rehydrations_tenant
    ON lake_rehydrations (tenant_id, created_at DESC);
-- The expiry sweep's scan.
CREATE INDEX IF NOT EXISTS idx_lake_rehydrations_expiry
    ON lake_rehydrations (expires_at) WHERE status = 'ready';

CREATE TABLE IF NOT EXISTS lake_portability_exports (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    range_start     DATE        NOT NULL,
    range_end       DATE        NOT NULL,
    -- The TENANT's bucket — portability means the data leaves on their
    -- terms, to storage they name. Credentials are supplied per-request
    -- and are never persisted here.
    s3_endpoint     TEXT        NOT NULL,
    s3_bucket       TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'complete', 'failed')),
    -- Manifest of what was written: per-month rows/files/sha256 + the
    -- schema document path, signed like the archive manifests.
    manifest        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    failure_reason  TEXT,
    requested_by    UUID        REFERENCES users(id) ON DELETE SET NULL,
    reason          TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,

    CONSTRAINT lake_portability_range_sane CHECK (range_start <= range_end)
);

COMMENT ON TABLE lake_portability_exports IS
    'Audited portability exports (WS2.3): Parquet + signed manifest + schema '
    'document written to a bucket the tenant names, readable with no AiSOC '
    'code. Request credentials are used for the job and never persisted.';

CREATE INDEX IF NOT EXISTS idx_lake_portability_tenant
    ON lake_portability_exports (tenant_id, created_at DESC);

-- RLS (154 shape), both tables: API writes bound, workers sweep unbound.
ALTER TABLE lake_rehydrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE lake_rehydrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lake_rehydrations_tenant ON lake_rehydrations;
CREATE POLICY lake_rehydrations_tenant ON lake_rehydrations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE lake_portability_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE lake_portability_exports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lake_portability_exports_tenant ON lake_portability_exports;
CREATE POLICY lake_portability_exports_tenant ON lake_portability_exports
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON lake_rehydrations TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON lake_portability_exports TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS lake_portability_exports;
--     DROP TABLE IF EXISTS lake_rehydrations;
--
-- Scratch rehydration tables in ClickHouse (aisoc.rehydrated_*) are
-- dropped by the sweep on expiry; without this ledger, drop them by hand.
