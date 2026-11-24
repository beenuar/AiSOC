-- the archive tier: closed lake months exported to object storage
-- in an open format, with a signed manifest and a verification trail.
--
-- The lake (ClickHouse `aisoc.raw_events`) holds at most `MAX_LAKE_DAYS`
-- (400) of events — the TTL is a hard ceiling nothing exempts. Everything
-- older exists only if it was exported first, so the archive is not a
-- convenience: it is the only path to multi-year retention, and these two
-- tables are its control plane and its ledger.
--
--   * `lake_archive_policies` — per-tenant opt-in (default OFF: writing a
--     tenant's events to a bucket is automation the tenant configures,
--     with their own bucket and their own credentials, vault-encrypted).
--   * `lake_archive_partitions` — one row per exported (tenant, month):
--     the manifest (row count, event-time bounds, schema + OCSF version,
--     per-file SHA-256, all signed with the evidence-bundle signer) and
--     the verification state. `exported` is a claim; `verified` means the
--     counts and checksums were READ BACK from the bucket and matched.
--
-- The export itself is composed by `app/services/lake_archive.py` and runs
-- inside ClickHouse (`INSERT INTO FUNCTION s3(...) ... FORMAT Parquet`):
-- the database that owns the rows writes the files, and verification
-- re-reads them through the same engine.

-- lane allocation: migration 170

CREATE TABLE IF NOT EXISTS lake_archive_policies (
    tenant_id       UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled         BOOLEAN     NOT NULL DEFAULT FALSE,
    -- How many years the archive promises. Attestation reports against
    -- this; the sweep never deletes archive objects (expiry of archived
    -- data is the bucket's lifecycle policy, stated in the docs).
    archive_years   INTEGER     NOT NULL DEFAULT 7
        CHECK (archive_years BETWEEN 1 AND 30),
    -- S3-compatible endpoint + bucket, the tenant's or the operator's own.
    s3_endpoint     TEXT        NOT NULL DEFAULT '',
    s3_bucket       TEXT        NOT NULL DEFAULT '',
    s3_region       TEXT        NOT NULL DEFAULT '',
    -- Vault-encrypted (CredentialVault `vault:v1:` tokens) — never plaintext.
    s3_access_key_enc TEXT      NOT NULL DEFAULT '',
    s3_secret_key_enc TEXT      NOT NULL DEFAULT '',
    -- WORM intent. Object Lock is a bucket property this service does not
    -- manage; enabling this records the operator's declaration that the
    -- bucket carries a default retention lock, and the attestation reports
    -- it as declared, never as verified.
    worm_declared   BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE lake_archive_policies IS
    'Per-tenant archive-tier policy. Off until a row enables it; '
    'credentials vault-encrypted; worm_declared is an operator declaration, '
    'reported as such and never as verified.';

CREATE TABLE IF NOT EXISTS lake_archive_partitions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The partition key: one calendar month of one tenant's events,
    -- exported only once it is CLOSED (strictly in the past).
    month           DATE        NOT NULL,

    status          TEXT        NOT NULL DEFAULT 'exported'
        CHECK (status IN ('exported', 'verified', 'failed')),

    -- The manifest, exactly as signed: row_count, event_time_min/max,
    -- schema_version, ocsf_version, files [{path, sha256, bytes}], plus
    -- the evidence-bundle signature envelope.
    manifest        JSONB       NOT NULL DEFAULT '{}'::jsonb,

    exported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at     TIMESTAMPTZ,
    -- When verification failed, what it saw — a count that differs, a
    -- checksum that differs, an object that is gone.
    failure_reason  TEXT,

    CONSTRAINT lake_archive_partitions_one_per_month UNIQUE (tenant_id, month)
);

COMMENT ON TABLE lake_archive_partitions IS
    'One row per exported (tenant, month) lake partition: the signed '
    'manifest and the verification state. exported is a claim; verified '
    'means counts and checksums were read back from the bucket and matched.';

CREATE INDEX IF NOT EXISTS idx_lake_archive_partitions_tenant
    ON lake_archive_partitions (tenant_id, month DESC);

-- RLS (154 shape): API writes under the request-bound GUC; the archive
-- sweep worker reads every opted-in tenant under no GUC.
ALTER TABLE lake_archive_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE lake_archive_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lake_archive_policies_tenant ON lake_archive_policies;
CREATE POLICY lake_archive_policies_tenant ON lake_archive_policies
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE lake_archive_partitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lake_archive_partitions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lake_archive_partitions_tenant ON lake_archive_partitions;
CREATE POLICY lake_archive_partitions_tenant ON lake_archive_partitions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON lake_archive_policies TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON lake_archive_partitions TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS lake_archive_partitions;
--     DROP TABLE IF EXISTS lake_archive_policies;
--
-- Objects already written to buckets are untouched either way; without the
-- ledger they are files whose provenance has to be re-established by hand.
