-- Depth plan 4.3, third bullet — a query over cold data reports an
-- estimated cost and a progress state instead of timing out silently.
--
-- Why a table rather than an in-process dictionary
-- ------------------------------------------------
-- A cold-tier scan outlives the request that started it, and the API runs
-- more than one replica. An in-process job registry would lose every job
-- on a restart and answer 404 for half of them on a second replica, which
-- is the shape this repository has already shipped three times (API keys,
-- marketplace installs, the action-approval store).
--
-- `progress_ratio` is deliberately nullable. ClickHouse publishes
-- `total_rows_approx` on a best-effort basis, so a running query can have
-- a row count and no denominator. A progress bar that invents 100%
-- because the denominator was zero is worse than one that says it does
-- not know.
--
-- `estimate` is stored as written at submit time and never recomputed.
-- It is the number the analyst agreed to before the scan started; moving
-- it afterwards would make the record of what they were told untrue.

CREATE TABLE IF NOT EXISTS lake_query_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The authenticated principal that submitted it. Nullable only
    -- because a service principal has no user row; a job with neither is
    -- refused at the API.
    submitted_by    UUID,
    submitted_email TEXT,

    -- The rewritten, tenant-scoped SQL. Stored rather than the caller's
    -- original: the original has no tenant predicate, and a re-run from
    -- this row must not be able to resolve to a different tenant than the
    -- submission did.
    rewritten_sql   TEXT NOT NULL,
    row_cap         INTEGER NOT NULL,
    referenced_tables TEXT[] NOT NULL DEFAULT '{}',

    -- The ClickHouse query id, so progress can be read from
    -- system.processes and the query can be killed.
    query_id        TEXT NOT NULL UNIQUE,

    status          TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued','running','succeeded','failed','cancelled')),

    estimate        JSONB NOT NULL DEFAULT '{}',

    rows_read       BIGINT NOT NULL DEFAULT 0,
    bytes_read      BIGINT NOT NULL DEFAULT 0,
    total_rows_approx BIGINT NOT NULL DEFAULT 0,
    progress_ratio  DOUBLE PRECISION,

    -- The result, bounded by row_cap at submit time. Held here rather
    -- than streamed because the caller is polling: there is nothing to
    -- stream to.
    result_columns  TEXT[],
    result_rows     JSONB,
    row_count       INTEGER,

    -- Why it ended, when it ended badly. A failed job with no reason is
    -- indistinguishable from one nobody looked at.
    error           TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The poll path: one tenant's jobs, newest first.
CREATE INDEX IF NOT EXISTS lake_query_jobs_tenant_idx
    ON lake_query_jobs (tenant_id, created_at DESC);

-- The runner's claim path. Partial, because a finished job is never
-- claimed again and indexing the history would grow without bound.
CREATE INDEX IF NOT EXISTS lake_query_jobs_queued_idx
    ON lake_query_jobs (created_at)
    WHERE status = 'queued';

COMMENT ON TABLE lake_query_jobs IS
    'Cold-tier lake queries that outlive their request. A job carries the estimate the analyst '
    'agreed to before the scan started, and the server''s own progress counters while it runs.';

COMMENT ON COLUMN lake_query_jobs.progress_ratio IS
    'Nullable on purpose: ClickHouse publishes total_rows_approx best-effort, so a running query '
    'can have a numerator and no denominator. NULL means unknown, never zero.';

COMMENT ON COLUMN lake_query_jobs.estimate IS
    'As written at submit time and never recomputed. It is the number the analyst agreed to.';

-- Written out rather than looped with format(), so the policy stays
-- visible to grep and to scripts/check_tenant_query_predicates.py.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE lake_query_jobs ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE lake_query_jobs FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON lake_query_jobs';
    -- The unbound-session arm in WITH CHECK mirrors USING, and is the same
    -- shape 079/081/104/117/118 use: the claim runner and the stuck sweep are
    -- GUC-less worker sessions whose UPDATEs re-check the new row, so without
    -- it no job could ever be claimed or finished under the runtime role —
    -- the live suite caught exactly that once its DSN moved off the owner.
    EXECUTE
        'CREATE POLICY tenant_isolation ON lake_query_jobs '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON lake_query_jobs TO aisoc_app';
    END IF;
END
$$;
