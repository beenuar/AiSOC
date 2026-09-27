-- 068: where the SIEM reconciliation sweep got to, and why it stopped if it did.
--
-- Gap-closure Phase 2.1, closing D15.
--
-- The sweep polls a customer's own SIEM for the closures their analysts made
-- there, so a tenant whose queue lives in Splunk ES still accumulates a track
-- record. That is bounded work against somebody else's API on a timer, and
-- three properties have to survive a restart for it to be safe to run at all.
--
-- A watermark, so a window is read once
-- -------------------------------------
-- Without one the sweep re-reads the same hours forever: every tick costs the
-- vendor a search and returns findings that were already graded. `watermark_at`
-- is the close time the last successful pass reached, and the next window
-- starts there minus a small overlap, because a vendor's search index lags its
-- own close events and a window that starts exactly where the last one ended
-- steps over anything indexed late. The overlap is safe to re-read:
-- `reconcile_findings` only writes decisions whose `resolved_at` is still null,
-- so an overlapping finding is reported as `already_resolved` rather than
-- graded twice.
--
-- A distinction between a fault that will clear and one that will not
-- -------------------------------------------------------------------
-- `blocked_reason` is set when the vendor refused the stored credentials, or
-- when the credentials cannot be decrypted at all. Neither resolves by waiting,
-- so the sweep stops polling that connector and says what an operator must do.
-- `blocked_connector_updated_at` is what unblocks it: the sweep compares it to
-- `connectors.updated_at`, so re-saving the connector resumes polling and
-- nothing else does. A timer would be the churn this column exists to avoid,
-- and a manual reset would be a support ticket.
--
-- A record of the healthy case, not only the broken one
-- -----------------------------------------------------
-- `last_status` is written on every pass including the ones with nothing to
-- do. A sweep that silently stopped and a sweep whose tenant closed nothing
-- last night are indistinguishable from outside unless the quiet case is
-- recorded, and that ambiguity is the failure this table's health endpoint
-- exists to remove.
--
-- Keyed on the connector, not the tenant
-- --------------------------------------
-- A tenant can have Splunk and Sentinel both connected, each with its own
-- index lag, its own rate limit and its own credential lifetime. One watermark
-- across both would replay whichever is slower and skip whichever is faster.

CREATE TABLE IF NOT EXISTS aisoc_shadow_reconcile_state (
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id UUID        NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    -- Denormalised from the connector so a health read does not need a join
    -- and so the row still names its vendor after the connector is deleted
    -- and the cascade has not yet run.
    vendor       TEXT        NOT NULL,

    -- The close time the last successful pass reached. NULL before the first
    -- one, which is how the sweep knows to start from when measurement began
    -- rather than from the beginning of the vendor's retention.
    watermark_at TIMESTAMPTZ,

    last_run_at  TIMESTAMPTZ,
    -- ok | idle | blocked | transient. Written every pass, including the ones
    -- that found nothing, so "nothing to do" is a recorded state rather than
    -- an absence that looks like a stopped worker.
    last_status  TEXT        NOT NULL DEFAULT 'idle',
    -- One operator-facing sentence. Never an exception repr: a reason nobody
    -- can act on is the same as no reason.
    last_detail  TEXT,

    -- Counters from the most recent pass, kept apart because they answer
    -- different questions. `last_matched` at zero with `last_considered` high
    -- means the vendor finding id is not reaching the decision rows, which is
    -- a wiring fault rather than a quiet week.
    last_considered INTEGER  NOT NULL DEFAULT 0,
    last_matched     INTEGER NOT NULL DEFAULT 0,
    last_unmatched   INTEGER NOT NULL DEFAULT 0,

    -- Transient-failure run length, so a caller can tell one bad night from a
    -- fault that has outlived any explanation a retry would fix.
    consecutive_failures INTEGER NOT NULL DEFAULT 0,

    -- Set only for a condition that will not clear on its own.
    blocked_reason TEXT,
    blocked_at     TIMESTAMPTZ,
    -- `connectors.updated_at` as it stood when the block was recorded. The
    -- sweep resumes when the live value differs, which is exactly "somebody
    -- changed the connector" and nothing weaker.
    blocked_connector_updated_at TIMESTAMPTZ,

    -- Honoured before the next poll. Set from a vendor's own `Retry-After`,
    -- so a SIEM that asks us to slow down is obeyed rather than estimated.
    retry_after  TIMESTAMPTZ,

    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, connector_id)
);

COMMENT ON TABLE aisoc_shadow_reconcile_state IS
    'Per-connector progress of the shadow-reconciliation sweep: how far it has '
    'read, when it last ran, and whether what stopped it was transient or needs '
    'an operator.';
COMMENT ON COLUMN aisoc_shadow_reconcile_state.watermark_at IS
    'Latest vendor close time successfully reconciled. The next window starts '
    'here minus the configured overlap, never at the wall clock.';
COMMENT ON COLUMN aisoc_shadow_reconcile_state.blocked_connector_updated_at IS
    'connectors.updated_at at the moment of the block. Polling resumes when the '
    'live value differs, so a revoked credential stops churning and restarts on '
    'the one event that could have fixed it.';

-- The sweep picks its next batch by "least recently run, not blocked", so that
-- is the index. Partial on the unblocked rows because a blocked connector is
-- never a candidate and carrying it in the index only widens the scan.
CREATE INDEX IF NOT EXISTS idx_shadow_reconcile_due
    ON aisoc_shadow_reconcile_state (last_run_at NULLS FIRST)
    WHERE blocked_reason IS NULL;

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets the
-- cross-tenant sweep read every tenant's row; dropping it would make the sweep
-- silently see nothing, which here means every tenant's scorecard quietly
-- stopping with no error anywhere. FORCE so the owner does not walk past.
ALTER TABLE aisoc_shadow_reconcile_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_shadow_reconcile_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_shadow_reconcile_state_tenant ON aisoc_shadow_reconcile_state;
CREATE POLICY aisoc_shadow_reconcile_state_tenant ON aisoc_shadow_reconcile_state
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_shadow_reconcile_state TO aisoc_app;
    END IF;
END
$$;
