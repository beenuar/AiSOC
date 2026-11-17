-- 162: support index for the resolved->closed auto-close sweep.
--
-- The worker visits each tenant and scans
-- `tenant_id = :t AND status = 'resolved' AND resolved_at <= cutoff` hourly.
-- Without a supporting index that is a sequential scan of the whole cases table
-- on a hot OLTP path. Partial index keeps it small: only open-but-resolved rows
-- are ever candidates for auto-close; leading on tenant_id matches the
-- per-tenant sweep shape.
CREATE INDEX IF NOT EXISTS idx_cases_resolved_pending_auto_close
    ON aisoc_cases (tenant_id, resolved_at)
    WHERE status = 'resolved' AND resolved_at IS NOT NULL;

COMMENT ON INDEX idx_cases_resolved_pending_auto_close IS
    'Partial index supporting the hourly resolved->closed auto-close sweep (CASE_AUTO_CLOSE_AFTER_DAYS)';
