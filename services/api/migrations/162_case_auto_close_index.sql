-- 162: support index for the resolved->closed auto-close sweep.
--
-- The worker scans `status = 'resolved' AND resolved_at <= cutoff` hourly.
-- Without a supporting index that is a sequential scan of the whole cases table
-- on a hot OLTP path. Partial index keeps it small: only open-but-resolved rows
-- are ever candidates for auto-close.
CREATE INDEX IF NOT EXISTS idx_cases_resolved_pending_auto_close
    ON aisoc_cases (resolved_at)
    WHERE status = 'resolved' AND resolved_at IS NOT NULL;

COMMENT ON INDEX idx_cases_resolved_pending_auto_close IS
    'Partial index supporting the hourly resolved->closed auto-close sweep (CASE_AUTO_CLOSE_AFTER_DAYS)';
