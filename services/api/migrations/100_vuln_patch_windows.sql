-- PR2 (docs/cve-patch-policy.md): patch-window tracking on the vulnerability
-- inventory. Additive only — no existing column is touched, so a stack that
-- rolls back the code keeps running against this schema unchanged.
--
-- Semantics:
--   environment    = 'test' | 'prod' bucket assigned at first materialization
--                    from hostname classification (app/patch_calendar.py);
--                    unknown hosts are 'prod' (fail closed toward the stricter
--                    window).
--   patch_due_date = window due date computed once at first materialization
--                    from first_found; re-polls MUST NOT move it (the due date
--                    is the operational promise, not observed state).
--   patch_status   = 'tracked' -> 'overdue' (due date passed) -> 'promoted'
--                    (an alert exists). 'tracked' is the default so rows
--                    written before the promotion job exists still enter the
--                    lifecycle on the next sweep.
--
-- The partial index serves the promotion sweep's hot path
-- (open rows by tenant + status + due date) without indexing the full
-- remediated history.

ALTER TABLE asset_vulnerabilities
    ADD COLUMN IF NOT EXISTS environment text;

ALTER TABLE asset_vulnerabilities
    ADD COLUMN IF NOT EXISTS patch_due_date date;

ALTER TABLE asset_vulnerabilities
    ADD COLUMN IF NOT EXISTS patch_status text NOT NULL DEFAULT 'tracked';

CREATE INDEX IF NOT EXISTS ix_asset_vuln_patch_due
    ON asset_vulnerabilities (tenant_id, patch_status, patch_due_date)
    WHERE remediated_at IS NULL;
