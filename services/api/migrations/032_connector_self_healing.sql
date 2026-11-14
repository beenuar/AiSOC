-- 032_connector_self_healing.sql
-- Workstream 5: self-healing bookkeeping for the connectors table.
--
-- Adds the four columns the auto-OAuth-refresh worker, the
-- backfill-on-outage worker, and the freshness-SLO badge UI need to do
-- their jobs without inferring state from the existing
-- last_sync / last_health_check signals (which both move on every
-- poll, including empty polls).
--
--   oauth_refresh_failures : Consecutive refresh failures for OAuth
--                            -provisioned connectors. Reset to 0 on a
--                            successful refresh. The worker raises an
--                            operator-visible alarm at >= 3 (per plan
--                            §5: "Alarms when refresh fails 3x").
--
--   oauth_last_refresh_at  : Wall clock of the most recent successful
--                            refresh. Used by the worker to throttle
--                            its scan and by the UI to show "token
--                            rotated 3 min ago".
--
--   last_outage_at         : When the connector first transitioned to
--                            ``health_status='unhealthy'`` (and stayed
--                            there). NULL while healthy. The backfill
--                            worker reads this on recovery — if the
--                            outage spanned more than 30 min we kick
--                            off a backfill polling job from the last
--                            known good cursor.
--
--   last_backfill_at       : Wall clock of the most recent backfill
--                            run. Stops the worker from re-firing on
--                            every recovery flap and gives the UI a
--                            "backfilled to <ts>" affordance.
--
-- All four are nullable / default 0 so existing rows are valid.
-- Idempotent — running this migration twice is safe.

BEGIN;

ALTER TABLE connectors
    ADD COLUMN IF NOT EXISTS oauth_refresh_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS oauth_last_refresh_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_outage_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_backfill_at TIMESTAMPTZ;

-- Partial index so the OAuth refresh worker can find rows that need
-- attention (oauth_provisioned + auth_config has expires_at) without
-- scanning every connector row in the table. The worker will still
-- filter on auth_config->>'expires_at' < now() + 5 min in Python; this
-- index just narrows the candidate set.
CREATE INDEX IF NOT EXISTS idx_connectors_oauth_provisioned
    ON connectors(tenant_id, oauth_provisioned)
    WHERE oauth_provisioned = TRUE;

-- Partial index on currently-unhealthy rows so the backfill worker can
-- watch the recovery transition cheaply.
CREATE INDEX IF NOT EXISTS idx_connectors_unhealthy
    ON connectors(tenant_id, health_status, last_outage_at)
    WHERE health_status = 'unhealthy';

COMMIT;
