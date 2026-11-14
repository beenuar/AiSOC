-- 161: disposition authorship.
--
-- alerts.disposition has no authorship: both the analyst override
-- (POST /feedback/alert-override, alerts:write) and the AI auto-triage
-- (investigator/ledger.py) write into the same column. That made any
-- disposition-keyed suppression ungovernable -- a single uncorroborated AI
-- false-positive verdict would outvote every future recurrence of the
-- fingerprint (the GHSA-qp9f-459j-w89c condition, reintroduced through a
-- side door; see review on #1875).
--
-- disposition_source names WHO wrote the current disposition value:
--   analyst -> human override (alerts:write endpoint)
--   ai      -> auto-triage verdict
--   NULL    -> never dispositioned, or written before this column existed.
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS disposition_source TEXT
        CHECK (disposition_source IN ('analyst', 'ai'));

-- Backfill: existing AI-authored dispositions are indistinguishable from
-- analyst ones, so leave them NULL (unknown provenance) rather than guess.
-- Unknown provenance is treated as NOT durable suppression downstream,
-- which is the safe default.

COMMENT ON COLUMN alerts.disposition_source IS
    'Who authored the current disposition: analyst (human override) | ai (auto-triage) | NULL (unknown/never)';
