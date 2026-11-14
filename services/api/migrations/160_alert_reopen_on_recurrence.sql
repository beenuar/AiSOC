-- Reopening a closed alert when its detection fires again.
--
-- GHSA-qp9f-459j-w89c, reported by Jake Davis.
--
-- Why this migration exists
-- -------------------------
-- `alert_sink._INSERT_SQL` deduplicates with
--
--     WHERE NOT EXISTS (
--         SELECT 1 FROM alerts WHERE tenant_id = $2 AND dedup_hash = $11::text
--     )
--
-- and that predicate carries no status. Once an analyst closes the alert, the
-- closed row keeps absorbing every later firing of the same detection: the
-- insert is filtered, the sink answers DUPLICATE, and no open alert is ever
-- created. An attacker who trips a detection, waits for the alert to be
-- closed, and repeats the activity is invisible to the queue. That is
-- evasion of a detection that is working, not a cosmetic dedup complaint.
--
-- Why reopen rather than insert a second row
-- ------------------------------------------
-- The reporter named two remedies and left the choice open: reopen the closed
-- alert, or create a new row under a time-bucketed fingerprint. The database
-- settles it. `uq_alerts_tenant_dedup` (migration 120) is UNIQUE on
-- `(tenant_id, dedup_hash) WHERE dedup_hash IS NOT NULL`, so a second row for
-- the same fingerprint cannot exist at all. Reaching the new-row remedy would
-- mean changing `RawAlert.fingerprint()` itself to fold in a time bucket,
-- which changes the dedup key for every consumer of it -- the Redis
-- correlation hint, `deterministic_id()`, the occurrence rollup keyed on
-- `dedup_hash`, the root-cause membership -- and, worse, breaks the control
-- the reporter explicitly asked to keep: two firings that straddle a bucket
-- boundary while the alert is still open would become two rows. A wall-clock
-- bucket cannot tell "repeated while open" from "repeated after closure",
-- which is the only distinction that matters here.
--
-- Reopening also bounds the queue. A recurrence returns the one existing row
-- to the queue; a hundred further recurrences while it is open change
-- nothing. The new-row remedy's failure mode is a flood, and this one has no
-- flood to bound.
--
-- The objection to reopening is real and is what these columns answer
-- -------------------------------------------------------------------
-- Reopening rewrites a state an analyst deliberately set, and without a
-- record a reopened alert is indistinguishable from one that was never
-- closed -- which would destroy exactly the audit trail the new-row remedy
-- was trying to protect. So the reopen is not a silent status flip: it is
-- counted, timestamped and given a reason that names the status the alert
-- was closed as. `services/agents` already refuses to reopen a closed alert
-- on a re-reading of *existing* evidence, under the docstring "re-opening a
-- closed alert is an analyst-visible state change". A fresh firing is new
-- evidence from the world rather than a re-interpretation of old evidence,
-- and these columns are what make the difference legible to an auditor.
--
-- Deliberately shaped after `090_case_reopen.sql`, which solved the same
-- problem for cases, so the two surfaces answer "has this come back?" with
-- the same three column names rather than inventing a second vocabulary.
--
-- What is NOT cleared, and why
-- ----------------------------
-- `disposition` survives the reopen. It records the judgement a human made
-- about the previous occurrence, and erasing it would lose the fact that
-- anyone judged it at all. `reopened_at` beside it is the disambiguator: an
-- alert carrying both a disposition and a reopen is one whose verdict is
-- older than its newest evidence.
--
-- `resolved_at` *is* cleared by the sink, because it is not a judgement but a
-- claim of fact -- and the MTTR average subtracts it from `created_at`. An
-- open alert carrying a resolution timestamp would be counted as resolved by
-- a query that never looks at `status`.

ALTER TABLE alerts
    -- When it was last reopened. NULL means never. Not back-filled: we cannot
    -- know whether a historical alert ever recurred, and inventing a
    -- timestamp would be worse than admitting we do not know.
    ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ,

    -- How many times. An alert that has come back four times is a different
    -- conversation from one that came back once, and `reopened_at` alone
    -- cannot tell them apart because each reopen overwrites it.
    --
    -- Defaulted to 0 rather than NULL: unlike the timestamp, "no reopen has
    -- been recorded since this column existed" genuinely is zero reopens for
    -- every row that already exists.
    ADD COLUMN IF NOT EXISTS reopen_count INTEGER NOT NULL DEFAULT 0,

    -- Why. Written by the sink and naming the status the alert was closed as,
    -- so the row itself says what was overturned. An unexplained reopen is
    -- the thing an auditor asks about.
    ADD COLUMN IF NOT EXISTS reopen_reason TEXT;

COMMENT ON COLUMN alerts.reopened_at IS
    'When this alert was last reopened because its detection fired again. NULL means never.';
COMMENT ON COLUMN alerts.reopen_count IS
    'How many times this alert has recurred after being closed. reopened_at only holds the most recent.';
COMMENT ON COLUMN alerts.reopen_reason IS
    'Why it was last reopened, naming the status it had been closed as.';

-- Finding alerts that keep coming back is the question this data is for: a
-- detection whose alert is closed and reopened repeatedly is either a tuning
-- problem or an attacker probing the gap between closures. Partial, because
-- the overwhelming majority of rows never recur and indexing them would be
-- paying for the answer on every alert to serve a query about a few.
CREATE INDEX IF NOT EXISTS idx_alerts_reopened
    ON alerts (tenant_id, reopened_at DESC)
    WHERE reopen_count > 0;
