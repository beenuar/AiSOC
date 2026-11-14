-- Reopening a closed case: the column, before the route that writes it.
--
-- Why this migration exists
-- -------------------------
-- `case_status.TRANSITIONS[CLOSED]` is an empty set, so the state machine has
-- no backward move and `PATCH /cases/{id}` refuses every transition out of
-- `closed`. That is the right default: a forward-only machine is what makes
-- "this case was closed" mean something, and letting an ordinary edit walk it
-- backwards is how a containment gets silently undone.
--
-- But "closed in error" and "it came back" are real, and the only way to
-- record either was to open a second case, which loses the history that makes
-- the first one worth having.
--
-- So reopening becomes its own deliberate act with its own column, rather
-- than a hole in the transition table. `PATCH` stays forward-only.
--
-- The ordering matters
-- --------------------
-- A previous attempt at this feature wrote `reopened_at` from the route
-- without ever creating the column, so every call raised
-- `UndefinedColumnError` -- the route was merged, looked complete, and had
-- never once succeeded. The column lands first and on its own.

ALTER TABLE aisoc_cases
    -- When it was last reopened. NULL means never, which is the honest
    -- default for the rows that already exist: we cannot know whether a
    -- historical case was ever reopened, and back-filling a timestamp would
    -- invent one.
    ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMPTZ,

    -- How many times. A case reopened four times is a different conversation
    -- from one reopened once, and `reopened_at` alone cannot tell them apart
    -- because each reopen overwrites it.
    --
    -- Defaulted to 0 rather than NULL: unlike the timestamp, "no reopen has
    -- been recorded since this column existed" genuinely is zero reopens
    -- recorded, and a count that renders as blank would read as missing data.
    ADD COLUMN IF NOT EXISTS reopen_count INTEGER NOT NULL DEFAULT 0,

    -- Why, as given by the person who did it. Required by the route, which
    -- is the point: an unexplained reopen is the thing an auditor asks about
    -- six months later.
    ADD COLUMN IF NOT EXISTS reopen_reason TEXT;

COMMENT ON COLUMN aisoc_cases.reopened_at IS
    'When this case was last reopened from a terminal state. NULL means never.';
COMMENT ON COLUMN aisoc_cases.reopen_count IS
    'How many times this case has been reopened. reopened_at only holds the most recent.';
COMMENT ON COLUMN aisoc_cases.reopen_reason IS
    'Why it was last reopened, required at the point of reopening.';

-- Finding reopened cases is the question this data is for -- a reopen rate is
-- a quality signal about closure, not an incident-response metric -- and it
-- is a small minority of rows, so a partial index is both cheap and the right
-- shape.
CREATE INDEX IF NOT EXISTS ix_aisoc_cases_reopened
    ON aisoc_cases (tenant_id, reopened_at DESC)
    WHERE reopened_at IS NOT NULL;
