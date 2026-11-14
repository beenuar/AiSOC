-- 096_playbook_wait_pauses.sql — let a pause be a timer or a callback, not
-- only an approval.
--
-- Depth plan 5.3. `aisoc_playbook_pauses` (migration 081) already stores the
-- position, the context and the step results a suspended run needs, and does
-- so on disk precisely because "survives restarts" is the requirement. A
-- `wait` step needs all of that and none of the approval part: there is no
-- human to ask, there is a clock or a callback.
--
-- Rather than a second table with the same five columns and a second set of
-- RLS policies, the existing one grows three:
--
--   kind          what this pause is waiting for
--   resume_at     when a timer pause becomes due
--   resume_token  the unguessable handle a callback presents
--
-- Why `kind` defaults to 'approval'
-- ---------------------------------
-- Every existing row is one. Defaulting the other way would relabel live
-- approvals as waits and the sweeper would resume them without a decision,
-- which is the single worst thing this table can do.
--
-- Why the token is not the id
-- ---------------------------
-- A caller presenting a resume token is unauthenticated by construction —
-- that is what a callback is. The row id appears in the run record, which
-- an analyst can read, so using it as the handle would let anyone who can
-- see a run resume it. The token is minted separately, is never put in a
-- step result that leaves the service, and is indexed unique so a guess has
-- one target rather than a range.
--
-- Reversible: DROP COLUMN IF EXISTS on each.

ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'approval'
    CHECK (kind IN ('approval', 'wait'));

-- When a timer pause becomes due. NULL for an approval (which waits on a
-- person) and for a callback wait (which waits on an event). The sweeper
-- reads it, so a NULL means "not on a clock" rather than "due now".
ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS resume_at TIMESTAMPTZ;

ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS resume_token TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS aisoc_playbook_pauses_resume_token_idx
    ON aisoc_playbook_pauses (resume_token)
    WHERE resume_token IS NOT NULL;

-- The sweeper's query: waiting timer pauses that are due. Partial, because
-- the resolved rows accumulate and a full-table scan every tick is a cost
-- that grows with history rather than with work.
CREATE INDEX IF NOT EXISTS aisoc_playbook_pauses_due_idx
    ON aisoc_playbook_pauses (resume_at)
    WHERE status = 'waiting' AND resume_at IS NOT NULL;

COMMENT ON COLUMN aisoc_playbook_pauses.kind IS
    'approval = waiting on a person; wait = waiting on a clock or a callback.';
COMMENT ON COLUMN aisoc_playbook_pauses.resume_token IS
    'Unguessable handle a callback presents to resume a wait. Not the row id, which appears in run records.';
