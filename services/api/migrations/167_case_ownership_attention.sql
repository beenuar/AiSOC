-- 167: case ownership and the next-action clock.
--
-- A case could sit open with nobody — person or agent — responsible and no
-- time by which anything was due, and nothing surfaced that state. An owner
-- is a person (`assigned_to_id`, which has existed since the table did) OR
-- an agent run (`owner_agent_run_id`, new): launching an investigation
-- claims an unowned case for the run, and never steals one a person holds.
-- `next_action_due_at` is the clock the attention feed and the shift
-- handoff read.

ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS next_action_due_at TIMESTAMPTZ;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS owner_agent_run_id UUID;

-- The attention feed's shape: open cases that are unowned or overdue. The
-- partial index keeps it a scan over the attention set rather than the
-- whole caseload; `status != 'closed'` mirrors case_status.OPEN_STATUSES
-- (resolved is deliberately open — a resolved case still has a next action:
-- confirming closure).
CREATE INDEX IF NOT EXISTS idx_cases_attention
    ON aisoc_cases (tenant_id, next_action_due_at)
    WHERE status != 'closed';
