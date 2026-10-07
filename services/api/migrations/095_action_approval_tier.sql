-- Record the approval tier an action was graded at, and repair the status
-- column it sits beside.
--
-- Two defects, both of which made a metered number unusable.
--
-- `approval_tier` did not exist. The grading happens on every submission
-- (`approval_gate.apply_matrix` resolves the tenant's autonomy tier and the
-- capability contract's impact, then decides), and the answer was used to
-- set a status and then discarded. So "how much response ran unattended"
-- had no answer, and the usage meter could only report one undifferentiated
-- `actions` count whose own description admitted it: "across every approval
-- tier".
--
-- The `status` column held the Python repr of an enum member rather than its
-- value. `action_store.save` wrote `str(record["status"])`, and for a
-- `class ActionStatus(str, Enum)` that is `'ActionStatus.COMPLETED'`, not
-- `'completed'` — a detail of how `Enum` defines `__str__` for a mixin
-- class, which `json.dumps` does not share, so the JSONB copy of the same
-- record has always been correct. Any query against the column, including
-- the index this table carries on `(tenant_id, status)`, matched nothing.
--
-- The UPDATE below is the only way existing rows become readable: the
-- producer fix repairs new writes and cannot reach what is already stored.

ALTER TABLE aisoc_action_records
    ADD COLUMN IF NOT EXISTS approval_tier TEXT;

-- `ApprovalRequirement`: automatic | analyst | mandatory_human | prohibited.
-- NULL means the row predates this column, which the meters count as its own
-- bucket rather than guessing — an ungraded action reported as automatic
-- would claim the platform ran something unattended that nobody assessed.
COMMENT ON COLUMN aisoc_action_records.approval_tier IS
    'ApprovalRequirement the submission was graded at. NULL for rows written before 095.';

CREATE INDEX IF NOT EXISTS ix_action_records_tenant_tier
    ON aisoc_action_records (tenant_id, approval_tier);

UPDATE aisoc_action_records
   SET status = lower(split_part(status, '.', 2))
 WHERE status LIKE 'ActionStatus.%';
