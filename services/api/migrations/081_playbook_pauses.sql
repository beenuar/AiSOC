-- A playbook run suspended at an approval step, and able to resume.
--
-- Parity plan 5.2.
--
-- The engine is a single-threaded index walk with no pause and no resume,
-- so an `approval` step had nothing to suspend. It failed closed, which was
-- the right interim behaviour (it previously returned `{"skipped": true}`
-- while reporting SUCCESS, letting a run continue straight into the action
-- a human was supposed to authorise) but it means **12 shipped playbooks
-- abort at their approval step**.
--
-- Suspending needs the position and the context on disk, not in the
-- process: "survives restarts" is the requirement, and an in-memory pause
-- is lost by the thing most likely to interrupt a long-running approval.

CREATE TABLE IF NOT EXISTS aisoc_playbook_pauses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The engine's own run id, so a resumed run keeps its identity in the
    -- realtime stream and the ledger rather than appearing as a new one.
    run_id          TEXT NOT NULL,
    playbook_id     TEXT NOT NULL,
    playbook_name   TEXT,

    -- Where to pick up. The index of the approval step itself: resume
    -- advances past it, so a replayed decision cannot re-run the step.
    step_index      INTEGER NOT NULL,
    step_id         TEXT NOT NULL,

    -- Everything a later step reads through `{{prev.*}}`. Without this the
    -- resumed half of the run sees an empty context and every templated
    -- parameter resolves to nothing.
    run_context     JSONB NOT NULL DEFAULT '{}'::jsonb,
    step_results    JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- The approval this pause is waiting on, in `agent_approvals`.
    approval_id     UUID,

    status          TEXT NOT NULL DEFAULT 'waiting'
                    CHECK (status IN ('waiting', 'resumed', 'denied', 'expired', 'cancelled')),

    -- Expiry is mandatory and has an outcome. A pause with no expiry is a
    -- run that hangs forever and an operator who never learns it did:
    -- `expired` is a recorded decision, not an absence of one.
    expires_at      TIMESTAMPTZ NOT NULL,
    resolved_at     TIMESTAMPTZ,
    resolution      TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One live pause per run. A run cannot be waiting at two approval steps,
-- and a duplicate would resume the same run twice.
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_playbook_pauses_run_idx
    ON aisoc_playbook_pauses (run_id)
    WHERE status = 'waiting';

CREATE INDEX IF NOT EXISTS aisoc_playbook_pauses_approval_idx
    ON aisoc_playbook_pauses (approval_id)
    WHERE status = 'waiting';

-- The expiry sweep reads this. Partial, because a resolved pause is never
-- swept and keeping it out of the index keeps the scan proportional to what
-- is actually waiting.
CREATE INDEX IF NOT EXISTS aisoc_playbook_pauses_expiry_idx
    ON aisoc_playbook_pauses (expires_at)
    WHERE status = 'waiting';

ALTER TABLE aisoc_playbook_pauses ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_playbook_pauses FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_playbook_pauses;
CREATE POLICY tenant_isolation ON aisoc_playbook_pauses
    -- The engine writes this from the agents service, which runs its
    -- playbooks off a Kafka consumer binding no tenant. Without the unbound
    -- arm every pause would fail to write and the run would abort exactly
    -- as it does today, with the new table looking installed and doing
    -- nothing.
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE ON aisoc_playbook_pauses TO aisoc_app;
    END IF;
END
$$;
