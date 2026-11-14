-- Durable storage for actions awaiting approval.
--
-- services/actions kept these in a module-global dict with the comment
-- "replace with DB in production". The consequence is specific: a restart or
-- a second replica loses every pending containment, so an analyst taps
-- Approve on a Slack card and gets "Action not found" for an incident that is
-- still live. There is no retry — the agent already decided, and the record of
-- what it wanted is gone.
--
-- The record is stored whole as JSONB rather than decomposed into columns.
-- The action record's shape is owned by services/actions and changes with the
-- executor contract; mirroring it as columns here would make every contract
-- change a migration, and the only queries this table serves are by primary
-- key and by tenant.

CREATE TABLE IF NOT EXISTS aisoc_action_records (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    record      JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The operational question is "what is waiting on a human in this tenant",
-- which is the only access pattern beyond primary key.
CREATE INDEX IF NOT EXISTS ix_action_records_tenant_status
    ON aisoc_action_records (tenant_id, status);

-- Pending actions are the ones with a deadline attached, so ordering them by
-- age is how an approval-SLA view is built.
CREATE INDEX IF NOT EXISTS ix_action_records_created
    ON aisoc_action_records (created_at DESC);
