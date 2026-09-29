-- 075_dead_letter_replay.sql — draining the dead-letter queue (deferral 5b)
--
-- Phase 5 shipped the schema registry, the dead-letter queue and event-time
-- watermarking. `GET /api/v1/health/dead-letters` reports the backlog and
-- nothing consumed it: a dead-letter queue nobody can drain is an audit
-- trail, not a recovery mechanism.
--
-- Two things were missing and both are here.
--
-- The coordinates. `aisoc_dead_letters` recorded topic, reason and a 2,000
-- character excerpt — deliberately far short of the event, because the
-- payload is untrusted by definition and storing all of it turns the table
-- into an unbounded sink for exactly the content the pipeline refused. That
-- reasoning still holds, and it means the row cannot be the thing replayed.
-- The faithful copy lives in Kafka, and reaching it needs the partition and
-- offset the consumer had in hand and discarded. Both are nullable: rows
-- written before this migration have no coordinates and never will, and a
-- fabricated offset would replay somebody else's message.
--
-- The record of the action. A replay re-injects production traffic, so it is
-- the kind of operation whose absence from the audit log is itself the
-- incident. `aisoc_dlq_replays` records who asked, for what range, what the
-- re-validation found, and what was actually produced — including for a dry
-- run, because "we checked and it would still fail" is the outcome an
-- operator most needs to be able to point at later.

ALTER TABLE aisoc_dead_letters
    ADD COLUMN IF NOT EXISTS topic_partition INTEGER,
    ADD COLUMN IF NOT EXISTS kafka_offset    BIGINT;

COMMENT ON COLUMN aisoc_dead_letters.kafka_offset IS
    'Offset of the refused message on its partition, or NULL when unknown. '
    'The excerpt cannot be replayed; this is how the real message is found again.';

-- The lookup a replay does: "the refused messages on this partition, in
-- offset order, from here". Partial, because a row with no coordinates can
-- never be the start of one.
CREATE INDEX IF NOT EXISTS idx_dead_letters_coordinates
    ON aisoc_dead_letters (topic, topic_partition, kafka_offset)
    WHERE kafka_offset IS NOT NULL;


CREATE TABLE IF NOT EXISTS aisoc_dlq_replays (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The range asked for. Explicit, never inferred: an operator naming the
    -- partition and offset has decided what to replay, where "replay the
    -- backlog" would let one mis-click re-inject a week of traffic.
    topic           TEXT    NOT NULL,
    topic_partition INTEGER NOT NULL,
    start_offset    BIGINT  NOT NULL,
    max_messages    INTEGER NOT NULL,

    -- False is the default at every layer above this. A replay that has not
    -- been previewed is a replay nobody has checked the cause of.
    executed        BOOLEAN NOT NULL DEFAULT FALSE,

    -- What the re-validation found. `refused` is the safety property: a
    -- message that still fails the same validation that rejected it is not
    -- produced, because replaying a poison batch into the consumer that
    -- refused it reproduces the outage it caused.
    messages_read   INTEGER NOT NULL DEFAULT 0,
    would_pass      INTEGER NOT NULL DEFAULT 0,
    refused         INTEGER NOT NULL DEFAULT 0,
    produced        INTEGER NOT NULL DEFAULT 0,

    -- 'queued' | 'completed' | 'failed'. A run that never terminates is
    -- indistinguishable from a slow one, so the terminal states are stored
    -- rather than inferred from the absence of a result.
    status          TEXT NOT NULL DEFAULT 'queued',
    error           TEXT,

    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,

    CONSTRAINT aisoc_dlq_replays_status_known
        CHECK (status IN ('queued', 'completed', 'failed')),
    -- A replay with no ceiling is the unbounded re-injection this table
    -- exists to prevent, so the bound is a constraint and not a convention.
    CONSTRAINT aisoc_dlq_replays_bounded
        CHECK (max_messages > 0 AND max_messages <= 1000),
    CONSTRAINT aisoc_dlq_replays_offset_non_negative
        CHECK (start_offset >= 0 AND topic_partition >= 0)
);

CREATE INDEX IF NOT EXISTS idx_dlq_replays_tenant_time
    ON aisoc_dlq_replays (tenant_id, created_at DESC);

COMMENT ON TABLE aisoc_dlq_replays IS
    'Operator replays of refused messages from a Kafka offset. Written by '
    'POST /api/v1/health/dead-letters/replay; one row per request including '
    'dry runs, because a preview that found the cause unfixed is a finding.';

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers reach this table on a connection that binds no
-- tenant; dropping it makes those silently see nothing. FORCE so the owner
-- does not walk past, because the owner is the role that runs migrations.
ALTER TABLE aisoc_dlq_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_dlq_replays FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_dlq_replays_tenant ON aisoc_dlq_replays;
CREATE POLICY aisoc_dlq_replays_tenant ON aisoc_dlq_replays
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- `ALTER DEFAULT PRIVILEGES` from 061 only covers tables created by the role
-- that ran it, so a new table needs its grant stated.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE ON aisoc_dlq_replays TO aisoc_app;
    END IF;
END
$$;
