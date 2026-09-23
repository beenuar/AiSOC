-- Dead letters, made visible.
--
-- The fusion consumer routes poison events to a dead-letter queue and has
-- done since the DLQ landed. Nothing ever read it back: `LoggingDLQ` writes
-- a log line, `KafkaDLQ` writes to a topic with no consumer, and
-- `InMemoryDLQ` forgets on restart. So an operator could not answer "what
-- did we drop, and why" — which is the one question a dead-letter queue
-- exists to answer.
--
-- Dropped events are rare by construction (a poison message is a bug, not
-- traffic), so this table stays small and a plain B-tree index is enough.
-- It is deliberately not partitioned: partitioning a table that should have
-- tens of rows a week optimises for a failure mode that would itself be the
-- incident.

CREATE TABLE IF NOT EXISTS aisoc_dead_letters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Nullable because a message can be rejected *before* its tenant is
    -- known — a malformed envelope has no tenant, and recording a guess
    -- would put another tenant's name on someone else's bad data.
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,

    topic           TEXT        NOT NULL,
    reason          TEXT        NOT NULL,
    schema_version  TEXT        NOT NULL DEFAULT 'unknown',

    -- An excerpt, never the whole payload. The payload is what was rejected,
    -- so it is untrusted by definition and may be large or hostile; storing
    -- all of it turns this table into an unbounded sink for exactly the
    -- content the pipeline refused.
    payload_excerpt TEXT        NOT NULL DEFAULT '',
    source_event_id TEXT,

    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Triage state. A dead letter nobody acknowledged is different from one
    -- someone looked at and decided was expected.
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT
);

-- The query an operator actually runs: recent drops for my tenant, newest
-- first.
CREATE INDEX IF NOT EXISTS idx_dead_letters_tenant_time
    ON aisoc_dead_letters (tenant_id, occurred_at DESC);

-- And the aggregate that turns a list into a finding: which reason is
-- responsible for most of them.
CREATE INDEX IF NOT EXISTS idx_dead_letters_reason
    ON aisoc_dead_letters (reason, occurred_at DESC);

COMMENT ON TABLE aisoc_dead_letters IS
    'Events the pipeline refused, with the reason. Written by services/fusion; '
    'read by GET /api/v1/health/dead-letters. Subject to the tenant retention '
    'policy like any other tenant-scoped data.';
