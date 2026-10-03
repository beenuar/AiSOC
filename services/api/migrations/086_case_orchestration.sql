-- Case orchestration: queues, SLA policies, escalation, handoff, history.
--
-- Gap-closure wave 12.
--
-- `aisoc_cases` has `sla_due_at` and nothing sets it from a policy, so
-- the field is either hand-typed or empty. There are no queues, so
-- "my team's cases" is a filter each analyst remembers. There is no
-- escalation, so a case that nobody picks up stays unpicked and the
-- SLA quietly passes. The `/shifts` route was removed in v15.0.0 and
-- nothing replaced it, so a handover is a conversation.
--
-- And status transitions are not recorded anywhere. The case carries
-- its *current* status and four timestamps, so "who moved this to
-- resolved, and on what basis" is unanswerable — which is the first
-- question asked when a closed case turns out to have been an
-- incident.

-- ── SLA policies ───────────────────────────────────────────────────────────
--
-- Per tenant and per severity, because a critical case and an
-- informational one do not share a clock, and two tenants on the same
-- deployment do not share a contract.

CREATE TABLE IF NOT EXISTS case_sla_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    severity            TEXT NOT NULL,

    -- Three clocks, not one. A case picked up in four minutes and
    -- resolved in four days met its acknowledgement target and missed
    -- its resolution one, and a single `sla_due_at` cannot say that.
    ack_minutes         INTEGER,
    resolve_minutes     INTEGER,
    close_minutes       INTEGER,

    -- Whether the clock stops outside working hours. Off by default:
    -- a 24/7 SOC is the assumption, and a business-hours policy that
    -- applied silently would make every out-of-hours breach disappear.
    business_hours_only BOOLEAN NOT NULL DEFAULT FALSE,
    timezone            TEXT NOT NULL DEFAULT 'UTC',

    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, severity, name)
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_case_sla_severity') THEN
        ALTER TABLE case_sla_policies
            ADD CONSTRAINT ck_case_sla_severity
            CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));
    END IF;
END
$$;

-- ── Queues ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS case_queues (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,

    -- Which cases land here, as a stored predicate the resolver reads.
    -- Declarative rather than code so a queue can be created from the
    -- console without a deploy.
    match_severity  TEXT[],
    match_tags      TEXT[],
    match_case_type TEXT,

    -- Lower sorts first. Two queues can match one case and the case
    -- belongs in exactly one, so the tie has to break deterministically
    -- or a case moves between queues on each read.
    precedence      INTEGER NOT NULL DEFAULT 100,
    sla_policy_id   UUID REFERENCES case_sla_policies(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, name)
);

ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS queue_id UUID REFERENCES case_queues(id) ON DELETE SET NULL;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS sla_policy_id UUID REFERENCES case_sla_policies(id) ON DELETE SET NULL;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS ack_due_at TIMESTAMPTZ;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS resolve_due_at TIMESTAMPTZ;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS escalation_level INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_cases_queue ON aisoc_cases (tenant_id, queue_id, status);
CREATE INDEX IF NOT EXISTS ix_cases_sla_due ON aisoc_cases (tenant_id, resolve_due_at)
    WHERE resolve_due_at IS NOT NULL;

-- ── Escalation ─────────────────────────────────────────────────────────────
--
-- None existed. A case nobody picked up stayed unpicked and the SLA
-- passed in silence, which is the failure an SLA exists to prevent.

CREATE TABLE IF NOT EXISTS case_escalation_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    queue_id        UUID REFERENCES case_queues(id) ON DELETE CASCADE,

    -- Escalate when this much of the SLA has elapsed. A fraction, not
    -- a fixed delay: escalating a critical case after the same four
    -- hours as a low one is the same mistake as one shared clock.
    trigger_at_sla_fraction NUMERIC(3, 2) NOT NULL DEFAULT 0.75,

    -- Ordered. Each rung is tried in turn, which is what makes an
    -- unanswered page progress rather than repeat.
    ladder          JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, name)
);

-- ── Shift handoff, replacing the route removed in v15.0.0 ──────────────────

CREATE TABLE IF NOT EXISTS case_shift_handoffs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    from_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    to_user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    queue_id        UUID REFERENCES case_queues(id) ON DELETE SET NULL,

    -- The cases handed over, by id. Snapshotted rather than recomputed
    -- from the queue, because what was handed over is a historical
    -- fact and the queue has changed since.
    case_ids        UUID[] NOT NULL DEFAULT ARRAY[]::uuid[],

    notes           TEXT,
    -- Explicit: an unacknowledged handoff is not a handoff. A shift
    -- that ended with nobody confirming receipt is exactly the gap a
    -- handover exists to close.
    acknowledged_at TIMESTAMPTZ,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_handoffs_tenant ON case_shift_handoffs (tenant_id, started_at DESC);

-- ── Transition history ─────────────────────────────────────────────────────
--
-- The case carries its current status and four timestamps, so "who
-- moved this to resolved, and on what basis" is unanswerable — the
-- first question asked when a closed case turns out to have been an
-- incident.

CREATE TABLE IF NOT EXISTS case_status_transitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id         UUID NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,

    from_status     TEXT,
    to_status       TEXT NOT NULL,
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    -- `human`, `automation` or `escalation`. A status an analyst chose
    -- and one a timer produced read identically in the column without
    -- this, and they mean different things in a review.
    actor_kind      TEXT NOT NULL DEFAULT 'human',
    reason          TEXT,
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_case_transitions ON case_status_transitions (case_id, at);

-- ── Task dependencies ──────────────────────────────────────────────────────

ALTER TABLE case_tasks ADD COLUMN IF NOT EXISTS depends_on_task_id UUID REFERENCES case_tasks(id) ON DELETE SET NULL;
ALTER TABLE case_tasks ADD COLUMN IF NOT EXISTS blocked_reason TEXT;

COMMENT ON COLUMN case_tasks.depends_on_task_id IS
    'A task cannot be completed before the one it depends on. Enforced at the '
    'application layer, not by a constraint, because the useful behaviour is a clear '
    'refusal naming the blocker rather than a foreign-key error.';

-- ── RLS on every new table ─────────────────────────────────────────────────

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'case_sla_policies',
        'case_queues',
        'case_escalation_policies',
        'case_shift_handoffs',
        'case_status_transitions'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
            'WITH CHECK (tenant_id = current_tenant_id())',
            t
        );
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO aisoc_app', t);
        END IF;
    END LOOP;
END
$$;
