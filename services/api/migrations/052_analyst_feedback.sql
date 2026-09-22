-- Analyst disagreement as structured data, and the organisation memory
-- compiled from it.
--
-- Overturning a verdict previously recorded the new disposition and
-- discarded the only part that generalises: why. Free text did not
-- generalise either, because nobody queried it, so the next identical alert
-- was triaged with no knowledge that this one had been overturned.

CREATE TABLE IF NOT EXISTS aisoc_analyst_feedback (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL,
    alert_id            UUID,
    ai_disposition      TEXT NOT NULL,
    analyst_disposition TEXT NOT NULL,
    -- Closed vocabulary; see app/services/analyst_feedback.py::REASON_CODES.
    -- Not a FK to a lookup table: the codes carry behaviour (scope, TTL,
    -- corroboration threshold) that belongs in code, not in a row.
    reason_code         TEXT NOT NULL,
    scope               TEXT NOT NULL,
    scope_value         TEXT NOT NULL DEFAULT '',
    -- Distinct analysts are what corroborate a reason. One person clicking
    -- the same button ten times is still one opinion, so this is counted
    -- with DISTINCT rather than by row.
    analyst_id          TEXT NOT NULL,
    note                TEXT NOT NULL DEFAULT '',
    context             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_analyst_feedback_lookup
    ON aisoc_analyst_feedback (tenant_id, reason_code, scope, scope_value);
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_recent
    ON aisoc_analyst_feedback (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS aisoc_context_statements (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID NOT NULL,
    -- Human-readable on purpose. A suppression nobody can explain is one
    -- nobody dares remove, and it accumulates.
    statement     TEXT NOT NULL,
    reason_code   TEXT NOT NULL,
    scope         TEXT NOT NULL,
    scope_value   TEXT NOT NULL DEFAULT '',
    observations  INTEGER NOT NULL DEFAULT 1,
    -- NULL means permanent. An approved-pentest statement that outlives the
    -- pentest is an attacker's best friend, so those carry a short TTL and
    -- expiry is applied at read time rather than by a cleanup job.
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_context_statement UNIQUE (tenant_id, reason_code, scope, scope_value)
);

CREATE INDEX IF NOT EXISTS idx_context_statements_active
    ON aisoc_context_statements (tenant_id, expires_at);
