-- QA sampling of auto-closed alerts, and the measured closure accuracy it feeds.
--
-- Parity plan 3.5.
--
-- Why sample at all
-- -----------------
-- Closure accuracy is the number a buyer actually wants and the one nothing
-- in this tree measures. The eval harness grades a synthetic corpus; the
-- funnel counts how many alerts were closed. Neither answers "of the alerts
-- the agent closed on your data, how many should it have".
--
-- The only way to answer that is for a human to look at some of them. A
-- sample rather than all of them, because reviewing every auto-closure
-- would cost more than not auto-closing, and the point of the sample is to
-- measure the thing, not to re-do it.
--
-- Five percent by default, per tenant, so a tenant can dial it to zero
-- (they accept the risk and get no accuracy number) or to one hundred
-- (shadow mode by another name).

CREATE TABLE IF NOT EXISTS aisoc_closure_qa_samples (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id        UUID NOT NULL,

    -- What the agent decided, captured at sampling time rather than read
    -- back later: an analyst may change the disposition during review, and
    -- comparing the agent against a value the review itself moved would
    -- make every sample agree.
    agent_disposition   TEXT NOT NULL,
    agent_confidence    DOUBLE PRECISION,
    closed_at           TIMESTAMPTZ NOT NULL,

    -- Review state.
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'reviewed', 'skipped')),
    reviewer        TEXT,
    reviewed_at     TIMESTAMPTZ,

    -- The analyst's own verdict. NULL until reviewed.
    reviewer_disposition TEXT,

    -- The five-part rubric the plan names. 1 to 5, NULL until reviewed.
    -- Open scores rather than a single pass/fail, because "the verdict was
    -- right but it gathered no evidence" and "it gathered everything and
    -- concluded wrongly" are different failures and need different fixes.
    score_evidence      SMALLINT CHECK (score_evidence  BETWEEN 1 AND 5),
    score_reasoning     SMALLINT CHECK (score_reasoning BETWEEN 1 AND 5),
    score_verdict       SMALLINT CHECK (score_verdict   BETWEEN 1 AND 5),
    score_response      SMALLINT CHECK (score_response  BETWEEN 1 AND 5),
    score_report        SMALLINT CHECK (score_report    BETWEEN 1 AND 5),
    reviewer_note       TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One sample per alert. A repeat sample of the same closure would weight it
-- twice in the accuracy figure.
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_closure_qa_alert_idx
    ON aisoc_closure_qa_samples (tenant_id, alert_id);

CREATE INDEX IF NOT EXISTS aisoc_closure_qa_pending_idx
    ON aisoc_closure_qa_samples (tenant_id, created_at DESC)
    WHERE status = 'pending';

ALTER TABLE aisoc_closure_qa_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_closure_qa_samples FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_closure_qa_samples;
CREATE POLICY tenant_isolation ON aisoc_closure_qa_samples
    -- The sampler runs in the triage worker, which consumes from Kafka on a
    -- connection that binds no tenant. Without the unbound arm it would
    -- write nothing and report success.
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ── The per-tenant sample rate ──────────────────────────────────────────
--
-- On the closure policy table rather than its own, because it is a closure
-- setting and a tenant editing one will look for the other beside it.

ALTER TABLE aisoc_closure_policies
    ADD COLUMN IF NOT EXISTS qa_sample_rate DOUBLE PRECISION NOT NULL DEFAULT 0.05
        CHECK (qa_sample_rate >= 0.0 AND qa_sample_rate <= 1.0);

COMMENT ON COLUMN aisoc_closure_policies.qa_sample_rate IS
    'Fraction of auto-closed alerts of this class sent to analyst review. '
    '0 means no accuracy number for this class; 1 is shadow mode by another name.';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE ON aisoc_closure_qa_samples TO aisoc_app;
    END IF;
END
$$;
