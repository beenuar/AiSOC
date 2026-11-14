-- AiSOC Detection-as-Code lifecycle migration (Wave 2 — w2-dac)
--
-- Adds the `detection_rule_proposals` table that backs the
-- propose → review → eval-gated → promote flow. Every proposal carries
-- the candidate rule body, MITRE coverage, the eval baseline that will
-- be compared against, and the decision audit trail. When a proposal
-- is promoted it materialises a row in `detection_rules` and links back
-- via `promoted_rule_id` so the catalog UI can render lineage.
--
-- Multi-tenant RLS is applied: each tenant only sees its own proposals.
-- Platform-wide proposals (tenant_id IS NULL) are visible to operators
-- with the platform role and are how built-in detections get reviewed.

-- ============================================================
-- detection_rule_proposals
-- ============================================================
CREATE TABLE IF NOT EXISTS detection_rule_proposals (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID         REFERENCES tenants(id) ON DELETE CASCADE,
    -- Optional pointer to an existing rule when the proposal is an edit.
    base_rule_id        UUID         REFERENCES detection_rules(id) ON DELETE SET NULL,
    -- Materialised rule once the proposal is promoted.
    promoted_rule_id    UUID         REFERENCES detection_rules(id) ON DELETE SET NULL,

    -- Rule definition (uses the same naming convention as the ORM model).
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    rule_language       VARCHAR(30)  NOT NULL,
    rule_body           TEXT         NOT NULL,
    category            VARCHAR(100) NOT NULL,
    severity            VARCHAR(20)  NOT NULL DEFAULT 'medium',
    confidence          INTEGER      NOT NULL DEFAULT 50,
    mitre_tactics       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques    JSONB        NOT NULL DEFAULT '[]'::jsonb,
    tags                JSONB        NOT NULL DEFAULT '[]'::jsonb,

    -- Lifecycle: proposed → in_review → eval_passed | eval_failed → promoted | rejected.
    status              VARCHAR(20)  NOT NULL DEFAULT 'proposed',
    -- The most recent eval result so the UI can render gate verdicts
    -- without re-running the suite. Shape:
    --   {"baseline": {...}, "candidate": {...}, "delta_pp": -1.2, "passed": false, "ran_at": "..."}
    eval_result         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    -- Free-form review thread. Shape: [{"actor_id": "...", "comment": "...", "at": "..."}].
    review_comments     JSONB        NOT NULL DEFAULT '[]'::jsonb,

    -- Authoring + decision audit trail.
    proposed_by_id      UUID         REFERENCES users(id) ON DELETE SET NULL,
    decided_by_id       UUID         REFERENCES users(id) ON DELETE SET NULL,
    decision_comment    TEXT,
    decided_at          TIMESTAMPTZ,

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_proposals_tenant
    ON detection_rule_proposals(tenant_id);
CREATE INDEX IF NOT EXISTS idx_detection_proposals_status
    ON detection_rule_proposals(status);
CREATE INDEX IF NOT EXISTS idx_detection_proposals_base
    ON detection_rule_proposals(base_rule_id)
    WHERE base_rule_id IS NOT NULL;

ALTER TABLE detection_rule_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rule_proposals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS detection_proposals_tenant ON detection_rule_proposals;
CREATE POLICY detection_proposals_tenant ON detection_rule_proposals
    USING (
        tenant_id = current_tenant_id()
        OR tenant_id IS NULL
        OR current_tenant_id() IS NULL
    );

-- updated_at touch trigger (mirrors the agent_approvals pattern).
CREATE OR REPLACE FUNCTION detection_proposals_touch_updated()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_detection_proposals_touch ON detection_rule_proposals;
CREATE TRIGGER trg_detection_proposals_touch
    BEFORE UPDATE ON detection_rule_proposals
    FOR EACH ROW EXECUTE FUNCTION detection_proposals_touch_updated();

-- ============================================================
-- detection_eval_baselines
-- ============================================================
-- Stores the snapshot of MITRE accuracy / alert reduction / completeness
-- / response_quality the gate compares candidate proposals against.
-- A new baseline row is written by `scripts/run_evals.py --record-baseline`
-- and the latest active row per tenant (NULL = platform) is what the
-- gating endpoint reads.

CREATE TABLE IF NOT EXISTS detection_eval_baselines (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID         REFERENCES tenants(id) ON DELETE CASCADE,
    -- Eval suite this baseline scopes (mitre_accuracy, alert_reduction, ...).
    suite           VARCHAR(64)  NOT NULL,
    -- Aggregate score (e.g. 0.823 for 82.3 % MITRE accuracy).
    score           DOUBLE PRECISION NOT NULL,
    -- Full eval result for diffing — same shape produced by run_evals.py.
    payload         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    recorded_by_id  UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_eval_baselines_tenant_suite
    ON detection_eval_baselines(tenant_id, suite, is_active);

ALTER TABLE detection_eval_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_eval_baselines FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS eval_baselines_tenant ON detection_eval_baselines;
CREATE POLICY eval_baselines_tenant ON detection_eval_baselines
    USING (
        tenant_id = current_tenant_id()
        OR tenant_id IS NULL
        OR current_tenant_id() IS NULL
    );
