-- Wave 2, Phase 4.3 — the questions a tenant's analysts ask of every alert.
--
-- What this stores, and the split that makes it safe
-- ---------------------------------------------------
-- A question has two halves and they are kept strictly apart, because only
-- one of them is safe to let a tenant write freely:
--
--   * `label` is free text. It belongs to the analyst reading the triage
--     output, and it decides nothing. It reaches a model only inside an
--     `<UNTRUSTED_DATA>` envelope, quoted, beside an answer computed without
--     it.
--   * `field` / `op` / `value` is a closed-schema lookup over the evidence
--     bundle, and it is what actually produces the answer.
--
-- The plan's hard constraint for this item is that a tenant's free text never
-- becomes an instruction. The column split is how that is enforced at rest:
-- there is no column whose contents are interpreted.
--
-- Why `op` is CHECK-constrained rather than free
-- ----------------------------------------------
-- `neq` is not a comparator anywhere in this product, and a rule that uses it
-- parses, saves, and silently never matches — the recorded defect this phase
-- exists to avoid repeating. A constraint here means the same mistake is a
-- write error naming the column rather than a question that answers "no" to
-- everything forever. The list is a strict subset of the business-context
-- grammar; `scripts/check_business_context_grammar.py` holds the producers
-- level, and `services/agents/app/context/triage_questions.py` records why
-- the ordering comparators are deliberately absent.
--
-- `alert_type = '*'` means every type, which is the common case: most of
-- these questions ("is this IP a known office?") are not type-specific.

CREATE TABLE IF NOT EXISTS triage_questions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- '*' matches every alert type.
    alert_type    TEXT        NOT NULL DEFAULT '*',

    -- Free text. Rendered as quoted data; never interpreted.
    label         TEXT        NOT NULL CHECK (length(label) BETWEEN 1 AND 200),

    -- The closed-schema lookup.
    field         TEXT        NOT NULL CHECK (field ~ '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$'),
    op            TEXT        NOT NULL CHECK (op IN (
                      'eq', 'ne', 'contains', 'startswith', 'endswith',
                      'in', 'not_in', 'exists', 'not_exists'
                  )),
    -- JSONB so a list comparator ('in') and a scalar one share one column
    -- without a second nullable column that can disagree with `op`.
    value         JSONB,

    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- A unary comparator takes no value and a binary one requires it. Left
    -- to the application this drifts: the agents compiler already refuses
    -- both shapes, and a constraint means a row written by any other path
    -- cannot produce a question that answers nothing.
    CONSTRAINT triage_questions_value_matches_op CHECK (
        (op IN ('exists', 'not_exists') AND value IS NULL)
        OR (op NOT IN ('exists', 'not_exists') AND value IS NOT NULL)
    ),

    -- One question per (type, lookup) per tenant. Two identical questions
    -- with different labels would both be answered and both rendered, which
    -- reads to an analyst as corroboration from one fact.
    CONSTRAINT triage_questions_unique_lookup UNIQUE (tenant_id, alert_type, field, op)
);

COMMENT ON TABLE triage_questions IS
    'Per-alert-type questions triage answers from evidence. `label` is free '
    'tenant text and decides nothing; field/op/value is the closed-schema '
    'lookup that produces the answer.';
COMMENT ON COLUMN triage_questions.label IS
    'Free text for the analyst. Rendered inside an UNTRUSTED_DATA envelope '
    'and never interpreted as an instruction.';
COMMENT ON COLUMN triage_questions.alert_type IS
    'The alert type this applies to, or ''*'' for every type.';

-- The read the triage worker makes on every alert: this tenant's enabled
-- questions for this type plus the wildcards.
CREATE INDEX IF NOT EXISTS idx_triage_questions_tenant_type
    ON triage_questions (tenant_id, alert_type) WHERE enabled;

-- RLS, mirroring `alerts_tenant` from `002_rls.sql`.
--
-- The two access paths disagree about whether a tenant GUC is bound, which
-- is what decides the policy shape:
--
--   * **Writes** come from the API's request-scoped session, which binds
--     `app.current_tenant_id` before it writes.
--   * **Reads** come from the agents triage worker, which is a Kafka
--     consumer holding no request and no tenant session, and which reads
--     the questions for whichever tenant the alert belonged to.
--
-- So the `USING` expression needs the unbound arm or the worker reads zero
-- rows — and it would do so *silently*, because a tenant with no questions
-- and a tenant whose questions cannot be read render identically. That is
-- migration 151's lesson repeated: a correct-looking policy over rows
-- nothing can see reads as "this tenant asked nothing" rather than as an
-- error. `WITH CHECK` carries the same arm so the policy is one expression
-- in both directions rather than two that can drift.
ALTER TABLE triage_questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE triage_questions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS triage_questions_tenant ON triage_questions;
CREATE POLICY triage_questions_tenant ON triage_questions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON triage_questions TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS triage_questions;
--
-- Nothing else changes. Triage stops answering standing questions and the
-- prompt block disappears; no verdict depends on a question, because the
-- answers are context an analyst reads, never an input to closure.
