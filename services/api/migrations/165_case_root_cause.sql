-- 165: the evidence-backed root-cause record (WS7.1 of the gap-closure
-- program).
--
-- The only root-cause artifact before this was `root_cause_hypothesis`, a
-- free string on the forensic agent's run state — no case-level record, no
-- status separating a determined cause from a model's guess, no citations.
-- These two tables give a case exactly one root-cause record whose status is
-- `determined`, `hypothesis` or `undetermined`, where:
--
--   * `determined` requires at least one cited event (service-enforced: the
--     rule spans two tables, so the application layer refuses and the live
--     isolation suite pins it);
--   * every citation names an Investigation Ledger entry by (run_id, seq) —
--     the ledger's own stable address (`investigation_events` carries
--     UNIQUE (run_id, seq)) — and the write path verifies the entry exists;
--   * `undetermined` must say which telemetry was missing.
--
-- NOT named `root_cause_findings`: migration 152 already uses that name for
-- fusion's cross-vendor alert grouping, an unrelated concept.

CREATE TABLE IF NOT EXISTS case_root_cause_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('determined', 'hypothesis', 'undetermined')),
    summary TEXT NOT NULL,
    -- Required when status = 'undetermined' (service-enforced): "we could
    -- not know" has to say what would have made it knowable.
    missing_telemetry TEXT,
    created_by VARCHAR(320),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One record per case: the record is the case's root cause, not a feed.
    CONSTRAINT case_root_cause_one_per_case UNIQUE (tenant_id, case_id)
);

CREATE INDEX IF NOT EXISTS idx_case_root_cause_case
    ON case_root_cause_records (tenant_id, case_id);

CREATE TABLE IF NOT EXISTS case_root_cause_citations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    record_id UUID NOT NULL REFERENCES case_root_cause_records(id) ON DELETE CASCADE,
    -- The ledger address: investigation_events is UNIQUE (run_id, seq), and
    -- that pair — not the row UUID, which is minted fresh at write time — is
    -- how every reader addresses an entry.
    run_id UUID NOT NULL,
    seq INTEGER NOT NULL,
    -- Where the walk-back found the event: a typed story link, the entity
    -- graph, the lake, or the ledger itself.
    source VARCHAR(20) NOT NULL CHECK (source IN ('story_link', 'graph', 'lake', 'ledger')),
    event_time TIMESTAMPTZ,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_root_cause_citations_record
    ON case_root_cause_citations (tenant_id, record_id);

-- RLS, the migration-154 shape: the permissive unbound-session arm exists
-- because workers (the postmortem builder, the evidence bundle) read on the
-- unbound pool session — without the arm a tenant with no record and a
-- tenant whose record cannot be read render identically, which is migration
-- 151's lesson. `WITH CHECK` carries the same arm so the policy is one
-- expression in both directions rather than two that can drift. Route reads
-- still carry explicit tenant predicates (the cases-family convention).
ALTER TABLE case_root_cause_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_root_cause_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS case_root_cause_records_tenant ON case_root_cause_records;
CREATE POLICY case_root_cause_records_tenant ON case_root_cause_records
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE case_root_cause_citations ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_root_cause_citations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS case_root_cause_citations_tenant ON case_root_cause_citations;
CREATE POLICY case_root_cause_citations_tenant ON case_root_cause_citations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON case_root_cause_records TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON case_root_cause_citations TO aisoc_app;
    END IF;
END $$;
