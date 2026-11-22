-- 166: the resolution contract (WS7.2 of the gap-closure program).
--
-- `resolved` was a free transition: the PATCH gate checked only the status
-- ladder, and the war-room decision and the inbound ITSM mirror checked
-- nothing. These two tables carry the per-tenant policy (off by default —
-- no row means no enforcement; rule 14, enforcement is opt-in) and the
-- per-case facts the shared checker (`app/services/case_resolution.py`)
-- reads: containment verified-with-reference or waived-with-reason,
-- eradication and recovery steps, and the customer notification (channel
-- and time together). Root cause comes from migration 165's record;
-- affected entities are derived from the case and its alerts at check time,
-- never self-attested.

CREATE TABLE IF NOT EXISTS case_resolution_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enforce BOOLEAN NOT NULL DEFAULT FALSE,
    require_containment BOOLEAN NOT NULL DEFAULT TRUE,
    require_eradication_recovery BOOLEAN NOT NULL DEFAULT TRUE,
    require_root_cause BOOLEAN NOT NULL DEFAULT TRUE,
    require_entities BOOLEAN NOT NULL DEFAULT TRUE,
    require_notification BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT case_resolution_policy_one_per_tenant UNIQUE (tenant_id)
);

CREATE TABLE IF NOT EXISTS case_resolution_facts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    -- verified requires containment_reference; not_required requires
    -- containment_reason (service-enforced: the conditions are
    -- cross-column prose requirements).
    containment_state VARCHAR(20) CHECK (containment_state IN ('verified', 'not_required')),
    containment_reference VARCHAR(500),
    containment_reason TEXT,
    eradication TEXT,
    recovery TEXT,
    customer_notified_channel VARCHAR(200),
    customer_notified_at TIMESTAMPTZ,
    updated_by VARCHAR(320),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT case_resolution_facts_one_per_case UNIQUE (tenant_id, case_id)
);

CREATE INDEX IF NOT EXISTS idx_case_resolution_facts_case
    ON case_resolution_facts (tenant_id, case_id);

-- RLS, the migration-154 shape (unbound-session arm for worker reads; same
-- expression on both clauses so the two directions cannot drift). Route
-- reads still carry explicit tenant predicates.
ALTER TABLE case_resolution_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_resolution_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS case_resolution_policies_tenant ON case_resolution_policies;
CREATE POLICY case_resolution_policies_tenant ON case_resolution_policies
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE case_resolution_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_resolution_facts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS case_resolution_facts_tenant ON case_resolution_facts;
CREATE POLICY case_resolution_facts_tenant ON case_resolution_facts
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON case_resolution_policies TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON case_resolution_facts TO aisoc_app;
    END IF;
END $$;
