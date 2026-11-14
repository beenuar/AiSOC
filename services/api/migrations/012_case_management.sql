-- Migration 012: First-class case management
-- Adds cases table with lifecycle state machine, observable graph, and evidence chain.

CREATE TABLE IF NOT EXISTS aisoc_cases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL DEFAULT 'medium'
                        CHECK (severity IN ('info','low','medium','high','critical')),
    status          TEXT NOT NULL DEFAULT 'new'
                        CHECK (status IN ('new','triaged','investigating','contained','resolved','closed')),
    assignee        TEXT,
    -- ATT&CK coverage
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    -- evidence & observables
    alert_ids       UUID[] DEFAULT ARRAY[]::UUID[],
    observable_graph JSONB DEFAULT '{}'::jsonb,   -- nodes + edges
    evidence_chain   JSONB DEFAULT '[]'::jsonb,   -- ordered list of evidence items
    -- compliance
    compliance_frameworks TEXT[] DEFAULT ARRAY[]::TEXT[],
    -- timeline
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    triaged_at      TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    -- metadata
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT,
    tags            JSONB DEFAULT '{}'::jsonb,
    sla_due_at      TIMESTAMPTZ
);

-- Case comments / timeline entries
CREATE TABLE IF NOT EXISTS aisoc_case_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id     UUID NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    author      TEXT,
    body        TEXT NOT NULL,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_aisoc_cases_tenant     ON aisoc_cases (tenant_id);
CREATE INDEX IF NOT EXISTS idx_aisoc_cases_status     ON aisoc_cases (status);
CREATE INDEX IF NOT EXISTS idx_aisoc_cases_severity   ON aisoc_cases (severity);
CREATE INDEX IF NOT EXISTS idx_aisoc_case_comments    ON aisoc_case_comments (case_id);
