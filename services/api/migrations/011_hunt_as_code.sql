-- AiSOC Hunt-as-code migration (Wave 2 — w2-hac)
-- Stores the catalog of registered hunt hypotheses (loaded from the YAML
-- corpus in `hunts/`) plus first-class artifacts for every hunt run and
-- finding so they sit alongside the Investigation Ledger as queryable,
-- replayable evidence.
--
-- Tables:
--   hunt_hypotheses  — one row per loaded YAML hunt (catalog)
--   hunt_runs        — one row per scheduled execution of a hunt
--   hunt_findings    — first-class artifacts emitted by a hunt run
--
-- All three tables enforce tenant isolation via Row-Level Security so
-- hunts that fire are scoped to a tenant the same way alerts and cases are.

-- ============================================================
-- 1. hunt_hypotheses (catalog)
-- ============================================================
CREATE TABLE IF NOT EXISTS hunt_hypotheses (
    id                 UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id          UUID         REFERENCES tenants(id) ON DELETE CASCADE,
    -- ``hunt_id`` is the slug from the YAML (e.g. "hunt-svc-account-after-hours").
    -- Unique per tenant so each tenant can override the corpus version.
    hunt_id            VARCHAR(200) NOT NULL,
    name               VARCHAR(300) NOT NULL,
    description        TEXT,
    version            VARCHAR(40)  NOT NULL DEFAULT '1.0.0',
    severity           VARCHAR(20)  NOT NULL DEFAULT 'medium',
    category           VARCHAR(40)  NOT NULL DEFAULT 'other',
    tags               TEXT[]       NOT NULL DEFAULT '{}',
    log_sources        TEXT[]       NOT NULL DEFAULT '{}',
    schedule_enabled   BOOLEAN      NOT NULL DEFAULT TRUE,
    interval_minutes   INTEGER      NOT NULL DEFAULT 60,
    jitter_seconds     INTEGER      NOT NULL DEFAULT 60,
    hypothesis         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    expected           JSONB        NOT NULL DEFAULT '{}'::jsonb,
    -- ``refs`` (renamed from "references" because that is a reserved word
    -- in PostgreSQL): list of URLs / docs the hunt cites.
    refs               TEXT[]       NOT NULL DEFAULT '{}',
    author             VARCHAR(120),
    -- Hash of the YAML body — lets the loader detect when a hunt has changed.
    source_sha256      VARCHAR(64),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, hunt_id)
);

CREATE INDEX IF NOT EXISTS idx_hunt_hyp_tenant   ON hunt_hypotheses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hunt_hyp_category ON hunt_hypotheses(category);
CREATE INDEX IF NOT EXISTS idx_hunt_hyp_enabled  ON hunt_hypotheses(schedule_enabled);

ALTER TABLE hunt_hypotheses ENABLE ROW LEVEL SECURITY;
ALTER TABLE hunt_hypotheses FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS hunt_hyp_tenant ON hunt_hypotheses;
CREATE POLICY hunt_hyp_tenant ON hunt_hypotheses
    USING (
        tenant_id = current_tenant_id()
        OR tenant_id IS NULL
        OR current_tenant_id() IS NULL
    );

CREATE OR REPLACE FUNCTION hunt_hypotheses_touch_updated()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_hunt_hyp_touch ON hunt_hypotheses;
CREATE TRIGGER trg_hunt_hyp_touch
    BEFORE UPDATE ON hunt_hypotheses
    FOR EACH ROW EXECUTE FUNCTION hunt_hypotheses_touch_updated();

-- ============================================================
-- 2. hunt_runs
-- ============================================================
CREATE TABLE IF NOT EXISTS hunt_runs (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- references hunt_hypotheses.hunt_id (logical FK only, by slug)
    hunt_id         VARCHAR(200) NOT NULL,
    hypothesis_id   UUID         REFERENCES hunt_hypotheses(id) ON DELETE SET NULL,
    -- Trigger source: scheduler|manual|backtest|ci-eval
    trigger_source  VARCHAR(40)  NOT NULL DEFAULT 'scheduler',
    -- running|completed|failed|skipped
    status          VARCHAR(20)  NOT NULL DEFAULT 'running',
    -- How many synthetic events the hunt looked at (input window)
    events_scanned  INTEGER      NOT NULL DEFAULT 0,
    -- How many findings the hunt emitted (rows in hunt_findings for this run)
    findings_count  INTEGER      NOT NULL DEFAULT 0,
    -- Aggregate match score for telemetry; range 0.0–1.0
    match_score     NUMERIC(4,3) NOT NULL DEFAULT 0.0,
    error           TEXT,
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hunt_runs_tenant_started ON hunt_runs(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_runs_hunt_id        ON hunt_runs(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hunt_runs_status         ON hunt_runs(status);

ALTER TABLE hunt_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE hunt_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS hunt_runs_tenant ON hunt_runs;
CREATE POLICY hunt_runs_tenant ON hunt_runs
    USING (
        tenant_id = current_tenant_id()
        OR current_tenant_id() IS NULL
    );

-- ============================================================
-- 3. hunt_findings (first-class artifacts)
-- ============================================================
CREATE TABLE IF NOT EXISTS hunt_findings (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hunt_run_id         UUID         NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    hunt_id             VARCHAR(200) NOT NULL,
    severity            VARCHAR(20)  NOT NULL DEFAULT 'medium',
    -- Optional human-readable title; falls back to the hunt name if NULL.
    title               TEXT,
    -- Free-form summary of what this finding is asserting.
    summary             TEXT,
    -- The raw evidence: list of matched events (telemetry rows) plus indicator
    -- breakdown, indexed by indicator name.
    evidence            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    -- Subset of fields lifted out for indexing / quick filters in the UI.
    primary_entity      VARCHAR(200),
    primary_log_source  VARCHAR(80),
    -- Match score for this finding specifically (range 0.0–1.0).
    match_score         NUMERIC(4,3) NOT NULL DEFAULT 0.0,
    -- ATT&CK technique IDs (e.g. "T1078.002") so we can roll up to coverage.
    mitre_techniques    TEXT[]       NOT NULL DEFAULT '{}',
    -- open|triaged|promoted|dismissed
    status              VARCHAR(20)  NOT NULL DEFAULT 'open',
    promoted_alert_id   UUID,
    promoted_case_id    UUID,
    notes               TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hunt_findings_tenant_created ON hunt_findings(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_hunt_id        ON hunt_findings(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_run            ON hunt_findings(hunt_run_id);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_status         ON hunt_findings(status);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_severity       ON hunt_findings(severity);

ALTER TABLE hunt_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE hunt_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS hunt_findings_tenant ON hunt_findings;
CREATE POLICY hunt_findings_tenant ON hunt_findings
    USING (
        tenant_id = current_tenant_id()
        OR current_tenant_id() IS NULL
    );

CREATE OR REPLACE FUNCTION hunt_findings_touch_updated()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_hunt_findings_touch ON hunt_findings;
CREATE TRIGGER trg_hunt_findings_touch
    BEFORE UPDATE ON hunt_findings
    FOR EACH ROW EXECUTE FUNCTION hunt_findings_touch_updated();
