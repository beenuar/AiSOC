-- AiSOC Investigation Ledger migration (Phase 1A)
-- Persistent, append-only record of every agent investigation run.
-- Replaces the in-memory `_runs` dict in services/agents/app/api/investigate.py
-- so every run is queryable, replayable, and signable for compliance.
--
-- Tables:
--   investigation_runs       — one row per investigation
--   investigation_events     — one row per agent step (append-only via trigger)
--   investigation_artifacts  — full LLM transcripts, tool I/O, report blobs
--
-- All three tables enforce tenant isolation via Row-Level Security so the
-- agent decision ledger is scoped to a tenant the same way alerts and cases are.

-- ============================================================
-- 1. investigation_runs
-- ============================================================
CREATE TABLE IF NOT EXISTS investigation_runs (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id         VARCHAR(200) NOT NULL,        -- external case ref (UUID or human ID)
    alert_summary   TEXT,
    raw_alert       JSONB,
    model_used      VARCHAR(100),                  -- e.g. "gpt-4o-mini"
    status          VARCHAR(20)  NOT NULL DEFAULT 'running',  -- running|completed|failed
    error           TEXT,
    total_tokens    INTEGER      NOT NULL DEFAULT 0,
    total_cost_usd  NUMERIC(10,4) NOT NULL DEFAULT 0,
    iterations      INTEGER      NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_runs_tenant_started ON investigation_runs(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_runs_case          ON investigation_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_inv_runs_status        ON investigation_runs(status);

ALTER TABLE investigation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inv_runs_tenant ON investigation_runs;
CREATE POLICY inv_runs_tenant ON investigation_runs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ============================================================
-- 2. investigation_events  (append-only)
-- ============================================================
CREATE TABLE IF NOT EXISTS investigation_events (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id       UUID         NOT NULL REFERENCES investigation_runs(id) ON DELETE CASCADE,
    tenant_id    UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    seq          INTEGER      NOT NULL,            -- monotonically increasing within a run
    ts           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    kind         VARCHAR(40)  NOT NULL,            -- recon|forensic|responder|reporter|report|error|tool_call|llm_call|llm_prompt|llm_response|evidence_cited|decision_reason
    agent        VARCHAR(80)  NOT NULL,
    summary      TEXT         NOT NULL,
    payload      JSONB,
    input_hash   VARCHAR(64),
    output_hash  VARCHAR(64),
    duration_ms  INTEGER      NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (run_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_inv_events_run_seq    ON investigation_events(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_inv_events_tenant_ts  ON investigation_events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_inv_events_kind       ON investigation_events(kind);

-- Append-only: deny UPDATE and DELETE
CREATE OR REPLACE FUNCTION inv_events_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'investigation_events rows are immutable (attempted %)' , TG_OP;
END;
$$;
DROP TRIGGER IF EXISTS trg_inv_events_immutable ON investigation_events;
CREATE TRIGGER trg_inv_events_immutable
    BEFORE UPDATE OR DELETE ON investigation_events
    FOR EACH ROW EXECUTE FUNCTION inv_events_immutable();

ALTER TABLE investigation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inv_events_tenant ON investigation_events;
CREATE POLICY inv_events_tenant ON investigation_events
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ============================================================
-- 3. investigation_artifacts  (large blobs: prompts, tool I/O, reports)
-- ============================================================
CREATE TABLE IF NOT EXISTS investigation_artifacts (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id      UUID         NOT NULL REFERENCES investigation_runs(id) ON DELETE CASCADE,
    event_id    UUID         REFERENCES investigation_events(id) ON DELETE CASCADE,
    tenant_id   UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        VARCHAR(40)  NOT NULL,            -- llm_prompt|llm_response|tool_input|tool_output|report_md|report_html
    content     TEXT,                              -- inline content (truncated to safe size)
    blob_ref    TEXT,                              -- optional pointer to object store
    sha256      VARCHAR(64)  NOT NULL,
    size_bytes  INTEGER      NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_art_run    ON investigation_artifacts(run_id);
CREATE INDEX IF NOT EXISTS idx_inv_art_event  ON investigation_artifacts(event_id);
CREATE INDEX IF NOT EXISTS idx_inv_art_kind   ON investigation_artifacts(kind);

ALTER TABLE investigation_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_artifacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inv_art_tenant ON investigation_artifacts;
CREATE POLICY inv_art_tenant ON investigation_artifacts
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);
