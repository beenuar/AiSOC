-- Migration 014: Hypothesis-driven hunt workbench
-- Stores hunt hypotheses, linked detections, and execution results.

CREATE TABLE IF NOT EXISTS aisoc_hunts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID,
    title           TEXT NOT NULL,
    hypothesis      TEXT NOT NULL,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    status          TEXT NOT NULL DEFAULT 'draft'
                        CHECK (status IN ('draft','active','completed','archived')),
    priority        TEXT NOT NULL DEFAULT 'medium'
                        CHECK (priority IN ('low','medium','high','critical')),
    -- linked content
    query_esql      TEXT,
    query_spl       TEXT,
    query_kql       TEXT,
    -- results
    findings        JSONB DEFAULT '[]'::jsonb,
    false_positive_rate FLOAT,
    -- metadata
    assigned_to     TEXT,
    tags            TEXT[] DEFAULT ARRAY[]::TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    created_by      TEXT
);

CREATE TABLE IF NOT EXISTS aisoc_hunt_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hunt_id         UUID NOT NULL REFERENCES aisoc_hunts(id) ON DELETE CASCADE,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    platform        TEXT NOT NULL DEFAULT 'esql',
    query_used      TEXT,
    hit_count       INT DEFAULT 0,
    result_sample   JSONB DEFAULT '[]'::jsonb,
    duration_ms     INT,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_aisoc_hunts_status     ON aisoc_hunts (status);
CREATE INDEX IF NOT EXISTS idx_aisoc_hunt_runs_hunt   ON aisoc_hunt_runs (hunt_id);
