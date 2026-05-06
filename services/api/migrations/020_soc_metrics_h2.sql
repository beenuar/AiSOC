-- Migration 020: SOC Metrics H2 Roadmap features
-- Adds: alert disposition, first_seen_at (MTTD), run cost telemetry table,
--       autonomy thresholds table, institutional memory table.

BEGIN;

-- Alert disposition and MTTD tracking
ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS disposition TEXT,
  ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_alerts_tenant_disposition
  ON alerts (tenant_id, disposition)
  WHERE disposition IS NOT NULL;

-- Investigation cost telemetry
CREATE TABLE IF NOT EXISTS aisoc_run_costs (
    run_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    model           TEXT NOT NULL,
    total_prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    total_completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_cost_usd  DOUBLE PRECISION NOT NULL DEFAULT 0,
    total_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    call_count      INTEGER NOT NULL DEFAULT 0,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, tenant_id, model)
);

CREATE INDEX IF NOT EXISTS aisoc_run_costs_tenant_run
  ON aisoc_run_costs (tenant_id, run_id);

CREATE INDEX IF NOT EXISTS aisoc_run_costs_recorded_at
  ON aisoc_run_costs (recorded_at DESC);

-- Autonomy guardrails thresholds (per-tenant overrides)
CREATE TABLE IF NOT EXISTS aisoc_autonomy_thresholds (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    action_name TEXT NOT NULL,
    min_confidence DOUBLE PRECISION NOT NULL CHECK (min_confidence BETWEEN 0 AND 1),
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, action_name)
);

CREATE INDEX IF NOT EXISTS aisoc_autonomy_thresholds_tenant
  ON aisoc_autonomy_thresholds (tenant_id);

-- Institutional memory (three-tier memory system)
CREATE TABLE IF NOT EXISTS aisoc_institutional_memory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    key             TEXT NOT NULL,
    value           JSONB NOT NULL,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    analyst_override BOOLEAN NOT NULL DEFAULT FALSE,
    override_reason TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, key)
);

CREATE INDEX IF NOT EXISTS aisoc_institutional_memory_tenant_key
  ON aisoc_institutional_memory (tenant_id, key);

CREATE INDEX IF NOT EXISTS aisoc_institutional_memory_tags
  ON aisoc_institutional_memory USING GIN (tags);

COMMIT;
