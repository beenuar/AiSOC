-- Migration 015: L0–L4 auto-remediation maturity tiers
-- Tracks the per-tenant maturity posture and per-action-type configuration.

BEGIN;

-- 1. Maturity tier definition per tenant ----------------------------------------
-- One row per tenant. The maturity_tier controls which actions are permitted
-- to execute automatically vs. require human approval.
--
--   L0 — Observe:    All actions require approval. No automation. (default)
--   L1 — Notify:     Notifications and ticket creation are automatic.
--   L2 — Contain:    Low-blast-radius containment actions are automatic.
--   L3 — Remediate:  Medium-blast-radius remediation is automatic.
--   L4 — Automate:   High-blast-radius actions may run automatically if
--                    pre-approved criteria are satisfied.

CREATE TABLE IF NOT EXISTS remediation_maturity (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    maturity_tier   INT NOT NULL DEFAULT 0 CHECK (maturity_tier BETWEEN 0 AND 4),
    -- optional label for display
    tier_label      TEXT GENERATED ALWAYS AS (
        CASE maturity_tier
            WHEN 0 THEN 'L0-Observe'
            WHEN 1 THEN 'L1-Notify'
            WHEN 2 THEN 'L2-Contain'
            WHEN 3 THEN 'L3-Remediate'
            WHEN 4 THEN 'L4-Automate'
        END
    ) STORED,
    -- JSON config for fine-grained overrides per action_type
    action_overrides    JSONB NOT NULL DEFAULT '{}',
    -- audit
    changed_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    changed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rem_maturity_tenant ON remediation_maturity (tenant_id);

-- 2. Per-action-type maturity gate log ------------------------------------------
-- Every time an action is submitted, record which tier gate it was evaluated
-- against so we can track automation coverage over time.

CREATE TABLE IF NOT EXISTS remediation_gate_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_id       UUID NOT NULL,          -- references the action service UUID
    action_type     TEXT NOT NULL,
    blast_radius    TEXT NOT NULL,
    maturity_tier   INT NOT NULL,
    decision        TEXT NOT NULL CHECK (decision IN ('auto', 'queued_approval', 'blocked')),
    rationale       TEXT,
    actor           TEXT NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_gate_log_tenant   ON remediation_gate_log (tenant_id);
CREATE INDEX IF NOT EXISTS idx_gate_log_action   ON remediation_gate_log (action_id);
CREATE INDEX IF NOT EXISTS idx_gate_log_created  ON remediation_gate_log (tenant_id, created_at DESC);

-- 3. Approved action-type whitelist per tenant ----------------------------------
-- At L3/L4, operators can pre-approve specific (action_type, blast_radius) combos
-- so they execute without per-incident human sign-off.

CREATE TABLE IF NOT EXISTS remediation_whitelist (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_type     TEXT NOT NULL,
    blast_radius    TEXT NOT NULL,
    -- optional JSONB constraints, e.g. {"target_prefix": "10.0.0."}
    constraints     JSONB NOT NULL DEFAULT '{}',
    approved_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, action_type)
);

CREATE INDEX IF NOT EXISTS idx_whitelist_tenant ON remediation_whitelist (tenant_id);

COMMIT;
