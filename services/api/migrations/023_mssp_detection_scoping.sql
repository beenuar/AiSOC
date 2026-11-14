-- Migration 023: MSSP per-tenant detection scoping
--
-- Layers a parent-controlled detection scope on top of the existing
-- per-tenant + platform-wide detection rule model.
--
-- Concepts:
--   * An MSSP parent tenant curates `mssp_rule_packs` -- named bundles of
--     detection rules (drawn from platform-wide rules and/or rules owned
--     by the parent tenant).
--   * Each child tenant is assigned zero or more packs via
--     `mssp_rule_pack_assignments`. An assignment can be enabled/disabled
--     and carries optional default parameter overrides applied at hunt time.
--   * Per-rule fine-tuning is captured in `mssp_rule_overrides`: a parent
--     can disable a single rule for a single child or change its
--     effective severity / metadata without touching the source rule.
--   * Children retain the right to author their own private rules
--     (existing `detection_rules` rows where `tenant_id = child_id`).
--
-- Resolution order (highest precedence wins):
--   1. Tenant's own rules (`detection_rules.tenant_id = T`)
--   2. Platform-wide built-in rules (`tenant_id IS NULL AND is_builtin`)
--   3. Rules sourced from packs assigned by parent (subject to overrides)
--
-- Exclusions and severity bumps from `mssp_rule_overrides` apply to the
-- combined result before it reaches the rule engine.

BEGIN;

-- 0. Schema reconciliation: detection_rules.status -----------------------------
-- The ORM (services/api/app/models/detection_rule.py) treats `status` as the
-- source of truth for whether a rule participates in detection runs
-- (testing | active | disabled | deprecated), but migration 001 only ships the
-- legacy boolean `enabled` column. We need `status` to exist before the view
-- below can reference it on a fresh Postgres init (cold-boot via
-- /docker-entrypoint-initdb.d), otherwise CREATE VIEW fails with
-- "column r.status does not exist" and the container exits with code 3.
--
-- Strategy:
--   * Add the column idempotently (no-op on databases already migrated past
--     this point or that have a future "introduce status" migration).
--   * Backfill from `enabled` when both columns are present so historical rows
--     keep their semantics: enabled=TRUE -> 'active', enabled=FALSE -> 'disabled'.
--   * Default new rows to 'active' so existing seed data and the rest of this
--     migration's view definition behave exactly as documented below.
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

-- Backfill from `enabled` only if the legacy column still exists. We use a
-- DO block with information_schema so the migration is safe whether you're
-- coming from the legacy 001 schema or a future schema where `enabled` was
-- already dropped.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'enabled'
    ) THEN
        EXECUTE $sql$
            UPDATE detection_rules
               SET status = CASE WHEN enabled THEN 'active' ELSE 'disabled' END
             WHERE status = 'active'  -- only touch rows still on the default
        $sql$;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_detection_rules_status ON detection_rules(status);

-- 1. Rule packs ----------------------------------------------------------------
-- A pack is owned by a parent tenant and is the unit MSSPs assign to children.
CREATE TABLE IF NOT EXISTS mssp_rule_packs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    category        TEXT,           -- e.g. "baseline", "pci-dss", "azure-only"
    is_default      BOOLEAN NOT NULL DEFAULT FALSE,  -- auto-assign to new children
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_by_user UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (parent_tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_mssp_rule_packs_parent
    ON mssp_rule_packs (parent_tenant_id);
CREATE INDEX IF NOT EXISTS idx_mssp_rule_packs_default
    ON mssp_rule_packs (parent_tenant_id) WHERE is_default;

-- 2. Pack contents -------------------------------------------------------------
-- Many-to-many: packs <-> detection_rules.
-- A rule is eligible for a pack if it's owned by the parent
-- (detection_rules.tenant_id = parent_tenant_id) OR it's a platform built-in
-- (tenant_id IS NULL AND is_builtin = TRUE). The application layer enforces
-- that constraint; the schema only ensures referential integrity.
CREATE TABLE IF NOT EXISTS mssp_rule_pack_rules (
    pack_id     UUID NOT NULL REFERENCES mssp_rule_packs(id) ON DELETE CASCADE,
    rule_id     UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by_user UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (pack_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_mssp_pack_rules_rule
    ON mssp_rule_pack_rules (rule_id);

-- 3. Pack assignments to child tenants -----------------------------------------
CREATE TABLE IF NOT EXISTS mssp_rule_pack_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pack_id         UUID NOT NULL REFERENCES mssp_rule_packs(id) ON DELETE CASCADE,
    child_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    parameter_overrides JSONB NOT NULL DEFAULT '{}', -- e.g. {"threshold": 5}
    assigned_by_user UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (pack_id, child_tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_mssp_pack_assignments_child
    ON mssp_rule_pack_assignments (child_tenant_id) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_mssp_pack_assignments_pack
    ON mssp_rule_pack_assignments (pack_id);

-- 4. Per-tenant rule overrides -------------------------------------------------
-- Lets a parent tune a single rule for a single child without modifying the
-- shared rule definition. Action determines effect:
--   * 'exclude'   -- rule is removed from this child's effective set
--   * 'customize' -- rule remains, but severity / parameters are altered
CREATE TABLE IF NOT EXISTS mssp_rule_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    child_tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id          UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    action           TEXT NOT NULL CHECK (action IN ('exclude', 'customize')),
    severity_override TEXT,         -- 'info'|'low'|'medium'|'high'|'critical'
    parameter_overrides JSONB NOT NULL DEFAULT '{}',
    note             TEXT,
    created_by_user  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (child_tenant_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_mssp_rule_overrides_child
    ON mssp_rule_overrides (child_tenant_id);
CREATE INDEX IF NOT EXISTS idx_mssp_rule_overrides_rule
    ON mssp_rule_overrides (rule_id);

-- 5. Convenience view: effective rules per tenant -----------------------------
-- Resolves the rule sources for a tenant, returning the base rule rows plus
-- a `source` and `assignment_id` column. Application code stitches in
-- overrides on top of this view so that fine-tuning logic stays in one place.
CREATE OR REPLACE VIEW mssp_effective_tenant_rules AS
WITH child_packs AS (
    SELECT
        a.child_tenant_id,
        a.pack_id,
        a.id AS assignment_id,
        a.enabled,
        a.parameter_overrides
    FROM mssp_rule_pack_assignments a
    WHERE a.enabled
)
SELECT
    r.id            AS rule_id,
    cp.child_tenant_id AS tenant_id,
    'pack'::text    AS source,
    cp.pack_id,
    cp.assignment_id,
    cp.parameter_overrides
FROM child_packs cp
JOIN mssp_rule_pack_rules pr ON pr.pack_id = cp.pack_id
JOIN detection_rules r ON r.id = pr.rule_id
-- Match the convention used by the hunt endpoint: only "active" rules
-- count as part of the effective set. The detection_rules.status column
-- is the source of truth (testing|active|disabled|deprecated).
WHERE r.status = 'active';

COMMIT;
