-- 142_tenant_response_schedule.sql — when a tenant is willing to let the
-- platform act without a person.
--
-- Wave-2 Phase 6.3. "Automatic" has always been a statement about the
-- action's impact and the finding's confidence, and never about whether
-- anybody is awake. A verb that is reasonable to auto-execute at 14:00 on a
-- Tuesday, with the team watching and able to undo it in a minute, is a
-- different proposition at 03:00 on a Sunday when the rollback will not
-- happen until Monday.
--
-- The schedule can only ever **raise** an approval requirement. That is
-- enforced in `approval_rules.apply_schedule`, which refuses to touch a
-- decision that already requires a human and only ever moves AUTOMATIC to
-- ANALYST. A configuration surface that could relax a contract is a
-- configuration surface an attacker wants, which is the same reasoning the
-- tenant `force_auto` override already lives under.
--
-- Default off, in the strongest sense available: a tenant with no row here
-- gets byte-identical behaviour to before this table existed, because the
-- loader returns NULL and the rule function returns its input unchanged.
--
-- Why windows are rows rather than a JSONB blob
-- ---------------------------------------------
-- A console has to render them, an operator has to edit one without
-- rewriting the rest, and a constraint has to refuse 25:00. All three are
-- ordinary SQL against rows and all three are hand-rolled validation
-- against a blob.

CREATE TABLE IF NOT EXISTS aisoc_tenant_response_schedules (
    tenant_id       UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    -- IANA name, e.g. 'Europe/London'. Stored rather than derived because
    -- "business hours" is a statement about where the team is, not about
    -- where the database is.
    timezone_name   TEXT NOT NULL DEFAULT 'UTC',

    -- Each condition is opt-in and each raises. None of them lowers.
    require_human_outside_business_hours BOOLEAN NOT NULL DEFAULT FALSE,
    require_human_without_on_call        BOOLEAN NOT NULL DEFAULT FALSE,

    -- A declared window where the estate does not move without a person
    -- saying so. Separate from the two above because a freeze is a
    -- decision somebody made today, not a recurring property of the week.
    freeze_active   BOOLEAN NOT NULL DEFAULT FALSE,
    freeze_reason   TEXT NOT NULL DEFAULT '',

    -- The impact floor the conditions apply from. Without it a tenant who
    -- wanted to stop midnight containments would also be approving every
    -- enrichment at midnight, and would switch the whole thing off.
    applies_from_impact TEXT NOT NULL DEFAULT 'moderate'
        CHECK (applies_from_impact IN ('read_only', 'low', 'moderate', 'high', 'severe', 'irreversible')),

    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS aisoc_tenant_response_windows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- datetime.weekday(): Monday is 0, Sunday is 6. Matching Python's
    -- convention rather than ISO's means the loader does no arithmetic,
    -- and arithmetic on weekday numbering is where off-by-one lives.
    weekday         SMALLINT NOT NULL CHECK (weekday BETWEEN 0 AND 6),

    -- Minutes from local midnight. A window where start > end wraps
    -- midnight and covers both ends of the day it is declared on, which is
    -- how a night shift is expressed.
    start_minute    SMALLINT NOT NULL CHECK (start_minute BETWEEN 0 AND 1439),
    end_minute      SMALLINT NOT NULL CHECK (end_minute BETWEEN 0 AND 1440),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_response_windows_tenant
    ON aisoc_tenant_response_windows (tenant_id, weekday);

ALTER TABLE aisoc_tenant_response_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_tenant_response_windows   ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_response_schedules ON aisoc_tenant_response_schedules;
CREATE POLICY tenant_isolation_response_schedules ON aisoc_tenant_response_schedules
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS tenant_isolation_response_windows ON aisoc_tenant_response_windows;
CREATE POLICY tenant_isolation_response_windows ON aisoc_tenant_response_windows
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

COMMENT ON TABLE aisoc_tenant_response_schedules IS
    'Per-tenant time gates on automatic response. Conditions raise an approval requirement and never lower one; a tenant with no row here is unaffected.';
COMMENT ON COLUMN aisoc_tenant_response_schedules.require_human_without_on_call IS
    'When set, an unreadable on-call state counts as nobody on call. A failed rota lookup must not read as cover.';
