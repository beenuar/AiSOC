-- 070: tenant-authored investigation skills, and the version history that
-- makes a six-month-old verdict explainable.
--
-- Gap-closure Phase 6.1 and 6.2.
--
-- A skill is customer-authored content that steers an agent's plan and its
-- verdict. That puts it in the same class as a detection rule rather than in
-- the class of a settings toggle, and the difference is entirely in what has
-- to be recoverable afterwards. When an auto-close is disputed six months
-- later, "which text was steering the agent that day" has to have an answer,
-- and a single mutable row cannot give one.
--
-- Why two tables
-- --------------
-- `aisoc_tenant_skills` is the current state of each skill: one row per
-- `(tenant_id, skill_id)`, which is what the console lists and what the
-- agents service resolves on the hot path of an investigation.
--
-- `aisoc_tenant_skill_versions` is append-only history: one immutable row per
-- version, holding the body that was in force, who authored it, the backtest
-- that graded it and when it was activated. An investigation records
-- `skill_id` and `version`, and this is the table that turns that pair back
-- into the text. Without it the recorded version is a number pointing at
-- nothing, which is worse than recording nothing at all because it looks like
-- provenance.
--
-- Why activation carries a backtest id and a version
-- ---------------------------------------------------
-- `backtest_evaluation_id` alone is not enough. A skill backtested at version
-- 2, edited into version 3 and then activated would carry a report about text
-- nobody is running. `backtest_version` records which version the report
-- graded, and the activate route refuses when it is not the version being
-- activated. The constraint below is the floor under that check: an active
-- row must name a backtest, and the backtest must be of the active version.
--
-- Why expiry is NOT NULL
-- ----------------------
-- A skill states what is normal in one organisation. Organisational facts
-- rot: a service account is decommissioned, a subnet is re-purposed, a
-- nightly job moves. A skill with no review date keeps steering verdicts
-- after it stops being true, and nothing surfaces that. Expiry is required at
-- authoring time and the resolver drops an expired skill, so the failure mode
-- is "the agent stopped using my skill" rather than "the agent kept using it".
--
-- Why the status ladder is a CHECK and not an application constant
-- ----------------------------------------------------------------
-- `draft -> backtested -> active` is the lifecycle the plan specifies, plus
-- `retired` for a skill an operator has taken out of service without
-- deleting its history. Writing it into the column means a row cannot reach a
-- state the application does not know about, including through a migration
-- replay or a direct fix-up by an operator.

CREATE TABLE IF NOT EXISTS aisoc_tenant_skills (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The author's stable identifier, kebab-case. Stable across versions:
    -- this is what an investigation records alongside the version number.
    skill_id               TEXT        NOT NULL CHECK (skill_id ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),

    -- Assigned by the server, incremented on every content change. Never set
    -- by the author; the parser refuses `version:` as a document key so there
    -- is exactly one authority for what version 3 is.
    version                INTEGER     NOT NULL DEFAULT 1 CHECK (version >= 1),

    status                 TEXT        NOT NULL DEFAULT 'draft'
                                       CHECK (status IN ('draft', 'backtested', 'active', 'retired')),

    name                   TEXT        NOT NULL,
    -- Who to ask when a verdict this skill steered is disputed.
    owner                  TEXT        NOT NULL,
    -- Required. See the header: an organisational fact with no review date
    -- goes on steering verdicts after it stops being true.
    expires_at             TIMESTAMPTZ NOT NULL,

    -- The parsed skill. The agents service is served from this rather than
    -- from the YAML, so a later parser change cannot make an already-active
    -- skill unreadable at triage time.
    body                   JSONB       NOT NULL,
    -- The author's text, for round-tripping into the editor with their
    -- comments and formatting intact.
    source_yaml            TEXT        NOT NULL,

    -- The Phase 1 replay that graded this skill, and the version it graded.
    backtest_evaluation_id UUID        REFERENCES aisoc_replay_evaluations(id) ON DELETE SET NULL,
    backtest_baseline_id   UUID        REFERENCES aisoc_replay_evaluations(id) ON DELETE SET NULL,
    backtest_version       INTEGER,

    activated_at           TIMESTAMPTZ,
    activated_by           UUID        REFERENCES users(id) ON DELETE SET NULL,

    created_by             UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, skill_id),

    -- An active skill must name the backtest of the exact version that is
    -- active. Two reports side by side is what the plan asks for, so the
    -- baseline is required too: an "after" figure with no "before" is not a
    -- comparison, it is a number.
    CONSTRAINT aisoc_tenant_skills_active_is_backtested CHECK (
        status <> 'active'
        OR (
            backtest_evaluation_id IS NOT NULL
            AND backtest_baseline_id IS NOT NULL
            AND backtest_version = version
        )
    )
);

COMMENT ON TABLE aisoc_tenant_skills IS
    'Tenant-authored investigation skills: current state, one row per skill. '
    'Steers the investigation plan and the triage prompt on matching alerts.';
COMMENT ON COLUMN aisoc_tenant_skills.version IS
    'Server-assigned, incremented on every content change. An investigation '
    'records (skill_id, version); aisoc_tenant_skill_versions turns that back '
    'into the text that was in force.';
COMMENT ON COLUMN aisoc_tenant_skills.backtest_version IS
    'Which version the attached backtest graded. Activation refuses when it is '
    'not the version being activated, so a report can never describe text '
    'nobody is running.';
COMMENT ON COLUMN aisoc_tenant_skills.expires_at IS
    'Required. The resolver drops an expired skill, so a stale organisational '
    'fact stops steering rather than steering silently.';

CREATE INDEX IF NOT EXISTS idx_tenant_skills_tenant_status
    ON aisoc_tenant_skills (tenant_id, status);

-- Append-only history. Nothing updates a row here except the activation
-- stamp, which is itself a fact about that version rather than a change to it.
CREATE TABLE IF NOT EXISTS aisoc_tenant_skill_versions (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Denormalised so the RLS policy on this table stands on its own rather
    -- than on a join, the same reasoning as aisoc_replay_decisions: a policy
    -- that has to reach another table to decide returns nothing when that
    -- table is itself filtered.
    tenant_id              UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    skill_row_id           UUID        NOT NULL REFERENCES aisoc_tenant_skills(id) ON DELETE CASCADE,

    skill_id               TEXT        NOT NULL,
    version                INTEGER     NOT NULL CHECK (version >= 1),

    name                   TEXT        NOT NULL,
    owner                  TEXT        NOT NULL,
    expires_at             TIMESTAMPTZ NOT NULL,
    body                   JSONB       NOT NULL,
    source_yaml            TEXT        NOT NULL,

    backtest_evaluation_id UUID        REFERENCES aisoc_replay_evaluations(id) ON DELETE SET NULL,
    backtest_baseline_id   UUID        REFERENCES aisoc_replay_evaluations(id) ON DELETE SET NULL,

    authored_by            UUID        REFERENCES users(id) ON DELETE SET NULL,
    authored_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at           TIMESTAMPTZ,
    activated_by           UUID        REFERENCES users(id) ON DELETE SET NULL,
    retired_at             TIMESTAMPTZ,

    UNIQUE (tenant_id, skill_id, version)
);

COMMENT ON TABLE aisoc_tenant_skill_versions IS
    'Append-only history of every tenant skill version, with the backtest that '
    'graded it and when it was activated. This is what makes (skill_id, '
    'version) recorded on an investigation resolvable back to the text.';

CREATE INDEX IF NOT EXISTS idx_tenant_skill_versions_lookup
    ON aisoc_tenant_skill_versions (tenant_id, skill_id, version);

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) reach these
-- tables; dropping it makes those silently see nothing. FORCE so the table
-- owner, which is the role that runs migrations, does not walk past it.
ALTER TABLE aisoc_tenant_skills ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_tenant_skills FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_tenant_skills_tenant ON aisoc_tenant_skills;
CREATE POLICY aisoc_tenant_skills_tenant ON aisoc_tenant_skills
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_tenant_skill_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_tenant_skill_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_tenant_skill_versions_tenant ON aisoc_tenant_skill_versions;
CREATE POLICY aisoc_tenant_skill_versions_tenant ON aisoc_tenant_skill_versions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_tenant_skills TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_tenant_skill_versions TO aisoc_app;
    END IF;
END
$$;
