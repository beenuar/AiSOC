-- 124: derived privilege facts per identity, and the runtime-usage overlay
-- (depth plan wave 2, Phase 1.1).
--
-- Why derived facts and not "just resolve on read"
-- ------------------------------------------------
-- Migration 103 stores a provider's whole posture as one versioned jsonb
-- document, and the resolver computes a principal's effective permissions
-- from it. That is the right shape for an analyst asking about one identity
-- and the wrong one for three callers that need an answer on the hot path:
--
--   * fusion stamps a privilege tier on every alert at fuse time, and cannot
--     parse an estate-sized policy document per event;
--   * the queue sorts by priority, which reads the tier;
--   * the access review (1.2) scans every principal at once.
--
-- So the expensive resolution runs once per posture version and lands here as
-- a small row per principal. The rows are versioned with the same
-- valid_from / valid_until interval as the snapshot they came from, so "what
-- could this identity do when it acted" stays answerable -- which is the
-- whole reason 103 is versioned, and a derived table that collapsed to one
-- mutable row per principal would quietly undo it.
--
-- Why `unknown` is a stored value and not a NULL tier
-- ---------------------------------------------------
-- A principal with no posture covering an event time is a real and common
-- state: the tenant connected the provider last week and the alert is from
-- last month. Defaulting it to 'standard' is the confident-zero defect --
-- a reader cannot tell a measured standard account from one the platform
-- knows nothing about, and the second is the one worth escalating. So
-- 'unknown' is a first-class tier that every surface renders as unknown.
--
-- The four tags are `boolean NULL` for the same reason: NULL means "no
-- snapshot could answer this", false means "the snapshot says no".

CREATE TABLE IF NOT EXISTS identity_privilege_facts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL,

    provider        text NOT NULL,
    -- The provider-scoped id the resolver was asked about (AWS ARN or user
    -- id, Entra object id, GCP member, Okta user id, Workspace user key,
    -- GitHub login).
    principal_id    text NOT NULL,
    -- A second, human-readable handle when the provider has one. Kept
    -- alongside rather than instead of `principal_id`, because an alert
    -- carries whichever the connector emitted and a join on the wrong one
    -- silently matches nothing.
    principal_label text,
    principal_kind  text,

    tier            text NOT NULL DEFAULT 'unknown',

    -- The four computed tags. NULL is "no snapshot could answer", which is
    -- not the same as false and must not render as one.
    can_escalate    boolean,
    data_access     boolean,
    third_party     boolean,
    cross_account   boolean,

    -- Which actions and which policy chain drove each tag. An analyst who
    -- cannot see why an identity was tagged `can_escalate` has a label, not
    -- a finding.
    evidence        jsonb NOT NULL DEFAULT '{}'::jsonb,

    action_count    integer NOT NULL DEFAULT 0,
    resource_count  integer NOT NULL DEFAULT 0,

    -- The snapshot this was derived from. ON DELETE CASCADE because a fact
    -- whose snapshot is gone cannot be re-derived or audited, and keeping it
    -- would be a number with no provenance.
    snapshot_id     uuid REFERENCES posture_snapshots(id) ON DELETE CASCADE,
    resolver_version text NOT NULL DEFAULT '',
    -- True when the snapshot it came from was partial. Carried down rather
    -- than looked up, so a surface reading only this table can still say
    -- "this answer is incomplete".
    partial_source  boolean NOT NULL DEFAULT false,

    valid_from      timestamptz NOT NULL DEFAULT now(),
    valid_until     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT identity_privilege_facts_provider_check CHECK (
        provider IN ('aws', 'azure', 'gcp', 'gws', 'github', 'okta')
    ),
    CONSTRAINT identity_privilege_facts_tier_check CHECK (
        tier IN ('unknown', 'standard', 'elevated', 'admin', 'domain_admin')
    ),
    CONSTRAINT identity_privilege_facts_interval_check CHECK (
        valid_until IS NULL OR valid_until >= valid_from
    )
);

-- At most one live fact per principal per provider per tenant. Same
-- invariant, and same reason, as posture_snapshots_live_idx: two live rows
-- make "the current tier" whichever the planner returned first.
CREATE UNIQUE INDEX IF NOT EXISTS identity_privilege_facts_live_idx
    ON identity_privilege_facts (tenant_id, provider, principal_id)
    WHERE valid_until IS NULL;

-- The point-in-time lookup fusion makes per alert.
CREATE INDEX IF NOT EXISTS identity_privilege_facts_at_idx
    ON identity_privilege_facts (tenant_id, provider, principal_id, valid_from DESC);

-- The access review's scan: every principal carrying a tag, newest first.
CREATE INDEX IF NOT EXISTS identity_privilege_facts_tags_idx
    ON identity_privilege_facts (tenant_id, provider, tier)
    WHERE valid_until IS NULL;

-- Fusion joins on whichever handle the connector emitted, so the label needs
-- its own index or the stamp falls back to a sequential scan per alert.
CREATE INDEX IF NOT EXISTS identity_privilege_facts_label_idx
    ON identity_privilege_facts (tenant_id, lower(principal_label))
    WHERE valid_until IS NULL AND principal_label IS NOT NULL;

COMMENT ON TABLE identity_privilege_facts IS
    'Per-identity privilege tier and computed tags, derived once per posture version. Versioned on the '
    'same interval as the snapshot it came from so an alert reads the tier that was true when the '
    'identity acted, not the one true now.';

COMMENT ON COLUMN identity_privilege_facts.tier IS
    'unknown | standard | elevated | admin | domain_admin. unknown is a measured state (no snapshot '
    'covers this time), never a default, and every surface renders it as unknown.';

COMMENT ON COLUMN identity_privilege_facts.can_escalate IS
    'NULL means no snapshot could answer. false means the snapshot says no. The two are different '
    'facts and a surface that renders them the same is fabricating one of them.';


-- The runtime-usage overlay: of what a principal was granted, what did it
-- actually exercise?
--
-- Sourced from the event lake, which lives in the `full` profile. A CORE
-- install has no lake, and the honest consequence is that usage is *not
-- measured* there -- which is a different answer from "used nothing". The
-- difference matters more here than almost anywhere else in the product: a
-- right-sizing recommendation built on "used nothing" tells an operator to
-- revoke every permission in the estate.
--
-- `window_start` / `window_end` are on the row rather than implied by a
-- config value, because a finding that says "unused in the window" is
-- meaningless without the window, and the window changes.
CREATE TABLE IF NOT EXISTS identity_permission_usage (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL,

    provider        text NOT NULL,
    principal_id    text NOT NULL,
    -- Provider-namespaced, matching what the resolver returns, so granted
    -- and used can be compared without a translation table in between.
    action          text NOT NULL,

    use_count       bigint NOT NULL DEFAULT 0,
    first_used_at   timestamptz,
    last_used_at    timestamptz,

    window_start    timestamptz NOT NULL,
    window_end      timestamptz NOT NULL,

    -- Where the observation came from, so an operator can tell a lake-backed
    -- measurement from a connector-backed one.
    source          text NOT NULL DEFAULT 'lake',
    computed_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT identity_permission_usage_provider_check CHECK (
        provider IN ('aws', 'azure', 'gcp', 'gws', 'github', 'okta')
    ),
    CONSTRAINT identity_permission_usage_window_check CHECK (window_end >= window_start)
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_permission_usage_unique_idx
    ON identity_permission_usage (tenant_id, provider, principal_id, action);

CREATE INDEX IF NOT EXISTS identity_permission_usage_principal_idx
    ON identity_permission_usage (tenant_id, provider, principal_id, last_used_at DESC);

COMMENT ON TABLE identity_permission_usage IS
    'Granted actions a principal actually exercised in a trailing window, from the event lake. An '
    'absent row means not observed; on a CORE install with no lake that means not measured, which is '
    'not the same as never used and must never be rendered as it.';


DO $$
BEGIN
    EXECUTE 'ALTER TABLE identity_privilege_facts ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE identity_privilege_facts FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON identity_privilege_facts';
    EXECUTE
        'CREATE POLICY tenant_isolation ON identity_privilege_facts '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    EXECUTE 'ALTER TABLE identity_permission_usage ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE identity_permission_usage FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON identity_permission_usage';
    EXECUTE
        'CREATE POLICY tenant_isolation ON identity_permission_usage '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON identity_privilege_facts TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON identity_permission_usage TO aisoc_app';
    END IF;
END
$$;
