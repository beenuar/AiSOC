-- Detection-as-code lifecycle: ownership, expiry, versions, rollback.
--
-- Gap-closure wave 9.
--
-- Four gaps, and the first is a live authorization hole rather than a
-- missing feature.
--
-- **Separation of duties.** `detection_rule_proposals.proposed_by_id`
-- is written at creation and **never compared against the caller** at
-- `/decide`, so the author of a rule can approve their own rule. Every
-- other governance control in this product — action approval, playbook
-- dispatch, MSSP overrides — separates the two, and the detection
-- surface is the one that writes code into the engine.
--
-- **Promotion overwrites in place.** A promoted rule replaces the
-- previous body with no record of what it replaced, so "roll back the
-- rule we shipped on Tuesday" has no answer other than reconstructing
-- it from a pull request. A detection that starts firing on everything
-- at 02:00 is exactly when that matters.
--
-- **No owner and no expiry.** A rule written for a specific incident
-- three years ago is indistinguishable from one somebody maintains.
-- Both are the same row.
--
-- **No environment.** There is one state: live. A rule cannot be run
-- somewhere it does not page anybody first.

-- ── Ownership and lifecycle metadata ───────────────────────────────────────

ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS owner_email   TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS owner_team    TEXT;

-- Nullable on purpose. A rule with no expiry is permanent, which is a
-- legitimate choice for a well-understood detection; what was missing
-- is the *ability* to say otherwise, not a mandate.
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS expires_at    TIMESTAMPTZ;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS review_due_at TIMESTAMPTZ;

-- dev → staging → production. A rule in `dev` is evaluated and its
-- matches recorded, and it pages nobody — which is what makes a
-- shadow run safe to do on live traffic.
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'production';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_detection_rules_environment'
    ) THEN
        ALTER TABLE detection_rules
            ADD CONSTRAINT ck_detection_rules_environment
            CHECK (environment IN ('dev', 'staging', 'production'));
    END IF;
END
$$;

-- Shadow mode. Distinct from `environment` because a production rule
-- can be put in shadow during a tuning change without demoting it,
-- and a dev rule is in shadow by definition.
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS shadow_until TIMESTAMPTZ;

COMMENT ON COLUMN detection_rules.shadow_until IS
    'While set and in the future the rule is evaluated and its matches recorded, '
    'but it raises no alert. Independent of environment so a production rule can '
    'be shadowed during a tuning change without being demoted.';

-- ── Version history, which is what makes rollback possible ─────────────────

CREATE TABLE IF NOT EXISTS detection_rule_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,

    -- Monotonic per rule. Not a timestamp: two promotions in the same
    -- second are ordinary during a tuning session, and "the version
    -- before this one" must have exactly one answer.
    version         INTEGER NOT NULL,

    rule_language   TEXT NOT NULL,
    rule_body       TEXT NOT NULL,
    severity        TEXT,
    environment     TEXT NOT NULL DEFAULT 'production',

    -- Who put this version live, and who authored it. Both, because
    -- separation of duties is only auditable if the pair is recorded.
    promoted_by_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    authored_by_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    proposal_id     UUID,

    -- Set when this version was superseded. The live version is the one
    -- with the highest `version` and a NULL here; a rollback writes a
    -- *new* version whose body is an old one rather than deleting rows,
    -- so the history of what was live when stays intact.
    retired_at      TIMESTAMPTZ,
    rolled_back_from INTEGER,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (rule_id, version)
);

CREATE INDEX IF NOT EXISTS ix_rule_versions_rule ON detection_rule_versions (rule_id, version DESC);
CREATE INDEX IF NOT EXISTS ix_rule_versions_tenant ON detection_rule_versions (tenant_id);

ALTER TABLE detection_rule_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rule_versions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON detection_rule_versions;
CREATE POLICY tenant_isolation ON detection_rule_versions
    -- The unbound arm covers the shipped corpus, whose rules belong to
    -- no tenant and are readable by all of them.
    USING (tenant_id = current_tenant_id() OR tenant_id IS NULL OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR tenant_id IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON detection_rule_versions TO aisoc_app;
    END IF;
END
$$;

COMMENT ON TABLE detection_rule_versions IS
    'Every body a rule has ever had live. Promotion used to overwrite in place, so '
    '"roll back the rule we shipped on Tuesday" had no answer — which is exactly the '
    'question asked at 02:00 when a detection starts firing on everything.';

-- ── Shadow-mode observations ───────────────────────────────────────────────
--
-- What a shadowed rule *would* have alerted on. Separate from `alerts`
-- so a shadow match cannot be mistaken for one, by a query or a person.

CREATE TABLE IF NOT EXISTS detection_shadow_matches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id         UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    rule_version    INTEGER,
    event_id        TEXT,
    matched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_excerpt   JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_shadow_matches_rule ON detection_shadow_matches (rule_id, matched_at DESC);
CREATE INDEX IF NOT EXISTS ix_shadow_matches_tenant ON detection_shadow_matches (tenant_id, matched_at DESC);

ALTER TABLE detection_shadow_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_shadow_matches FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON detection_shadow_matches;
CREATE POLICY tenant_isolation ON detection_shadow_matches
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON detection_shadow_matches TO aisoc_app;
    END IF;
END
$$;

COMMENT ON TABLE detection_shadow_matches IS
    'What a shadowed rule would have raised. A separate table rather than a flag on '
    'alerts, so no query or person can mistake a shadow match for an alert.';
