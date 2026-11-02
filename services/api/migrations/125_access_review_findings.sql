-- 125: access-review findings (depth plan wave 2, Phase 1.2).
--
-- Read-only by construction
-- -------------------------
-- Every row here names an object a human should go and change, and nothing
-- in the product acts on one. That is a scope decision from the plan, and
-- it is also what makes the review safe to run across a whole estate: a
-- review that could act is one nobody enables.
--
-- Why the findings are stored rather than recomputed per request
-- --------------------------------------------------------------
-- Computing them needs the posture snapshot, the derived privilege facts and
-- the usage overlay joined per principal, which is an estate-sized scan. The
-- console page is a list a reviewer works through over days, with assignment
-- and acknowledgement, so the rows need identity and lifecycle of their own.
--
-- The honest-empty-state column
-- -----------------------------
-- `usage_measured` travels on the row. A finding computed where usage could
-- not be measured is a different, weaker claim than one computed where it
-- could, and a page that cannot tell them apart shows a short list and lets
-- a reviewer read it as a clean estate. The same reason `run_state` exists
-- on the run table below: zero findings over zero principals is "nothing
-- reviewed", never "no findings".

CREATE TABLE IF NOT EXISTS access_review_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL,
    provider        text NOT NULL,

    -- 'nothing_reviewed' | 'no_findings' | 'findings' | 'failed'.
    -- `nothing_reviewed` is the state the whole table exists to be able to
    -- express: an estate nobody could look at must not render identically
    -- to one with nothing wrong.
    run_state       text NOT NULL DEFAULT 'nothing_reviewed',

    reviewed_principals integer NOT NULL DEFAULT 0,
    -- How many of those had usage data behind them. Lower than
    -- reviewed_principals means a partial review, and the page says so.
    usage_measured_for  integer NOT NULL DEFAULT 0,
    finding_count   integer NOT NULL DEFAULT 0,

    -- The trailing window the usage half was computed over. A finding that
    -- says "unused" is meaningless without it, and the window changes.
    window_start    timestamptz,
    window_end      timestamptz,

    note            text,
    started_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,

    CONSTRAINT access_review_runs_provider_check CHECK (
        provider IN ('aws', 'azure', 'gcp', 'gws', 'github', 'okta')
    ),
    CONSTRAINT access_review_runs_state_check CHECK (
        run_state IN ('nothing_reviewed', 'no_findings', 'findings', 'failed')
    )
);

CREATE INDEX IF NOT EXISTS access_review_runs_recent_idx
    ON access_review_runs (tenant_id, provider, started_at DESC);


CREATE TABLE IF NOT EXISTS access_review_findings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL,
    run_id          uuid NOT NULL REFERENCES access_review_runs(id) ON DELETE CASCADE,

    kind            text NOT NULL,
    provider        text NOT NULL,
    principal_id    text NOT NULL,
    severity        text NOT NULL DEFAULT 'medium',

    title           text NOT NULL,
    detail          text NOT NULL,
    -- The object a person should change. Required, not nullable: a
    -- read-only finding that does not say where to go leaves the reviewer
    -- with the hard half of the work, which is why reviews do not happen.
    object_hint     text NOT NULL,
    recommendation  text NOT NULL,
    -- The smallest built-in role covering everything the principal actually
    -- used, where one exists. NULL means either usage was not measured or
    -- no built-in covers the used set -- and the second is a real answer
    -- for a principal doing genuinely broad work, not a failure.
    best_fit_role   text,

    evidence        jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- False means this finding was computed without usage data behind it.
    -- Usage-dependent kinds are never emitted in that case, so a false here
    -- marks the weaker non-usage findings for what they are.
    usage_measured  boolean NOT NULL DEFAULT false,

    -- Reviewer lifecycle. Acknowledgement is the only state transition, and
    -- it records a person rather than a flag, because "who decided this was
    -- fine" is the question an auditor asks.
    acknowledged_at timestamptz,
    acknowledged_by uuid,
    acknowledged_note text,

    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT access_review_findings_provider_check CHECK (
        provider IN ('aws', 'azure', 'gcp', 'gws', 'github', 'okta')
    ),
    CONSTRAINT access_review_findings_severity_check CHECK (
        severity IN ('info', 'low', 'medium', 'high', 'critical')
    )
);

-- One open finding per (principal, kind) per tenant. A review that runs
-- nightly must not accumulate ninety copies of the same sentence; a repeat
-- extends `last_seen` on the row the reviewer has already seen, and keeps
-- their acknowledgement attached to it.
CREATE UNIQUE INDEX IF NOT EXISTS access_review_findings_unique_idx
    ON access_review_findings (tenant_id, provider, principal_id, kind);

CREATE INDEX IF NOT EXISTS access_review_findings_open_idx
    ON access_review_findings (tenant_id, provider, severity, last_seen DESC)
    WHERE acknowledged_at IS NULL;

COMMENT ON TABLE access_review_findings IS
    'Read-only access-review findings. Nothing in the product acts on one: each names the object a '
    'human should change and stops.';

COMMENT ON COLUMN access_review_findings.usage_measured IS
    'False when no usage data backed this review. Usage-dependent kinds are suppressed entirely in '
    'that case rather than caveated, because a caveat on "revoke this" is read by nobody.';


DO $$
BEGIN
    EXECUTE 'ALTER TABLE access_review_runs ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE access_review_runs FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON access_review_runs';
    EXECUTE
        'CREATE POLICY tenant_isolation ON access_review_runs '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    EXECUTE 'ALTER TABLE access_review_findings ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE access_review_findings FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON access_review_findings';
    EXECUTE
        'CREATE POLICY tenant_isolation ON access_review_findings '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON access_review_runs TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON access_review_findings TO aisoc_app';
    END IF;
END
$$;
