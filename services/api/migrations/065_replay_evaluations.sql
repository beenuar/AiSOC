-- 065: replay evaluation jobs and the decisions behind their reports.
--
-- Gap-closure Phase 1.4. An operator asks "how would this have done on my
-- alerts", the API reads their closed findings, replays them through the
-- production triage path and grades the result. This is where the answer
-- lives.
--
-- Note on the number: 064 is `064_sandbox_upload_policy.sql`, which landed
-- from a different phase while this one was in flight. The plan's deviation
-- log names 064 for this table because that was the next free number when it
-- was written. It is not any more.
--
-- Why two tables
-- --------------
-- `aisoc_replay_evaluations` answers "what did the report say". It is read on
-- every page load and every export, and it is small.
--
-- `aisoc_replay_decisions` answers "why did it say that". One row per
-- replayed finding, holding the analyst's label, the agent's verdict and the
-- evidence the agent was given. It is read when somebody disputes a number,
-- which is rare and heavy. Folding them into one table would put a few
-- megabytes of evidence behind every list query.
--
-- Why the report markdown is stored rather than re-rendered
-- ---------------------------------------------------------
-- The phase's acceptance bar is that a report reproduces byte for byte. A
-- report re-rendered later by a newer renderer is a different artefact from
-- the one the operator read, and the export would silently stop matching what
-- the page showed when it was produced. `report_markdown` is the artefact.
-- `score` is kept alongside it so the console can render structured views
-- without parsing prose back out.
--
-- Why a status column and not a queue
-- -----------------------------------
-- The job runs in-process in the API, which is where the vault and the tenant
-- session already are. `status` is how a caller polling `GET
-- /evaluations/replay/{id}` tells a run still going from one that failed, and
-- `error` is why. A run that crashed reads `failed` with a reason rather than
-- staying `running` forever, because a job that never terminates is
-- indistinguishable from a slow one.

CREATE TABLE IF NOT EXISTS aisoc_replay_evaluations (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- 'queued' | 'running' | 'completed' | 'failed'
    status              TEXT        NOT NULL DEFAULT 'queued',
    error               TEXT,

    -- What was asked for.
    connector_id        TEXT        NOT NULL,
    vendor              TEXT        NOT NULL,
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    train_fraction      DOUBLE PRECISION NOT NULL,
    -- Both travel onto the row because both change the confidence intervals,
    -- and a report whose seed is not recorded cannot be reproduced.
    bootstrap_seed      INTEGER     NOT NULL,
    bootstrap_resamples INTEGER     NOT NULL,

    -- Sample sizes, promoted out of the score JSON because the console shows
    -- them beside the headline and a list query should not have to open a
    -- JSONB document to say how much was graded.
    findings_read       INTEGER     NOT NULL DEFAULT 0,
    findings_labelled   INTEGER     NOT NULL DEFAULT 0,
    decisions_recorded  INTEGER     NOT NULL DEFAULT 0,
    graded              INTEGER     NOT NULL DEFAULT 0,
    malicious_support   INTEGER     NOT NULL DEFAULT 0,

    -- NULL when the corpus was too thin for a headline. Not 0: a zero in an
    -- accuracy column says the agent got everything wrong, and "withheld" is
    -- a different fact with a different remedy. `headline_withheld_reason`
    -- carries the sentence the report prints.
    headline_accuracy   DOUBLE PRECISION,
    headline_withheld_reason TEXT,
    malicious_recall    DOUBLE PRECISION,

    -- The full `ReplayScore.as_dict()` and the method block the runner
    -- produced, so the console can render every panel from one read.
    score               JSONB,
    method              JSONB,
    -- The artefact the operator read, byte for byte.
    report_markdown     TEXT,

    requested_by        UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ
);

COMMENT ON TABLE aisoc_replay_evaluations IS
    'One replay evaluation: triage measured against a tenant''s own analysts on '
    'their own closed findings. The stored report_markdown is the artefact the '
    'operator read, not a re-render.';
COMMENT ON COLUMN aisoc_replay_evaluations.headline_accuracy IS
    'NULL when withheld for a thin corpus. Never 0 to mean "not measured".';
COMMENT ON COLUMN aisoc_replay_evaluations.bootstrap_seed IS
    'Seed the percentile bootstrap used. Recorded because a report that cannot '
    'name its seed cannot be reproduced.';

CREATE TABLE IF NOT EXISTS aisoc_replay_decisions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    evaluation_id       UUID        NOT NULL REFERENCES aisoc_replay_evaluations(id) ON DELETE CASCADE,
    -- Denormalised so the RLS policy on this table stands on its own rather
    -- than on a join. A policy that has to reach another table to decide is a
    -- policy that returns nothing when that table is itself filtered.
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    finding_id          TEXT        NOT NULL,
    vendor              TEXT        NOT NULL,
    rule_id             TEXT,
    closed_at           TIMESTAMPTZ,

    -- The analyst's label, canonical. 'unlabeled' means excluded from
    -- accuracy, never guessed.
    expected_disposition TEXT       NOT NULL,
    vendor_disposition  TEXT        NOT NULL DEFAULT '',
    labelled            BOOLEAN     NOT NULL DEFAULT FALSE,

    -- What triage said. `verdict_raw` is kept beside the canonical form
    -- because a verdict the taxonomy does not recognise is a finding about
    -- the product and must not be laundered into a canonical one.
    verdict             TEXT,
    verdict_raw         TEXT,
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0,
    tier                TEXT        NOT NULL DEFAULT '',

    -- Reasoning and the evidence it was produced from, so a disputed
    -- hallucination score can be re-derived rather than re-argued.
    decision            JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- Set when triage refused the finding outright, which is neither a
    -- verdict nor an abstention and is scored as neither.
    error               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE aisoc_replay_decisions IS
    'One replayed finding: the analyst label, the agent verdict, and the evidence '
    'the agent was given. Kept so a disputed score can be re-derived.';

CREATE INDEX IF NOT EXISTS idx_replay_evaluations_tenant_created
    ON aisoc_replay_evaluations (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_replay_evaluations_tenant_status
    ON aisoc_replay_evaluations (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_replay_decisions_evaluation
    ON aisoc_replay_decisions (evaluation_id);
CREATE INDEX IF NOT EXISTS idx_replay_decisions_tenant
    ON aisoc_replay_decisions (tenant_id, created_at DESC);

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) reach these
-- tables on a connection that binds no tenant; dropping it makes those
-- silently see nothing. FORCE so the owner does not walk past, because the
-- owner is the role that runs migrations.
ALTER TABLE aisoc_replay_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_replay_evaluations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_replay_evaluations_tenant ON aisoc_replay_evaluations;
CREATE POLICY aisoc_replay_evaluations_tenant ON aisoc_replay_evaluations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_replay_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_replay_decisions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_replay_decisions_tenant ON aisoc_replay_decisions;
CREATE POLICY aisoc_replay_decisions_tenant ON aisoc_replay_decisions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_replay_evaluations TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_replay_decisions TO aisoc_app;
    END IF;
END
$$;
