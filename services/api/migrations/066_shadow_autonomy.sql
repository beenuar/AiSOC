-- 066: what the agent said, what the analyst said, and whether they agreed.
--
-- Gap-closure Phase 2.1 and 2.2.
--
-- Two tables, because they answer different questions and neither answers the
-- other.
--
--   aisoc_shadow_mode        which alert classes this tenant is measuring
--                            rather than acting on
--   aisoc_shadow_decisions   one row per verdict produced while measuring,
--                            plus the analyst's own closure when it arrives
--
-- Why a decision ledger and not a counter
-- ---------------------------------------
-- A running agreement percentage is cheap and useless. The question asked of
-- a promotion six months later is "which decisions was that built on", and a
-- counter cannot answer it. Rows can: they carry the alert, the rule, the
-- source, the model and both verdicts, so a disputed promotion resolves into
-- a list of alerts somebody can open.
--
-- Why agreement is not stored
-- ---------------------------
-- There is no `agreed` column. Agreement is `verdict = analyst_disposition`,
-- derived in the aggregate query in `autonomy_evidence_rules.py`, so there is
-- exactly one definition of it. A stored boolean would be a second definition
-- that is correct on the day it is written and silently wrong after the
-- taxonomy moves, and it would be wrong in the direction that reads as a
-- better track record.
--
-- Why the analyst half is nullable
-- --------------------------------
-- Most rows sit unresolved for days. An alert the agent triaged this morning
-- has no analyst closure yet, and it must not be counted as agreement or as
-- disagreement in the meantime. `resolved_at IS NULL` is the whole of "not
-- evidence yet", and every aggregate filters on it.
--
-- `analyst_disposition` accepts `unlabeled`, which is the analyst saying "I
-- do not know" rather than the absence of an answer. Splunk ES ships two
-- dispositions that mean exactly that, and so do Sentinel and Defender.
-- Excluding those rows from accuracy while still counting them as resolved is
-- what stops a tenant whose history is mostly unlabeled from seeing a
-- confident rate derived from a remnant.
--
-- Why the class is a plain string
-- -------------------------------
-- `alerts.category` is `VARCHAR(100)` and nullable, and the classes that
-- appear in it are set by detection content rather than by an enum here. A
-- foreign key would make an ingest of new detection content fail at the
-- shadow ledger, which is the wrong place for that to break. Rows with no
-- category land under `unclassified` so they are still measurable rather
-- than invisible.

CREATE TABLE IF NOT EXISTS aisoc_shadow_mode (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- An `alerts.category` value, or `*` for every class this tenant sees.
    -- The wildcard is how a tenant starts: measuring one class at a time
    -- requires knowing which classes exist, which is what the first weeks of
    -- measurement are for.
    alert_class TEXT        NOT NULL,
    -- Off. A deployment that has not asked to measure is not measuring, and
    -- defaulting this on would start writing decision rows for every tenant
    -- on upgrade.
    enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
    enabled_at  TIMESTAMPTZ,
    updated_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, alert_class)
);

COMMENT ON TABLE aisoc_shadow_mode IS
    'Which alert classes a tenant is triaging in shadow: the verdict is recorded '
    'and measured, and nothing is written back, acted on or auto-closed.';
COMMENT ON COLUMN aisoc_shadow_mode.enabled_at IS
    'When measurement started. A promotion window that reaches back before this '
    'is reaching back before there was anything to measure.';

CREATE TABLE IF NOT EXISTS aisoc_shadow_decisions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The AiSOC alert this verdict was about. Nullable because a finding
    -- polled straight from a customer's SIEM may never have become an alert
    -- row here.
    alert_id            UUID,
    -- The vendor's own finding id. This is the join key an analyst closure
    -- polled from the source SIEM arrives on, and without it a closure made
    -- in Splunk cannot be matched to the verdict it should be graded against.
    external_id         TEXT,
    alert_class         TEXT        NOT NULL DEFAULT 'unclassified',
    rule_id             TEXT,
    -- `alerts.connector_type`: which product the finding came from.
    source              TEXT,
    -- What the gateway actually resolved the request to, not the alias asked
    -- for. Agreement is per model as well as per class, and an alias is not a
    -- model.
    model               TEXT,
    verdict             TEXT,
    confidence          DOUBLE PRECISION,
    -- The cost governor's evidence fingerprint, so a disputed row can be tied
    -- back to the evidence the verdict was formed on.
    evidence_signature  TEXT,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The analyst half. All null until somebody closes the alert.
    analyst_disposition TEXT,
    -- Where the closure came from: `aisoc` when an analyst closed it in this
    -- console, or the vendor name when it was polled back out of their SIEM.
    -- Recorded because "our analysts agree with it" and "their SIEM agrees
    -- with it" are different claims and a promotion may rest on either.
    resolution_source   TEXT,
    resolved_at         TIMESTAMPTZ,
    resolved_by         TEXT,
    -- The vendor's own label, verbatim. A mapping somebody later disputes is
    -- only arguable if what was actually recorded survived.
    vendor_disposition  TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE aisoc_shadow_decisions IS
    'One row per shadow triage verdict, with the analyst closure it is graded '
    'against once that arrives. The evidence behind every autonomy promotion.';
COMMENT ON COLUMN aisoc_shadow_decisions.resolved_at IS
    'Null until an analyst closes the alert. A row with no closure is not '
    'evidence yet and every aggregate excludes it.';
COMMENT ON COLUMN aisoc_shadow_decisions.analyst_disposition IS
    'Canonical disposition, or the literal `unlabeled` when the analyst '
    'declined to classify. Unlabeled rows count as resolved and are excluded '
    'from every rate.';
COMMENT ON COLUMN aisoc_shadow_decisions.verdict IS
    'The agent verdict. A null here is an abstention, the same as an explicit '
    '`needs_review`: both mean the agent did not decide.';

-- One verdict per alert. A worker that re-triages after a broker redelivery
-- must not double-count its own opinion into the evidence: two identical rows
-- would show as two agreements and inflate the sample toward promotion.
CREATE UNIQUE INDEX IF NOT EXISTS uq_shadow_decisions_alert
    ON aisoc_shadow_decisions (tenant_id, alert_id) WHERE alert_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_shadow_decisions_external
    ON aisoc_shadow_decisions (tenant_id, source, external_id)
    WHERE alert_id IS NULL AND external_id IS NOT NULL;

-- The window aggregate filters on `resolved_at` and orders by it for the
-- trailing drift slice, so that is the index it needs. Partial, because the
-- unresolved rows are never in any aggregate and are the majority early on.
CREATE INDEX IF NOT EXISTS idx_shadow_decisions_resolved
    ON aisoc_shadow_decisions (tenant_id, resolved_at DESC)
    WHERE resolved_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_shadow_decisions_class
    ON aisoc_shadow_decisions (tenant_id, alert_class, resolved_at DESC)
    WHERE resolved_at IS NOT NULL;
-- Reconciliation looks a decision up by the vendor finding id when a closure
-- arrives from the source SIEM.
CREATE INDEX IF NOT EXISTS idx_shadow_decisions_external_lookup
    ON aisoc_shadow_decisions (tenant_id, external_id)
    WHERE external_id IS NOT NULL AND resolved_at IS NULL;

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) and the agents
-- worker's unbound pool read these; dropping it makes those silently see
-- nothing. FORCE so the owner does not walk past.
ALTER TABLE aisoc_shadow_mode ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_shadow_mode FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_shadow_mode_tenant ON aisoc_shadow_mode;
CREATE POLICY aisoc_shadow_mode_tenant ON aisoc_shadow_mode
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_shadow_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_shadow_decisions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_shadow_decisions_tenant ON aisoc_shadow_decisions;
CREATE POLICY aisoc_shadow_decisions_tenant ON aisoc_shadow_decisions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_shadow_mode TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_shadow_decisions TO aisoc_app;
    END IF;
END
$$;
