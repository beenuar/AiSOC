-- Wave 2, Phase 3.3, second half — four vendors reporting one misconfigured
-- bucket is one finding, not four alerts.
--
-- What migration 151 did and did not reach
-- -----------------------------------------
-- 151 keeps *same-fingerprint* repeats as linked occurrences, so a vendor
-- re-reporting one finding 79 times is one alert that says 79. It cannot
-- touch the other half of the same problem: Security Hub, Defender for
-- Cloud, a CNAPP connector and GuardDuty each raising their own finding
-- about the same public S3 bucket produce four *different* fingerprints —
-- different titles, different vendors, different severities — so every
-- dedup layer in the pipeline correctly leaves all four standing.
--
-- They are four reports of one root cause. The analyst closes the same
-- misconfiguration four times.
--
-- What counts as one root cause
-- ------------------------------
-- The triple `(resource, technique, principal)`. All three, and the
-- conjunction is the control:
--
--   * **resource** alone over-collapses. Two unrelated findings on one
--     busy host are two findings, which is the lesson v21 paid for when a
--     missing tactic collapsed an exfiltration alert into a port scan.
--   * **technique** alone is a category, not an incident.
--   * **principal** alone is an account's whole day.
--
-- A NULL in any component does not match another NULL. "We do not know the
-- principal" is not evidence that two findings share one, and treating
-- absence as agreement is how a conservative key becomes a wide one — the
-- `correlation_key()` narrowing ladder is the same argument, and this table
-- enforces it in the index rather than leaving it to a caller.
--
-- Why a finding row rather than a column on one alert
-- ----------------------------------------------------
-- Every original stays, and stays queryable. Promoting one vendor's alert
-- to "the" alert would make the survivor's severity, title and vendor an
-- accident of arrival order, and would discard the fact that four
-- independent products agreed — which is itself the strongest evidence in
-- the group. `alert_root_cause_members` is the link; nothing is deleted and
-- nothing is rewritten.
--
-- The reduction this adds is published as its **own** labelled row,
-- separate from correlation and from repeat folding. Three reductions over
-- overlapping inputs, and a reader who summed them would be counting some
-- alerts three times.

CREATE TABLE IF NOT EXISTS root_cause_findings (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The triple, stored as the columns it is rather than as a hash, so an
    -- analyst can read why four alerts were grouped without re-deriving it,
    -- and so `scripts/check_raw_sql_columns.py` can see them.
    resource       TEXT        NOT NULL,
    technique      TEXT        NOT NULL,
    principal      TEXT        NOT NULL,
    -- How many distinct vendors reported it. The number that makes the
    -- finding worth having: one vendor is a finding, four agreeing is a
    -- different claim.
    vendor_count   INTEGER     NOT NULL DEFAULT 1 CHECK (vendor_count >= 1),
    member_count   INTEGER     NOT NULL DEFAULT 1 CHECK (member_count >= 1),
    -- The highest severity any member carried. Not an average: a finding
    -- containing one critical report is a critical finding, and averaging
    -- would let three low reports bury it.
    severity       VARCHAR(20) NOT NULL DEFAULT 'medium',
    first_seen     TIMESTAMPTZ NOT NULL,
    last_seen      TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, resource, technique, principal)
);

COMMENT ON TABLE root_cause_findings IS
    'Phase 3.3 — findings from different vendors that share a root cause '
    '(resource, technique, principal), collapsed into one record with every '
    'original kept and linked.';
COMMENT ON COLUMN root_cause_findings.vendor_count IS
    'Distinct connector types that reported this root cause. One vendor is a '
    'finding; several agreeing is a stronger claim and the reason the row exists.';

-- Which alerts belong to a finding. The originals are never deleted and
-- never rewritten; this is the only thing added.
CREATE TABLE IF NOT EXISTS alert_root_cause_members (
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id     UUID        NOT NULL REFERENCES root_cause_findings(id) ON DELETE CASCADE,
    alert_id       UUID        NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    connector_type VARCHAR(100),
    added_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One membership per alert per finding, and — through the alert's own
    -- primary key — an alert belongs to at most one finding per root cause.
    PRIMARY KEY (tenant_id, finding_id, alert_id)
);

COMMENT ON TABLE alert_root_cause_members IS
    'Phase 3.3 — the originals behind a root-cause finding. Deduplicated '
    'evidence must still resolve to its retained record, so nothing here is '
    'deleted when a finding is formed.';

-- "Show me this alert''s finding" is the read the console makes, and the
-- primary key above leads the wrong way for it.
CREATE INDEX IF NOT EXISTS idx_alert_root_cause_by_alert
    ON alert_root_cause_members (tenant_id, alert_id);

CREATE INDEX IF NOT EXISTS idx_root_cause_findings_tenant_vendors
    ON root_cause_findings (tenant_id, vendor_count DESC, last_seen DESC);

-- RLS, matching `alerts` and `alert_occurrences` — including the `IS NULL`
-- arm in WITH CHECK, and for the same measured reason migration 151 records
-- at length: fusion is a Kafka consumer, binds no `app.current_tenant_id`,
-- and the conventional stricter policy makes the row unwritable by the only
-- writer there is. The write is best-effort, so it would fail in silence and
-- the feature would read as "no vendor ever agrees with another".
ALTER TABLE root_cause_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE root_cause_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON root_cause_findings;
CREATE POLICY tenant_isolation ON root_cause_findings
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE alert_root_cause_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_root_cause_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_root_cause_members;
CREATE POLICY tenant_isolation ON alert_root_cause_members
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON root_cause_findings TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON alert_root_cause_members TO aisoc_app';
    END IF;
END $$;

-- The report this exists to make answerable — what several products agree
-- about, which is the shortest list worth an analyst's morning:
--
--     SELECT f.resource, f.technique, f.principal, f.vendor_count, f.severity
--       FROM root_cause_findings f
--      WHERE f.tenant_id = '<tenant-uuid>'::uuid
--        AND f.vendor_count > 1
--      ORDER BY f.vendor_count DESC, f.last_seen DESC;
--
-- Rollback
-- ────────
--     DROP TABLE IF EXISTS alert_root_cause_members;
--     DROP TABLE IF EXISTS root_cause_findings;
--
-- Nothing else changes. Every original alert is untouched by this feature,
-- so dropping these two tables returns the pipeline to showing four alerts
-- for one misconfiguration, which is the pre-3.3 behaviour.
