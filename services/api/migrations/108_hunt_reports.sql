-- 108_hunt_reports.sql — a hunt that found something becomes a case report
-- somebody can hand to a reader.
--
-- Depth plan 9.5. A natural-language hunt produced rows and a retro-hunt
-- produced a `retro_hunt_sightings` row, and neither produced anything a
-- person could read, forward or file. `grep -n hunt` across
-- `services/api/app/services/report_builder.py` and
-- `app/api/v1/endpoints/reports.py` returned nothing at all: the report
-- surface and the hunt surface did not know about each other.
--
-- Why the four sections are columns and not a blob
-- ------------------------------------------------
-- What, how, where and when are the questions the plan names, and they are
-- the questions a reader asks in that order. Storing them separately means
-- the HTML and PDF renderers share one structure, a reader of the row can
-- tell an empty section from an absent one, and a section that could not be
-- derived stays empty rather than being filled with a confident sentence
-- about nothing.
--
-- Why citations are their own column and are required to be a list
-- ----------------------------------------------------------------
-- "With ledger citations" is the load-bearing half of the item. A report
-- with no citation is an assertion, and this product's whole position is
-- that an assertion is not evidence. Each entry names a kind, an id and a
-- human label, so a renderer can link it and an auditor can resolve it
-- after the fact.
--
-- Why `case_id` is nullable
-- -------------------------
-- A hunt can find something before anybody has decided it is a case. The
-- report is written first and attached when the case exists, which is the
-- order the work actually happens in; forcing the case first would mean
-- opening one to find out whether you need it.
--
-- Reversible: DROP TABLE IF EXISTS aisoc_hunt_reports.

CREATE TABLE IF NOT EXISTS aisoc_hunt_reports (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Which surface produced it. Closed, because each value has exactly one
    -- builder and an unknown kind is a report nobody can regenerate.
    source_kind     TEXT        NOT NULL CHECK (source_kind IN ('hunt', 'retro_hunt')),
    -- The saved hunt or the sighting. Not an FK: the two live in different
    -- tables and a report should outlive the hunt definition it came from,
    -- the same reason a closed case outlives the rule that opened it.
    source_id       UUID        NOT NULL,

    case_id         UUID        REFERENCES aisoc_cases(id) ON DELETE SET NULL,

    title           TEXT        NOT NULL,

    -- The four questions, in the order a reader asks them.
    what            TEXT        NOT NULL DEFAULT '',
    how             TEXT        NOT NULL DEFAULT '',
    "where"         TEXT        NOT NULL DEFAULT '',
    "when"          TEXT        NOT NULL DEFAULT '',

    -- `[{kind, id, label}]`. A report with none is an assertion, which is
    -- the thing this product exists to be the opposite of.
    citations       JSONB       NOT NULL DEFAULT '[]'::jsonb,

    -- How many rows the hunt matched. Stored because the report is a
    -- snapshot: re-running the hunt tomorrow gives a different number and
    -- the report has to keep saying what it said when it was written.
    match_count     INTEGER     NOT NULL DEFAULT 0,

    generated_by    TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_hunt_reports_citations_is_array CHECK (jsonb_typeof(citations) = 'array')
);

CREATE INDEX IF NOT EXISTS aisoc_hunt_reports_tenant_idx
    ON aisoc_hunt_reports (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS aisoc_hunt_reports_case_idx
    ON aisoc_hunt_reports (case_id)
    WHERE case_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS aisoc_hunt_reports_source_idx
    ON aisoc_hunt_reports (tenant_id, source_kind, source_id);

COMMENT ON TABLE aisoc_hunt_reports IS
    'What a hunt found, written so a person can read it: what, how, where, when, and the '
    'ledger citations behind each. A snapshot -- re-running the hunt tomorrow gives a '
    'different answer and the report has to keep saying what it said when it was written.';

-- Written out rather than looped with format(): a loop makes the policy
-- invisible to grep and to scripts/check_tenant_query_predicates.py.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_hunt_reports ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_hunt_reports FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_hunt_reports';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_hunt_reports '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_hunt_reports TO aisoc_app';
    END IF;
END
$$;
