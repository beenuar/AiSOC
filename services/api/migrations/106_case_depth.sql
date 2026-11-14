-- 106_case_depth.sql — case merge, tenant custom fields, and the columns a
-- merge needs to keep history.
--
-- Depth plan 9.3 (parity 5.6 remainder).
--
-- What was already there and what was not
-- ---------------------------------------
-- `alerts` has carried `is_merged`, `parent_alert_id` and `child_alert_ids`
-- since migration 001 and **nothing has ever written any of them** — the
-- parity plan says so and a grep across `services/api/app` confirms it: the
-- only mention outside the ORM model is the ORM model. So the alert half of
-- merge needs no schema change at all, only a writer. That is the recurring
-- defect in this tree and it is worth being explicit that this migration is
-- deliberately *not* adding what already exists.
--
-- `aisoc_cases` has no merge columns, so the case half does need them.
--
-- Why a merge keeps both rows
-- ---------------------------
-- The absorbed case is not deleted. `merged_into_id` points at the survivor
-- and the status moves to `closed` with a reason. Deleting would lose the
-- audit chain, the evidence custody entries and the external references
-- (`case_external_refs`) that a vendor system already holds a ticket id for
-- — and a ticket pointing at a case id that no longer resolves is worse for
-- the analyst than one pointing at a case marked merged.
--
-- `merged_at` and `merged_by` are separate from `closed_at`/`updated_at` for
-- the reason the console-number work found the hard way: a timestamp that
-- moves whenever anybody edits the row cannot answer "when was this merged".
--
-- Tenant custom fields: two tables, because they answer different questions
-- ------------------------------------------------------------------------
-- `aisoc_tenant_custom_fields` is the tenant's schema — what fields exist,
-- what type each is, whether it is required, and what the permitted choices
-- are for a select. `aisoc_case_custom_values` is the data.
--
-- The obvious alternative is one JSONB column on `aisoc_cases`. It is wrong
-- here for a specific reason rather than on principle: a definition nobody
-- can enumerate cannot be rendered as a form, cannot be validated at write
-- time, and cannot be removed cleanly — "which cases still carry the field
-- we retired" is a question a JSONB blob answers only by scanning every row
-- and guessing at key spellings. A tenant that renames a field in a blob has
-- silently created a second field.
--
-- `field_type` is a closed set because each value maps to exactly one
-- validator and one input control. An open type is one the console cannot
-- render and the API cannot check.
--
-- Reversible: DROP TABLE IF EXISTS the two tables (values first), then the
-- three ALTER TABLE ... DROP COLUMN on aisoc_cases.

-- ── Case merge ─────────────────────────────────────────────────────────────

ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS merged_into_id UUID
    REFERENCES aisoc_cases(id) ON DELETE SET NULL;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS merged_at      TIMESTAMPTZ;
ALTER TABLE aisoc_cases ADD COLUMN IF NOT EXISTS merged_by      TEXT;

-- "What was folded into this case" — the query the case view runs. Partial,
-- because the overwhelming majority of cases were never merged into
-- anything and an index over those rows is dead weight.
CREATE INDEX IF NOT EXISTS aisoc_cases_merged_into_idx
    ON aisoc_cases (merged_into_id)
    WHERE merged_into_id IS NOT NULL;

COMMENT ON COLUMN aisoc_cases.merged_into_id IS
    'The surviving case this one was folded into. The absorbed row is kept, not deleted: '
    'deleting loses the audit chain, the custody entries and any vendor ticket that already '
    'points at this id.';

-- ── Tenant custom fields ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS aisoc_tenant_custom_fields (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Stable machine name. Immutable by convention: renaming is a new field
    -- plus a migration of the values, because a rename in place silently
    -- changes the meaning of every historical value.
    key             TEXT        NOT NULL,
    label           TEXT        NOT NULL,
    help_text       TEXT        NOT NULL DEFAULT '',

    -- Closed set: each value maps to exactly one validator and one input
    -- control. An open type is one the console cannot render and the API
    -- cannot check.
    field_type      TEXT        NOT NULL
                    CHECK (field_type IN ('text', 'number', 'boolean', 'date', 'select')),
    -- Permitted values for `select`. Empty for every other type, and the
    -- service refuses a select with none rather than storing a field whose
    -- form has no options.
    choices         TEXT[]      NOT NULL DEFAULT '{}',

    required        BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Where it appears in the form. Ties broken by `key` so the order is
    -- total and a render is reproducible.
    position        INTEGER     NOT NULL DEFAULT 0,

    -- Retired rather than deleted, for the same reason a merged case is:
    -- values already written against it stay readable and attributable.
    active          BOOLEAN     NOT NULL DEFAULT TRUE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_tenant_custom_fields_key_unique UNIQUE (tenant_id, key),
    -- A select with no choices renders an empty dropdown an analyst cannot
    -- satisfy, which for a required field makes the case unsaveable.
    CONSTRAINT aisoc_tenant_custom_fields_select_has_choices
        CHECK (field_type <> 'select' OR cardinality(choices) > 0)
);

CREATE INDEX IF NOT EXISTS aisoc_tenant_custom_fields_tenant_idx
    ON aisoc_tenant_custom_fields (tenant_id, position, key)
    WHERE active;

CREATE TABLE IF NOT EXISTS aisoc_case_custom_values (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id         UUID        NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    field_id        UUID        NOT NULL REFERENCES aisoc_tenant_custom_fields(id) ON DELETE CASCADE,

    -- One text column rather than one per type. The definition says how to
    -- read it, the service validates and canonicalises on write (ISO-8601
    -- for a date, "true"/"false" for a boolean), and a reader that ignores
    -- the definition gets a string rather than a wrong number.
    value           TEXT        NOT NULL DEFAULT '',

    updated_by      TEXT        NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_case_custom_values_unique UNIQUE (case_id, field_id)
);

CREATE INDEX IF NOT EXISTS aisoc_case_custom_values_case_idx
    ON aisoc_case_custom_values (case_id);

COMMENT ON TABLE aisoc_tenant_custom_fields IS
    'A tenant''s own case schema. Separate from the values so a field can be enumerated, '
    'rendered as a form, validated at write time and retired cleanly -- none of which a '
    'JSONB blob on aisoc_cases supports.';

-- Written out per table rather than looped with format(): a loop makes the
-- policy invisible to grep and to scripts/check_tenant_query_predicates.py,
-- which reads migrations to learn which tables carry one.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_tenant_custom_fields ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_tenant_custom_fields FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_tenant_custom_fields';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_tenant_custom_fields '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    EXECUTE 'ALTER TABLE aisoc_case_custom_values ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_case_custom_values FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_case_custom_values';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_case_custom_values '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_tenant_custom_fields TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_case_custom_values TO aisoc_app';
    END IF;
END
$$;
