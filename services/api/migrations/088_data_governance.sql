-- Legal hold, residency, field-level access, subject deletion, signed exports.
--
-- Gap-closure wave 14.
--
-- The retention worker can purge, and nothing can stop it. There is
-- no legal hold, so the correct response to "preserve everything
-- relating to this account pending litigation" is to disable
-- retention for the whole tenant and remember to turn it back on.
--
-- Residency is a label on a tenant that no query consults, so a
-- deployment spanning regions cannot demonstrate that EU data stayed
-- in the EU — it can only assert it.
--
-- Field-level access does not exist: a viewer who can read an alert
-- reads every field of it, including the raw event, which carries
-- whatever the source put there.
--
-- Per-subject deletion has no path at all. `tenant_deletion.py`
-- removes a whole tenant; "delete everything about this person" is a
-- different question and the common one.

-- ── Legal hold ─────────────────────────────────────────────────────────────
--
-- A hold must outrank retention unconditionally. Any ordering where
-- retention can win is a system that deletes evidence under
-- litigation, which is the one outcome that cannot be apologised for.

CREATE TABLE IF NOT EXISTS legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    name            TEXT NOT NULL,
    matter_ref      TEXT,

    -- What is held. A predicate rather than a list of ids, because
    -- the rows a hold covers keep arriving after it is placed — a
    -- hold frozen to the ids that existed when it was written covers
    -- none of the evidence created during the incident.
    subject_kind    TEXT NOT NULL,
    subject_value   TEXT NOT NULL,

    placed_by_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    placed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Lifting is an event with an actor, not a deletion. A hold that
    -- vanishes leaves no evidence it ever existed, which defeats the
    -- audit the hold was placed for.
    released_at     TIMESTAMPTZ,
    released_by_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    release_reason  TEXT,

    notes           TEXT
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_legal_hold_subject') THEN
        ALTER TABLE legal_holds
            ADD CONSTRAINT ck_legal_hold_subject
            CHECK (subject_kind IN ('user', 'host', 'case', 'alert', 'tenant', 'ip'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS ix_legal_holds_live
    ON legal_holds (tenant_id, subject_kind, subject_value)
    WHERE released_at IS NULL;

COMMENT ON TABLE legal_holds IS
    'Outranks retention unconditionally. Stored as a predicate rather than a list of '
    'ids because the rows a hold covers keep arriving after it is placed.';

-- ── Residency ──────────────────────────────────────────────────────────────

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS data_region TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS residency_enforced BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tenants.residency_enforced IS
    'When true, a write or export naming a region other than data_region is refused. '
    'Off by default: turning it on for an existing tenant whose data already spans '
    'regions would break it silently, so adopting it is a deliberate step.';

CREATE TABLE IF NOT EXISTS residency_violations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expected_region TEXT NOT NULL,
    actual_region   TEXT NOT NULL,
    operation       TEXT NOT NULL,
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE residency_violations IS
    'Recorded even when the operation is refused. A refusal nobody counted cannot '
    'answer "has this ever happened", which is the question an auditor asks.';

-- ── Field-level access ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS field_access_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    resource        TEXT NOT NULL,
    field_path      TEXT NOT NULL,

    -- Roles that may see it in full. Everyone else gets the treatment
    -- below rather than an error: a missing field and a hidden field
    -- look the same to a client, and an analyst needs to know the
    -- difference.
    visible_to_roles TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
    treatment       TEXT NOT NULL DEFAULT 'redact',

    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, resource, field_path)
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_field_treatment') THEN
        ALTER TABLE field_access_rules
            ADD CONSTRAINT ck_field_treatment
            CHECK (treatment IN ('redact', 'mask', 'hash', 'omit'));
    END IF;
END
$$;

-- ── Per-subject deletion ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS subject_deletion_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    subject_kind    TEXT NOT NULL,
    subject_value   TEXT NOT NULL,

    requested_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- `pending`, `blocked_by_hold`, `in_progress`, `completed`,
    -- `refused`. `blocked_by_hold` is its own state rather than a
    -- failure: a deletion refused because of litigation is a correct
    -- outcome that has to be reportable to the person who asked.
    status          TEXT NOT NULL DEFAULT 'pending',
    blocked_by_hold_id UUID REFERENCES legal_holds(id) ON DELETE SET NULL,

    -- What was removed, per table. An auditor needs the counts, and a
    -- deletion that reports only "done" cannot be verified.
    affected_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    completed_at    TIMESTAMPTZ,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS ix_subject_deletion ON subject_deletion_requests (tenant_id, status, requested_at DESC);

-- ── Signed exports ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS export_signatures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    export_kind     TEXT NOT NULL,
    content_sha256  TEXT NOT NULL,
    signature       TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'ed25519',

    -- What was asked for, so a recipient can tell a partial export
    -- from a complete one. An export that omits rows and does not say
    -- so is worse than no export.
    query_digest    TEXT,
    row_count       INTEGER,

    exported_by_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    exported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_export_signatures ON export_signatures (tenant_id, exported_at DESC);

COMMENT ON TABLE export_signatures IS
    'Detached signatures over exported bundles. The signature is kept here rather than '
    'only in the bundle so a recipient can verify against a record the sender cannot '
    'alter after the fact.';

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'legal_holds',
        'residency_violations',
        'field_access_rules',
        'subject_deletion_requests',
        'export_signatures'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
            'WITH CHECK (tenant_id = current_tenant_id())',
            t
        );
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO aisoc_app', t);
        END IF;
    END LOOP;
END
$$;
