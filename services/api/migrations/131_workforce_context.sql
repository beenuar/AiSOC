-- Depth plan wave 2, item 1.3: HR and device context, available on CORE.
--
-- `services/api/app/services/context_import.py` already imports exactly this
-- context and writes it to Neo4j, which is a `full`-profile service. On a
-- CORE install -- the one `make up` gives you -- there is no graph, so the
-- HR dimension would not exist at all and every triage input reading it
-- would be silently dead. ADR 0010 put the entity store in CORE for this
-- reason; these two tables are the same decision applied to the same data.
--
-- Both paths stay. The graph import is richer, because it links employees to
-- identities and applications through relationships. These tables are the
-- ones that are always there, and the connectors scheduler writes them
-- because that service holds a Postgres engine and no Neo4j driver.
--
-- Personal data minimisation (the plan's rule, enforced in the schema rather
-- than only in the readers): these columns are the complete list of what
-- item 1.3 names. There is no column for compensation, date of birth, home
-- address, personal contact details or a national identifier, and the
-- connectors do not request those fields from the vendor either. A schema
-- that cannot hold a salary cannot leak one.

CREATE TABLE IF NOT EXISTS workforce_members (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Which HR system said so. Part of the identity because two sources can
    -- legitimately both know a person, and silently merging them would make
    -- the last connector to poll the only one that counts.
    connector_type   TEXT NOT NULL,
    external_id      TEXT NOT NULL,

    email            TEXT,
    display_name     TEXT,
    -- active | leave | terminated | pending | unknown.
    -- `unknown` is a real member and is what an unrecognised vendor value
    -- becomes. Deciding somebody still works here on a value nobody
    -- recognises is the wrong direction to be wrong in.
    status           TEXT NOT NULL DEFAULT 'unknown',
    -- DATE and not TIMESTAMPTZ: a last day is a calendar date in a
    -- jurisdiction, not an instant. Storing it as an instant moves somebody's
    -- departure by a day for half the world.
    start_date       DATE,
    end_date         DATE,
    manager_external_id TEXT,
    department       TEXT,
    -- employee | contractor | unknown. A contractor read as staff loses
    -- exactly the signal the column exists for, so a source that does not
    -- say stays unknown rather than defaulting.
    worker_type      TEXT NOT NULL DEFAULT 'unknown',
    title            TEXT,

    -- When the sync last saw this row, so a reader can tell stale context
    -- from current context. A row nobody has refreshed in a month is not the
    -- same fact as one refreshed this morning.
    last_synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT workforce_members_identity UNIQUE (tenant_id, connector_type, external_id),
    CONSTRAINT workforce_members_status_known CHECK (
        status IN ('active', 'leave', 'terminated', 'pending', 'unknown')
    ),
    CONSTRAINT workforce_members_type_known CHECK (
        worker_type IN ('employee', 'contractor', 'unknown')
    )
);

-- The lookup triage actually makes: "who is this email address". Partial on
-- a non-null email because a record with no work email cannot be joined to
-- an authentication event and would only pad the index.
CREATE INDEX IF NOT EXISTS idx_workforce_members_email
    ON workforce_members (tenant_id, lower(email))
    WHERE email IS NOT NULL;

-- "Who is leaving in the next N days" and "who left and is still
-- authenticating" are the two queries this table exists for.
CREATE INDEX IF NOT EXISTS idx_workforce_members_end_date
    ON workforce_members (tenant_id, end_date)
    WHERE end_date IS NOT NULL;


CREATE TABLE IF NOT EXISTS workforce_devices (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_type   TEXT NOT NULL,
    external_id      TEXT NOT NULL,

    hostname         TEXT,
    owner_email      TEXT,
    owner_external_id TEXT,
    -- compliant | noncompliant | in_grace_period | not_enrolled | unknown.
    -- `unknown` covers both "the MDM has not evaluated this device" and "the
    -- vendor reported a state we do not recognise", and must never render as
    -- compliant: a device nobody evaluated is not one that passed.
    compliance_state TEXT NOT NULL DEFAULT 'unknown',
    os_name          TEXT,
    os_version       TEXT,
    -- Nullable on purpose, and the null is load-bearing. FALSE means the MDM
    -- evaluated the device and found no encryption, which is a finding. NULL
    -- means nobody said, which is not. A NOT NULL DEFAULT FALSE here would
    -- put every unevaluated device into the finding.
    encrypted        BOOLEAN,
    -- The agent's own verdict, carried through under the vendor's
    -- vocabulary rather than flattened to a boolean: "no agent is talking to
    -- us" and "the agent says this device is fine" are different facts and a
    -- boolean merges them.
    edr_agent_health TEXT,
    serial_number    TEXT,
    last_seen        TIMESTAMPTZ,

    last_synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT workforce_devices_identity UNIQUE (tenant_id, connector_type, external_id),
    CONSTRAINT workforce_devices_compliance_known CHECK (
        compliance_state IN ('compliant', 'noncompliant', 'in_grace_period', 'not_enrolled', 'unknown')
    )
);

CREATE INDEX IF NOT EXISTS idx_workforce_devices_hostname
    ON workforce_devices (tenant_id, lower(hostname))
    WHERE hostname IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_workforce_devices_owner
    ON workforce_devices (tenant_id, lower(owner_email))
    WHERE owner_email IS NOT NULL;


-- Row-level security. Both tables are tenant-scoped and hold personal data,
-- so the policy is not defence in depth here, it is the control.
ALTER TABLE workforce_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE workforce_devices ENABLE ROW LEVEL SECURITY;

-- FORCE, not just ENABLE. Without it the table owner -- which is the role
-- that runs migrations -- walks straight past the policy, so a policy that
-- reads correctly protects nothing when the owner is also a reader.
ALTER TABLE workforce_members FORCE ROW LEVEL SECURITY;
ALTER TABLE workforce_devices FORCE ROW LEVEL SECURITY;

-- The `OR current_tenant_id() IS NULL` arm is the shape every table here
-- uses, and it is load-bearing rather than a loosening: the connectors
-- scheduler writes these rows on a connection that binds no tenant GUC,
-- and without the arm it would see and write zero rows while reporting
-- success. The real control for those writers is the explicit tenant
-- predicate in the statement itself -- every read and write in
-- `app/workforce.py` and `app/services/workforce_context.py` names
-- `tenant_id` -- which is the query-layer scoping this repository treats
-- as primary, with RLS as defence in depth for session-bound callers.
DROP POLICY IF EXISTS workforce_members_tenant_isolation ON workforce_members;
CREATE POLICY workforce_members_tenant_isolation ON workforce_members
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS workforce_devices_tenant_isolation ON workforce_devices;
CREATE POLICY workforce_devices_tenant_isolation ON workforce_devices
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- The runtime role is DML-only; without these grants every read and write
-- from the services fails with a permission error that reads as a missing
-- table.
GRANT SELECT, INSERT, UPDATE, DELETE ON workforce_members TO aisoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON workforce_devices TO aisoc_app;

COMMENT ON TABLE workforce_members IS
    'HR context per person, tenant-scoped: employment status, start and last-day dates, manager, department and worker type. Departures are recorded, never deleted: a terminated employee whose accounts still authenticate is the highest-signal row here.';
COMMENT ON TABLE workforce_devices IS
    'Managed device context, tenant-scoped: owner, compliance state, OS version, encryption and agent health. NULL encryption means nobody reported, which is not the same as not encrypted.';
