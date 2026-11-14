-- 103: versioned posture snapshots (depth plan 2.5).
--
-- Why a table and not a cache
-- ---------------------------
-- The resolver in `services/api/app/services/effective_permissions/` is pure:
-- it takes a snapshot and computes what a principal can do. Until now the
-- only production snapshot source returned `{}`, so every live call 412'd and
-- the whole subsystem had never answered a question about a real estate.
--
-- Collecting one is half the job. The other half is *when* it was true. An
-- alert is triaged minutes to days after the event, and the question an
-- analyst asks is "what could this identity do **at the time it acted**" --
-- not what it can do now, after someone revoked the role. A single mutable
-- "current posture" row answers the second question while appearing to answer
-- the first, which is the worse failure of the two because the number looks
-- right.
--
-- So snapshots are versioned and closed rather than overwritten:
-- `valid_until IS NULL` is the live one, and a lookup at an event timestamp
-- selects the row whose interval contains it.
--
-- Spelling
-- --------
-- `valid_from` / `valid_until`, matching `identity_edges` in migration 018 --
-- the one existing table in this database that bounds a fact in time. The
-- depth plan says `valid_to`; adopting it would put two spellings of one
-- concept in one schema, so the existing one wins and the deviation is
-- recorded in DEPTH_PROGRESS.md rather than made silently.

CREATE TABLE IF NOT EXISTS posture_snapshots (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL,

    -- The identity provider the snapshot describes, not the connector that
    -- fetched it: two connectors may both be able to read AWS IAM, and a
    -- resolver asks for a provider.
    provider            text NOT NULL,
    -- Which connector actually produced it, so an operator can tell a stale
    -- snapshot's source without reading the blob.
    connector_id        text NOT NULL,
    connector_instance_id uuid,

    snapshot            jsonb NOT NULL,

    -- sha256 over the canonical form of `snapshot`. A collector that runs
    -- every hour against an estate nobody changed would otherwise write a new
    -- version every hour, and "when did this posture last change" -- the
    -- question a drift reviewer asks -- would be unanswerable because every
    -- row is a change. An unchanged collection extends the live row instead.
    content_hash        text NOT NULL,

    -- Counted at write time from the snapshot the collector returned, so a
    -- reader can see an empty or truncated collection without parsing jsonb.
    -- A snapshot that collected nothing is a real and important state: it
    -- means the credential lost its read permission, not that the estate is
    -- empty.
    principal_count     integer NOT NULL DEFAULT 0,
    resource_count      integer NOT NULL DEFAULT 0,
    policy_count        integer NOT NULL DEFAULT 0,

    -- What the collector could not see. Carried as data rather than logged,
    -- because the resolver's answer is only as complete as its input and the
    -- triage surface has to be able to say so.
    partial             boolean NOT NULL DEFAULT false,
    collection_notes    jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- When the collector finished reading the provider. Distinct from
    -- valid_from, which is when this *version* became the one in force --
    -- they differ on a re-collection that found no change.
    collected_at        timestamptz NOT NULL DEFAULT now(),
    collection_ms       integer,

    valid_from          timestamptz NOT NULL DEFAULT now(),
    -- NULL means in force. Set when a later version supersedes it.
    valid_until         timestamptz,

    created_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT posture_snapshots_provider_check CHECK (
        provider IN ('aws', 'azure', 'gcp', 'gws', 'github', 'okta')
    ),
    -- An interval that ends before it starts would silently match nothing,
    -- and a lookup returning no snapshot is indistinguishable from a tenant
    -- that never collected one.
    CONSTRAINT posture_snapshots_interval_check CHECK (
        valid_until IS NULL OR valid_until >= valid_from
    )
);

-- At most one live version per provider per tenant. This is the invariant the
-- whole table rests on: two rows with `valid_until IS NULL` make "the current
-- posture" ambiguous, and the resolver would pick whichever the planner
-- returned first. A partial unique index refuses it in the database rather
-- than trusting every writer to close the old row first.
CREATE UNIQUE INDEX IF NOT EXISTS posture_snapshots_live_idx
    ON posture_snapshots (tenant_id, provider)
    WHERE valid_until IS NULL;

-- The point-in-time lookup: newest version whose interval contains an event
-- timestamp.
CREATE INDEX IF NOT EXISTS posture_snapshots_at_idx
    ON posture_snapshots (tenant_id, provider, valid_from DESC);

-- "Has this estate's posture changed since we last looked", without reading
-- the blob.
CREATE INDEX IF NOT EXISTS posture_snapshots_hash_idx
    ON posture_snapshots (tenant_id, provider, content_hash);

COMMENT ON TABLE posture_snapshots IS
    'Versioned identity-posture snapshots per provider. valid_until IS NULL is the version in force; '
    'a lookup at an event timestamp selects the version that was in force when the event happened, '
    'because what an identity can do now is a different question from what it could do when it acted.';

COMMENT ON COLUMN posture_snapshots.content_hash IS
    'sha256 of the canonical snapshot. An unchanged re-collection extends the live row rather than '
    'writing a new version, so every row in the history is a real posture change.';

COMMENT ON COLUMN posture_snapshots.partial IS
    'True when the collector could not read part of the estate. The resolver answer is only as '
    'complete as its input, and a surface that cannot say so will present a gap as an absence.';

DO $$
BEGIN
    EXECUTE 'ALTER TABLE posture_snapshots ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE posture_snapshots FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON posture_snapshots';
    EXECUTE
        'CREATE POLICY tenant_isolation ON posture_snapshots '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON posture_snapshots TO aisoc_app';
    END IF;
END
$$;
