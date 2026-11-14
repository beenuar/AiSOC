-- Depth plan 2.4: sessions per principal.
--
-- Why this table is in Postgres and not only in the graph: ADR-0010
-- (docs/decisions/0010-entity-and-session-context-in-core.md). Neo4j measured
-- 696.8 MiB resident for 20,000 sessions, which is 42.2% of what the CORE
-- profile has left at the moment it is triaging an alert; the same rows here
-- cost +10.9 MiB in a container CORE already runs. The graph still gets the
-- Session nodes when it is enabled, written from the same ingest-side
-- projection, so `full` keeps one traversable graph and CORE keeps the
-- context on the alert.
--
-- What a row is
-- -------------
-- One session as a *vendor* understands it, or as close as the vendor lets us
-- get. `services/ingest/internal/activity/session.go` reads the key per event
-- and labels how strong it is; this table is the stateful half — start, end,
-- event count, and the walk up an assumed-role chain.
--
-- `key_kind` is stored rather than flattened away because the four kinds are
-- not interchangeable. Okta's externalSessionId is a durable session; Entra's
-- correlationId groups one sign-in flow and nothing the resulting session went
-- on to do; a derived key is principal + address + client with an idle gap. A
-- surface that renders all four as "session" is lying with a precise number,
-- so the column is NOT NULL and constrained to the producer's closed set.
--
-- `id` is deterministic — uuidv5 over (tenant, source, key) — so the lake row,
-- the graph node and this row agree on one identifier without any of the three
-- coordinating, and a Kafka replay upserts the same row instead of minting a
-- second session for events that already have one.

CREATE TABLE IF NOT EXISTS sessions (
    id                     uuid PRIMARY KEY,
    tenant_id              uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- As the vendor spells it, never a hash: an analyst pastes this into the
    -- vendor's own console, and a value that exists nowhere else cannot be
    -- looked up anywhere.
    session_key            text NOT NULL,
    key_kind               text NOT NULL,
    -- The vendor field the key was read from, so a reviewer can check the
    -- derivation against the vendor's documentation without reading Go.
    key_source             text NOT NULL DEFAULT '',
    source                 text NOT NULL,

    principal              text,
    -- The person behind the session. On a chained session this is resolved by
    -- walking `parent_session_id`, because the second hop's own events name
    -- only the role. NULL is the honest answer when nothing named a person;
    -- the role name is never read as one.
    originating_human      text,
    originating_human_source text,

    first_seen_at          timestamptz NOT NULL,
    last_seen_at           timestamptz NOT NULL,
    -- Set when the session is known to have ended: a vendor logout event, or
    -- the idle gap closing a derived session. NULL means still open *or*
    -- unknown, which are the same thing from here and are not claimed apart.
    ended_at               timestamptz,
    ended_reason           text,

    event_count            bigint NOT NULL DEFAULT 0,
    -- The strongest actor kind seen on the session's events, from the 2.2
    -- projection. A session that is sometimes a human and sometimes a token
    -- is the interesting case, so this is the maximum rather than the first.
    actor_kinds            jsonb NOT NULL DEFAULT '[]'::jsonb,
    highest_severity       text,
    source_ips             jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- The assumed-role chain. ON DELETE SET NULL rather than CASCADE: losing
    -- the parent must not delete the child's events, it must only make the
    -- chain unresolvable, which is what actually happened.
    parent_session_id      uuid REFERENCES sessions(id) ON DELETE SET NULL,
    -- How the parent edge was established, so a chain built from a
    -- caller-chosen roleSessionName is distinguishable from one built from
    -- AWS's own sourceIdentity.
    parent_link_source     text,

    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sessions_key_kind_check CHECK (
        key_kind IN ('vendor_session', 'vendor_credential', 'vendor_flow', 'derived')
    )
);

-- The upsert's conflict target. A key is only unique within its source: an
-- Okta session id and a GitHub token hash have no shared namespace, and two
-- tenants may legitimately observe the same vendor identifier.
CREATE UNIQUE INDEX IF NOT EXISTS sessions_tenant_source_key_idx
    ON sessions (tenant_id, source, session_key);

-- "What else did this person do" — the question the chain exists to answer.
CREATE INDEX IF NOT EXISTS sessions_tenant_human_idx
    ON sessions (tenant_id, originating_human, last_seen_at DESC)
    WHERE originating_human IS NOT NULL;

-- "What else did this principal do", and the idle sweep's scan.
CREATE INDEX IF NOT EXISTS sessions_tenant_principal_idx
    ON sessions (tenant_id, principal, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS sessions_open_idx
    ON sessions (tenant_id, last_seen_at)
    WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS sessions_parent_idx
    ON sessions (parent_session_id)
    WHERE parent_session_id IS NOT NULL;

COMMENT ON TABLE sessions IS
    'One session per principal, keyed by the strongest identifier the source offers. key_kind carries '
    'how strong that is and is never flattened away: a vendor session, the credential that is the '
    'session, one sign-in flow, or a derived principal+address+client grouping closed on an idle gap.';

COMMENT ON COLUMN sessions.parent_session_id IS
    'The session that issued this one, from an STS AssumeRole response. The edge exists only on the '
    'issuing call, so it is unrecoverable once that record ages out of the lake.';

-- The alert side. Additive: a stack that rolls the code back keeps running
-- against this schema, and every existing alert reads NULL, which renders as
-- "no session context" rather than as a fabricated one.
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS session_id uuid REFERENCES sessions(id) ON DELETE SET NULL;

-- Denormalized onto the alert deliberately. The queue renders thousands of
-- rows and the strength of the grouping changes what the row is allowed to
-- say; a join per row to learn it would make the honest rendering the
-- expensive one.
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS session_key_kind text;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS originating_human text;

CREATE INDEX IF NOT EXISTS alerts_session_idx
    ON alerts (tenant_id, session_id)
    WHERE session_id IS NOT NULL;

-- Written out rather than looped with `format()`: the loop was shorter and it
-- made the policy invisible to `grep` and to
-- `scripts/check_tenant_query_predicates.py`, which reads migrations to learn
-- which tables carry one. A control a tool cannot see is a control nobody can
-- audit.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE sessions ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE sessions FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON sessions';
    EXECUTE
        'CREATE POLICY tenant_isolation ON sessions '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO aisoc_app';
    END IF;
END
$$;
