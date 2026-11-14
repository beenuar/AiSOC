-- Depth plan 4.5 / parity 6.8 — leader election for the connector scheduler.
--
-- The problem
-- -----------
-- `ConnectorScheduler` adds one APScheduler job per enabled connector
-- instance, in process. Two replicas therefore each run every job: every
-- vendor is polled twice on every cycle, every page of results is fetched
-- twice, and the duplicate events are deduplicated downstream at best. On
-- a rate-limited vendor API it is worse than duplication — the second
-- replica's poll is what gets 429'd, and a connector that is being
-- throttled looks identical to one whose credentials have expired.
--
-- That is why the Helm chart pins `connectors` to one replica. A
-- deployment that scales it for availability silently doubles its vendor
-- call volume, which is the kind of change nobody attributes to a replica
-- count.
--
-- Why a Postgres lease rather than the Kubernetes Lease API
-- ---------------------------------------------------------
-- Because the scheduler also runs under Docker Compose, under `make up`,
-- and in a plain systemd unit, and a leader election that only works on
-- Kubernetes is a leader election that is off wherever most first runs
-- happen. Every deployment of this service already has Postgres; not
-- every one has an API server or the RBAC to write a coordination object
-- in its own namespace.
--
-- The shape
-- ---------
-- One row per scope. A holder renews it; a challenger may take it only
-- once `expires_at` has passed. `UPDATE ... WHERE expires_at < now()` is
-- the whole mechanism: Postgres takes a row lock, so a second challenger
-- blocks and then re-evaluates the predicate against the committed row,
-- finds a fresh expiry and matches nothing. A SELECT-then-UPDATE has no
-- such re-evaluation and elects two leaders.
--
-- `fenced_at` is not used for mutual exclusion and is not a substitute
-- for it. It is the monotonically increasing term number, recorded so a
-- log can answer "which generation of the leader wrote this" after a
-- network partition — the question an election without one cannot answer
-- at all.

CREATE TABLE IF NOT EXISTS scheduler_leases (
    -- What is being led. One row per scope rather than one global row, so
    -- a future second scheduler does not contend with this one.
    scope           TEXT PRIMARY KEY,
    -- Who holds it. A hostname or pod name; carried for the log, never
    -- compared for correctness except by the holder renewing its own.
    holder          TEXT NOT NULL,
    -- The term. Incremented on every acquisition, never on a renewal.
    fenced_at       BIGINT NOT NULL DEFAULT 1,
    acquired_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    renewed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The only thing that decides whether a challenger may take over.
    expires_at      TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE scheduler_leases IS
    'Leader election for in-process schedulers. A Postgres lease rather than a Kubernetes Lease '
    'because the scheduler also runs under Compose and systemd, and an election that only works '
    'on Kubernetes is off wherever most first runs happen.';

COMMENT ON COLUMN scheduler_leases.fenced_at IS
    'Term number, incremented on acquisition and not on renewal. Not used for mutual exclusion '
    'and not a substitute for it: it exists so a log can say which generation of the leader '
    'wrote a line after a partition.';

-- Deliberately **not** tenant-scoped and deliberately without RLS.
--
-- A scheduler lease is infrastructure coordination between replicas of
-- one deployment, not tenant data: it holds a hostname and two
-- timestamps. Adding a tenant_id would be inventing a dimension the thing
-- does not have, and a tenant-scoped RLS policy on a table the scheduler
-- reads before it has resolved any tenant would make the election fail
-- closed on every boot.
--
-- Stated here rather than left as an absence, because
-- scripts/check_tenant_query_predicates.py reads migrations to learn
-- which tables carry a policy, and a table with none and no reason looks
-- like an oversight.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON scheduler_leases TO aisoc_app';
    END IF;
END
$$;
