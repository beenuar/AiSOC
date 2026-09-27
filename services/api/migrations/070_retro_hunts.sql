-- 070: intel-driven retro-hunts — who opted in, what was already swept, and
-- how much budget is left.
--
-- Gap-closure Phase 8.1.
--
-- A retro-hunt is somebody else's intelligence pointed at a customer's own
-- past, on a schedule the customer did not choose. Two of the three tables
-- below exist because that shape is expensive and noisy by default, and the
-- third exists because it is also a disclosure.
--
-- Why opt-in is a row rather than a deployment setting
-- -----------------------------------------------------
-- Sweeping a tenant's thirty-day history every time a public feed publishes
-- an indicator is a real cost against their warehouse, and on a metered SIEM
-- licence it is a real bill. A deployment-wide switch would make one
-- operator's answer everybody's. `enabled` defaults to FALSE, so a tenant
-- that has never been asked is never swept, which is the standing rule for
-- anything that calls out or changes state.
--
-- Why the dedup ledger is a table and not a cache
-- ------------------------------------------------
-- The thing this phase most has to avoid is one indicator opening a thousand
-- alerts. Two independent mechanisms stop that, and they stop different
-- halves of it. The sweep query is an aggregate, so a million matching events
-- produce one result; that handles breadth. `retro_hunt_sightings` handles
-- time: its UNIQUE constraint means the same indicator seen again on a later
-- sweep updates a row rather than opening a second alert, so a feed that
-- republishes an indicator daily does not produce a daily alert. A cache
-- would lose that on restart and the first sweep after a deploy would
-- re-alert on everything already known.
--
-- Why the budget counters live on the settings row
-- -------------------------------------------------
-- The lake API's rate limiter is an in-memory token bucket, documented as a
-- soft per-process limit. That is right for an interactive surface where the
-- hard caps live downstream in ClickHouse. It is wrong here: sweeps arrive
-- from a queue rather than from a person, and an API restart would hand a
-- backlog a fresh full bucket. Counters on a row survive restarts and are
-- shared across replicas, which is what "budget" has to mean when the work is
-- unattended.

-- 1. Per-tenant opt-in and budget -------------------------------------------

CREATE TABLE IF NOT EXISTS retro_hunt_settings (
    tenant_id          UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    -- Off until a tenant asks. See above.
    enabled            BOOLEAN     NOT NULL DEFAULT FALSE,

    -- How far back a sweep looks. Bounded in the column so no settings row
    -- can express "scan everything"; the service clamps to the same ceiling.
    lookback_days      INTEGER     NOT NULL DEFAULT 30
                                   CHECK (lookback_days BETWEEN 1 AND 365),

    -- Whether to go beyond AiSOC's own lake into the tenant's connected
    -- SIEMs. Separate from `enabled` because it is a separate cost: a lake
    -- sweep is free to the customer and a SIEM sweep may not be.
    include_federated  BOOLEAN     NOT NULL DEFAULT TRUE,

    -- The budget. Both are per-tenant and both are enforced before a sweep
    -- runs, not after, so an exhausted budget costs nothing.
    max_sweeps_per_hour INTEGER    NOT NULL DEFAULT 120
                                   CHECK (max_sweeps_per_hour BETWEEN 0 AND 10000),
    max_sweeps_per_day  INTEGER    NOT NULL DEFAULT 1000
                                   CHECK (max_sweeps_per_day BETWEEN 0 AND 100000),

    -- Rolling-window counters. `*_started_at` is the window anchor; the
    -- service resets the counter when the anchor is older than the window
    -- rather than running a cron to zero them.
    sweeps_this_hour   INTEGER     NOT NULL DEFAULT 0 CHECK (sweeps_this_hour >= 0),
    hour_started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sweeps_today       INTEGER     NOT NULL DEFAULT 0 CHECK (sweeps_today >= 0),
    day_started_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Observability for the operator, not for billing: how many indicators
    -- were dropped because the budget was spent. A silently discarded sweep
    -- is indistinguishable from an indicator nobody published.
    sweeps_skipped_budget BIGINT   NOT NULL DEFAULT 0 CHECK (sweeps_skipped_budget >= 0),

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE retro_hunt_settings IS
    'Per-tenant opt-in and budget for intel-driven retro-hunts. Disabled by '
    'default: a sweep costs the customer warehouse time and, where it reaches '
    'a connected SIEM, possibly money.';
COMMENT ON COLUMN retro_hunt_settings.sweeps_skipped_budget IS
    'Sweeps dropped because the hourly or daily budget was spent. Counted so '
    'an operator can tell a quiet feed from an exhausted budget.';

-- 2. Dedup ledger and provenance --------------------------------------------

CREATE TABLE IF NOT EXISTS retro_hunt_sightings (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The indicator, in the Phase 4 vocabulary
    -- (`app.services.agent_tools.indicators.INDICATOR_TYPES`) so an agent
    -- tool, a federated search and a retro-hunt all name types the same way.
    indicator_type     TEXT        NOT NULL,
    indicator_value    TEXT        NOT NULL,

    -- Provenance, which the plan requires an alert to carry: which feed
    -- published this, and when that feed first saw it. Kept beside the
    -- sighting rather than only in the alert body so a later sweep can
    -- report "known since" without re-reading an alert.
    feed_source        TEXT        NOT NULL,
    intel_first_seen_at TIMESTAMPTZ,

    -- Where it matched, and when, in the tenant's own data.
    first_matched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_matched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_sighting_at  TIMESTAMPTZ,
    last_sighting_at   TIMESTAMPTZ,
    sightings          BIGINT      NOT NULL DEFAULT 0 CHECK (sightings >= 0),
    matched_surfaces   JSONB       NOT NULL DEFAULT '[]'::jsonb,

    -- The alert this sighting opened. Nullable because a sweep that matched
    -- while the alert insert failed must still be recorded: losing the
    -- sighting would re-alert on the next sweep.
    alert_id           UUID,

    -- How many times a later sweep found this same indicator again. The
    -- counter is the evidence that dedup is doing something, and it is what
    -- the gate asserts moves rather than the alert count.
    times_seen         INTEGER     NOT NULL DEFAULT 1 CHECK (times_seen >= 1),

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The whole dedup mechanism. One row per (tenant, indicator), so a feed
    -- republishing an indicator every day cannot open an alert every day.
    CONSTRAINT retro_hunt_sightings_unique UNIQUE (tenant_id, indicator_type, indicator_value)
);

COMMENT ON TABLE retro_hunt_sightings IS
    'One row per (tenant, indicator) that a retro-hunt matched. The UNIQUE '
    'constraint is the dedup: a republished indicator updates this row '
    'instead of opening a second alert.';
COMMENT ON COLUMN retro_hunt_sightings.matched_surfaces IS
    'Where the indicator matched: lake columns, connector types, and which '
    'federated SIEM sources answered. Carried into the alert as provenance.';
COMMENT ON COLUMN retro_hunt_sightings.intel_first_seen_at IS
    'When the publishing feed first saw the indicator, which is a different '
    'fact from when the tenant first saw it (first_sighting_at). Both are '
    'kept because an indicator published today and seen here last month is a '
    'different finding from one published and seen today.';

CREATE INDEX IF NOT EXISTS idx_retro_hunt_sightings_tenant
    ON retro_hunt_sightings (tenant_id, last_matched_at DESC);

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) reach these
-- tables; dropping it makes those silently see nothing. FORCE so the table
-- owner, which is the role that runs migrations, does not walk past it.
ALTER TABLE retro_hunt_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE retro_hunt_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS retro_hunt_settings_tenant ON retro_hunt_settings;
CREATE POLICY retro_hunt_settings_tenant ON retro_hunt_settings
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE retro_hunt_sightings ENABLE ROW LEVEL SECURITY;
ALTER TABLE retro_hunt_sightings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS retro_hunt_sightings_tenant ON retro_hunt_sightings;
CREATE POLICY retro_hunt_sightings_tenant ON retro_hunt_sightings
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON retro_hunt_settings TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON retro_hunt_sightings TO aisoc_app;
    END IF;
END
$$;
