-- shifts and handoffs, from real rows this time.
--
-- The previous shifts.py served three invented shifts from a module-level
-- list with no tenant filter, and was deleted rather than rebuilt, with a
-- test pinning its absence ("a route with no caller serving data nobody
-- entered is not a feature with a bug"). This is the rebuild that pin
-- invited: tenant-scoped shift definitions, and handoffs GENERATED from
-- the tenant's real open alerts, cases, pending approvals and running
-- investigations at shift end — never typed in, never invented.
--
-- Time is stored as minutes-of-day in a named IANA timezone, because a
-- shift is a local-clock fact ("06:00–18:00 in Europe/Berlin") that must
-- survive DST; the generator resolves it to instants per occurrence.

-- lane allocation: migration 173

CREATE TABLE IF NOT EXISTS soc_shifts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    timezone        TEXT        NOT NULL DEFAULT 'UTC',
    -- Local wall-clock minutes. An overnight shift has end < start.
    start_minute    INTEGER     NOT NULL CHECK (start_minute BETWEEN 0 AND 1439),
    end_minute      INTEGER     NOT NULL CHECK (end_minute BETWEEN 0 AND 1439),
    -- ISO weekday numbers (1=Monday … 7=Sunday) this shift runs on.
    weekdays        INTEGER[]   NOT NULL DEFAULT '{1,2,3,4,5,6,7}',
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT soc_shifts_name_per_tenant UNIQUE (tenant_id, name)
);

COMMENT ON TABLE soc_shifts IS
    'Tenant shift definitions. Local wall-clock minutes in a named '
    'IANA timezone; the handoff generator resolves occurrences to instants.';

CREATE TABLE IF NOT EXISTS shift_handoffs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    shift_id        UUID        NOT NULL REFERENCES soc_shifts(id) ON DELETE CASCADE,
    -- The shift occurrence this handoff closes, as instants.
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    -- The snapshot, generated from the tenant's real rows at generation
    -- time: open alerts by severity, open/attention cases, pending
    -- approvals, running investigations. Counts carry their queries'
    -- provenance; a section whose store could not answer says so.
    snapshot        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- The outgoing shift's free-text notes — the one human-authored field.
    notes           TEXT        NOT NULL DEFAULT '',
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by    UUID        REFERENCES users(id) ON DELETE SET NULL,
    acked_by        UUID        REFERENCES users(id) ON DELETE SET NULL,
    acked_at        TIMESTAMPTZ,

    CONSTRAINT shift_handoffs_window_sane CHECK (window_start < window_end),
    -- One handoff per shift occurrence; regeneration replaces.
    CONSTRAINT shift_handoffs_one_per_occurrence UNIQUE (tenant_id, shift_id, window_start)
);

COMMENT ON TABLE shift_handoffs IS
    'Shift handoffs, generated from the tenant''s real open work at '
    'shift end and acknowledged by the incoming shift.';

CREATE INDEX IF NOT EXISTS idx_shift_handoffs_tenant
    ON shift_handoffs (tenant_id, window_end DESC);

-- RLS (154 shape): API writes under the bound GUC; the generator worker
-- sweeps every tenant under none.
ALTER TABLE soc_shifts ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_shifts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soc_shifts_tenant ON soc_shifts;
CREATE POLICY soc_shifts_tenant ON soc_shifts
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE shift_handoffs ENABLE ROW LEVEL SECURITY;
ALTER TABLE shift_handoffs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS shift_handoffs_tenant ON shift_handoffs;
CREATE POLICY shift_handoffs_tenant ON shift_handoffs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON soc_shifts TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON shift_handoffs TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS shift_handoffs;
--     DROP TABLE IF EXISTS soc_shifts;
