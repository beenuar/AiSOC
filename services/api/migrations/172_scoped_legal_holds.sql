-- WS2.4 — legal holds scoped in time, so a hold exempts ONLY its own rows.
--
-- What was deferred, in the purge worker's own words: "the subject of a
-- bulk tenant purge is the tenant. Every live hold in this tenant matches
-- it, which is the fail-closed reading" — any single live hold froze the
-- ENTIRE tenant's purge, over-retaining everything to avoid under-retaining
-- anything. Subject scoping already exists (`subject_kind`/`subject_value`
-- is a predicate precisely so a hold keeps covering rows that arrive after
-- it is placed); what was missing is the TIME dimension and a purge that
-- subtracts held rows instead of aborting.
--
-- Two columns, both nullable because an open-ended hold is legitimate:
--   * `covers_from` — the hold covers records whose event time is on or
--     after this instant (null: since the beginning).
--   * `covers_until` — ... on or before this instant (null: indefinitely).
--
-- The narrowing itself lands in `app/services/retention.py` /
-- `workers/retention_purge.py`: the alerts purge subtracts rows matched by
-- a live hold's subject predicate within its window, and tenant-wide holds
-- (`subject_kind = 'tenant'`) keep the old whole-tenant freeze, because
-- that is what a tenant-wide hold MEANS. The lake TTL ceiling is untouched
-- and untouchable — a hold older than `MAX_LAKE_DAYS` is only satisfiable
-- through the archive tier (WS2.1), and the attestation says so.

-- lane allocation: migration 172 (WS2)

ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS covers_from  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS covers_until TIMESTAMPTZ;

-- An inverted window would silently cover nothing; refuse it at write time.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'legal_holds_window_sane'
    ) THEN
        ALTER TABLE legal_holds
            ADD CONSTRAINT legal_holds_window_sane
            CHECK (covers_from IS NULL OR covers_until IS NULL OR covers_from <= covers_until);
    END IF;
END $$;

COMMENT ON COLUMN legal_holds.covers_from IS
    'The hold covers records with event time >= this (null: from the beginning).';
COMMENT ON COLUMN legal_holds.covers_until IS
    'The hold covers records with event time <= this (null: indefinitely).';

-- Rollback
-- ────────
--     ALTER TABLE legal_holds
--         DROP CONSTRAINT IF EXISTS legal_holds_window_sane,
--         DROP COLUMN IF EXISTS covers_from,
--         DROP COLUMN IF EXISTS covers_until;
--
-- Dropping the columns returns every hold to "covers all time", which
-- over-retains — the recoverable direction.
