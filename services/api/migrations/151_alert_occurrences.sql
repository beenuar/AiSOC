-- Wave 2, Phase 3.3 — a repeated vendor finding is one alert that says 79.
--
-- What the pipeline does with a repeat today, and what it keeps
-- -------------------------------------------------------------
-- Same-fingerprint repeats are collapsed by three independent layers: a
-- 300 s Redis check in `Deduplicator`, a `WHERE NOT EXISTS` on the alert
-- insert, and `uq_alerts_tenant_dedup` from migration 120 behind both. All
-- three work, and none of them keeps the repeat.
--
-- The only trace a folded event leaves is an append to the surviving alert's
-- `source_event_ids`. That column answers "did more than one event produce
-- this?" and it cannot be asked for more:
--
--   * it grows on multi-event correlation as well as on repeats, so its
--     length is not a repeat count;
--   * it is capped at 200 and then silently stops, so 200 repeats and 5,000
--     repeats are indistinguishable;
--   * `alerts.first_seen` and `alerts.last_seen` have existed since
--     `001_init.sql` and fusion has never written either, so the window the
--     repeats span is recorded nowhere at all.
--
-- A rollup, not a row per occurrence
-- ----------------------------------
-- One row per occurrence is unbounded by construction, and "one indicator, a
-- thousand rows" is the exact shape the retro-hunt sweep is built to refuse
-- (`services/api/app/services/retro_hunt/sweep.py`). The same reasoning
-- applies to a noisy vendor: the answer an analyst wants is a number and a
-- window, not five thousand rows to page through. So this is a rollup keyed
-- `(tenant_id, alert_id)` holding an exact count, the real window, and a
-- bounded window of the original payload ids.
--
-- `occurrence_count` counts the surviving alert as occurrence 1. A row is
-- created on the first fold with the count already at 2, which is why there
-- is no row at all for an alert that has never repeated: absent means one,
-- and a reader that joins must `COALESCE(occurrence_count, 1)`.
--
-- Why the payload-id window keeps the NEWEST ids
-- ----------------------------------------------
-- The redelivery guard is a jsonb containment test against the ids this row
-- still holds, so the window decides what the guard can see. A Kafka
-- consumer-group rebalance redelivers *recent* messages; keeping the oldest
-- 200 ids would put the guard's coverage precisely where redelivery never
-- happens. The window therefore evicts from the front, and
-- `payload_ids_complete` goes false the moment it does, so no reader is told
-- a partial list is the whole set.
--
-- The honest limit, stated rather than hidden: a redelivery of an event that
-- has already been evicted from the window would be counted twice. Kafka
-- redelivery is bounded by the consumer's session timeout and is always
-- recent, so that case needs 200 distinct repeats of one fingerprint to
-- arrive between a message and its own redelivery.

CREATE TABLE IF NOT EXISTS alert_occurrences (
    tenant_id             UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Cascades with the alert: an occurrence record whose alert has been
    -- erased is not evidence of anything, and ADR-0014's tenant-erasure path
    -- walks foreign keys rather than a hand-maintained table list.
    alert_id              UUID        NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    occurrence_count      BIGINT      NOT NULL DEFAULT 2 CHECK (occurrence_count >= 2),
    first_seen            TIMESTAMPTZ NOT NULL,
    last_seen             TIMESTAMPTZ NOT NULL,
    payload_ids           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- FALSE once the window has evicted an id. A reader showing the list must
    -- say "most recent N of M" rather than presenting it as the full set.
    payload_ids_complete  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, alert_id)
);

COMMENT ON TABLE alert_occurrences IS
    'Phase 3.3 — repeats of one alert fingerprint, kept as a linked rollup '
    'rather than discarded. occurrence_count includes the surviving alert, '
    'so no row means exactly one sighting.';
COMMENT ON COLUMN alert_occurrences.payload_ids IS
    'The most recent original payload ids, newest last. Bounded; see '
    'payload_ids_complete.';
COMMENT ON COLUMN alert_occurrences.payload_ids_complete IS
    'FALSE once the bounded window has evicted an id, so a partial list is '
    'never presented as the complete set.';

-- The read an alert page makes: one row by alert, already covered by the
-- primary key. This index serves the other direction — "the noisiest
-- findings in this tenant" — which is the question that makes the feature
-- worth having.
CREATE INDEX IF NOT EXISTS idx_alert_occurrences_tenant_count
    ON alert_occurrences (tenant_id, occurrence_count DESC);

-- RLS, matching `alerts` exactly — and the reason is worth writing down,
-- because the obvious stricter policy makes this table unwritable.
--
-- The first cut of this migration carried the usual pairing: the `IS NULL`
-- arm in `USING` only, and a bare `WITH CHECK (tenant_id =
-- current_tenant_id())`. That is correct for a table written through a
-- request-scoped API session, which binds `app.current_tenant_id` before it
-- writes. **Fusion binds no such GUC.** It is a Kafka consumer, it holds no
-- request and no tenant session, and it writes rows for whichever tenant the
-- event belonged to. Under the stricter policy its insert evaluates
-- `tenant_id = NULL`, which is NULL and therefore not true, and the write is
-- refused:
--
--     ERROR:  new row violates row-level security policy for table "alert_occurrences"
--
-- Measured as `aisoc_app` (NOBYPASSRLS) on a live database with every
-- migration applied: the identical session inserts into `alerts` and is
-- refused here. The failure would have been invisible in production, because
-- `_record_deduplicated_event` is deliberately best-effort — the exception is
-- logged at warning and the alert verdict stands — so every occurrence row
-- would simply never appear and the feature would read as "this vendor never
-- repeats" rather than as an error. That is migration 123's defect exactly:
-- a correct-looking policy over a row nothing can write.
--
-- So the policy below mirrors `alerts_tenant` from `002_rls.sql`, which has
-- no `WITH CHECK` at all and therefore applies its `USING` expression —
-- including the `IS NULL` arm — to writes as well. Two further reasons this
-- is the right posture rather than a weakening: this table is strictly less
-- sensitive than the alert it hangs off, carrying a count and a window and
-- no event content; and the foreign key means a row can only be written for
-- an alert that already exists, so an unbound writer cannot invent a tenant's
-- data, only annotate a row that is already there. A policy stricter than the
-- parent table's buys nothing and costs the whole feature.
ALTER TABLE alert_occurrences ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_occurrences FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON alert_occurrences;
CREATE POLICY tenant_isolation ON alert_occurrences
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON alert_occurrences TO aisoc_app';
    END IF;
END $$;

-- The noisiest findings in a tenant, which is the report this table exists
-- to make answerable:
--
--     SELECT a.title, o.occurrence_count, o.first_seen, o.last_seen
--       FROM alert_occurrences o
--       JOIN alerts a ON a.id = o.alert_id AND a.tenant_id = o.tenant_id
--      WHERE o.tenant_id = '<tenant-uuid>'::uuid
--      ORDER BY o.occurrence_count DESC
--      LIMIT 20;
--
-- Rollback
-- ────────
--     DROP TABLE IF EXISTS alert_occurrences;
--
-- Nothing else changes: the collapse itself predates this table and is
-- unaffected by it. Dropping this loses the counts and returns the pipeline
-- to discarding repeats, which is the pre-3.3 behaviour.
