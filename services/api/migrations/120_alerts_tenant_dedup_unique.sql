-- 120_alerts_tenant_dedup_unique.sql
--
-- Make the database enforce what the Fusion alert sink already intends:
-- one visible alert per (tenant_id, dedup_hash).
--
-- Why this exists
-- ───────────────
-- ``alert_sink._INSERT_SQL`` deduplicates with
--
--     WHERE NOT EXISTS (
--         SELECT 1 FROM alerts WHERE tenant_id = $2 AND dedup_hash = $11
--     )
--
-- That check and the INSERT are two statements. Under READ COMMITTED two
-- workers can both run the check before either inserts, both see no row, and
-- both insert. They only avoided that for the canonical Fusion path because
-- ``RawAlert.deterministic_id()`` gives both writers the same primary key, so
-- the second INSERT hits ``ON CONFLICT (id) DO NOTHING``. The sink's contract
-- is not "callers must supply a deterministic id": any writer that supplies a
-- different id for the same tenant and fingerprint — a replay after an id
-- algorithm change, a future batch producer, a direct write — can persist a
-- second visible alert.
--
-- The non-unique ``idx_alerts_dedup`` from 001_init.sql cannot prevent that.
-- This partial unique index is the authoritative guarantee, scoped per tenant
-- exactly like the lookup it backs. Rows with a NULL dedup_hash (manual
-- alerts, connector paths that do not use the fingerprint) are outside the
-- predicate and keep their current behaviour.
--
-- The sink handles the resulting conflict explicitly: migration 120 makes the
-- loser of the race raise ``UniqueViolationError`` on constraint
-- ``uq_alerts_tenant_dedup``, and ``AlertSink._persist_on_conn`` resolves it
-- to the winner's row instead of writing a second alert.
--
-- Precondition: no existing duplicate pairs
-- ──────────────────────────────────────────
-- ``CREATE UNIQUE INDEX`` fails if the table already contains duplicates.
-- This migration checks first and raises a diagnostic naming the offending
-- pairs. It deliberately does not delete, merge, or rewrite any alert: which
-- of two analyst-visible rows survives is an operator decision, and a
-- migration that silently picks one would destroy evidence.
--
-- Find the blockers before deploying with:
--
--     SELECT tenant_id, dedup_hash, count(*) AS rows,
--            min(created_at) AS first_seen, max(created_at) AS last_seen
--       FROM alerts
--      WHERE dedup_hash IS NOT NULL
--      GROUP BY tenant_id, dedup_hash
--     HAVING count(*) > 1
--      ORDER BY count(*) DESC;
--
-- Resolve them deliberately, then re-run the migration chain. Until this file
-- succeeds it is not recorded in ``aisoc_schema_migrations`` and the old
-- non-unique behaviour remains, so a failed run is safe but incomplete.
--
-- Rollout notes
-- ─────────────
-- The index is built inside this file's transaction. PostgreSQL takes a
-- SHARE lock on ``alerts`` while it builds, which blocks writes but not reads;
-- on a large table schedule the deploy accordingly. An operator who cannot
-- take that lock can build the index out of band with
-- ``CREATE UNIQUE INDEX CONCURRENTLY uq_alerts_tenant_dedup ...`` first; the
-- ``IF NOT EXISTS`` below then treats it as already done. Do not use
-- CONCURRENTLY inside this file: the runner sends the whole script as one
-- simple-query batch, and a failed concurrent build would leave an invalid
-- index that ``IF NOT EXISTS`` would later mistake for a valid one.
--
-- Runner behaviour (operational requirement)
-- ──────────────────────────────────────────
-- ``run_migrations.py`` logs a failed migration, rolls it back, continues with
-- the remaining files, and exits 0 unless ``AISOC_MIGRATIONS_STRICT=1`` (also
-- accepted: true/yes/on). A non-strict run therefore looks successful while
-- this index is absent and the sink's cross-writer race is still open.
--
-- Set ``AISOC_MIGRATIONS_STRICT=1`` for this deploy. The failure is never
-- recorded in ``aisoc_schema_migrations`` either way, so the file is retried
-- on the next run; strict mode is what stops the release from proceeding with
-- the guarantee missing.
--
-- Deploy ordering
-- ───────────────
-- The index can be applied before the Fusion sink change, but an old sink
-- treats the resulting UniqueViolationError as a permanent constraint failure
-- and dead-letters the losing event. The alert itself is not lost (the winner
-- row exists), but the DLQ entry is spurious. Deploy the sink change first, or
-- both together, to avoid that window.
--
-- Rollback: DROP INDEX IF EXISTS uq_alerts_tenant_dedup;
-- The non-unique ``idx_alerts_dedup`` from 001_init.sql is unaffected.

BEGIN;

DO $$
DECLARE
    duplicate_pairs bigint;
    sample text;
    index_is_invalid boolean;
BEGIN
    -- A failed CREATE INDEX CONCURRENTLY leaves an invalid index behind, and
    -- ``IF NOT EXISTS`` below would then treat it as a valid guarantee. Fail
    -- loudly instead: the operator must drop the invalid index and re-run.
    SELECT NOT i.indisvalid
      INTO index_is_invalid
      FROM pg_index i
      JOIN pg_class c ON c.oid = i.indexrelid
     WHERE i.indrelid = 'alerts'::regclass
       AND c.relname = 'uq_alerts_tenant_dedup';

    IF index_is_invalid THEN
        RAISE EXCEPTION
            'index uq_alerts_tenant_dedup exists but is invalid (a failed CREATE INDEX CONCURRENTLY leaves this state). DROP INDEX uq_alerts_tenant_dedup and re-run. No rows were changed.';
    END IF;

    SELECT count(*)
      INTO duplicate_pairs
      FROM (
          SELECT 1
            FROM alerts
           WHERE dedup_hash IS NOT NULL
           GROUP BY tenant_id, dedup_hash
          HAVING count(*) > 1
      ) AS duplicates;

    IF duplicate_pairs > 0 THEN
        SELECT string_agg(
                   format('%s / %s (%s rows)', tenant_id, dedup_hash, row_count),
                   '; '
                   ORDER BY row_count DESC
               )
          INTO sample
          FROM (
              SELECT tenant_id, dedup_hash, count(*) AS row_count
                FROM alerts
               WHERE dedup_hash IS NOT NULL
               GROUP BY tenant_id, dedup_hash
              HAVING count(*) > 1
               ORDER BY count(*) DESC
               LIMIT 5
          ) AS duplicates;

        RAISE EXCEPTION
            'alerts has % duplicate (tenant_id, dedup_hash) pair(s); refusing to create uq_alerts_tenant_dedup. Sample: %. Resolve the duplicates deliberately (merge or delete) and re-run. No rows were changed.',
            duplicate_pairs,
            sample;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_tenant_dedup
    ON alerts (tenant_id, dedup_hash)
    WHERE dedup_hash IS NOT NULL;

COMMIT;
