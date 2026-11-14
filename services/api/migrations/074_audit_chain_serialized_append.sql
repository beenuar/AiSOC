-- 074: make an audit-chain fork unrepresentable, rather than unlikely.
--
-- The defect
-- ----------
-- Appending to a hash chain is a read-modify-write on a shared head: read the
-- tenant's latest `entry_hash`, write a row whose `prev_hash` is that value.
-- Nothing made the read and the write atomic, so two writers could read the
-- same head and both append to it. Measured on `POST /alerts/{id}/explain`,
-- two milliseconds apart:
--
--     alerts:create   entry=dabf5207f866  prev=-
--     alerts.explain  entry=66eed8144cee  prev=dabf5207f866
--     alerts:create   entry=ca30ed264f98  prev=dabf5207f866   <- fork
--
-- `verify_chain` calls that broken and is right to: a fork is
-- indistinguishable from a removed row.
--
-- Why a lock alone was not the answer
-- -----------------------------------
-- A transaction-scoped advisory lock was tried and reverted. The two writers
-- were the handler's `emit_audit` and `audit_middleware`, on separate
-- sessions **within one request**, and the middleware runs before the request
-- session's dependency teardown. So the middleware waited on a transaction
-- that could not commit until the middleware returned — a genuine cycle. Its
-- acquisition timed out and its audit row was dropped, which is worse than
-- the fork: a missing audit row is undetectable, a forked one is not.
--
-- What this migration adds
-- ------------------------
-- Serialization needs somewhere to serialize *on*, and the invariant needs
-- somewhere to be enforced. Both are structural and belong in the schema:
--
--   `audit_chain_head`  one row per tenant, holding the current head hash and
--                       the next chain position. Appenders take a row lock on
--                       it, so concurrent appends for one tenant queue
--                       instead of racing. One lock per append means the
--                       protocol cannot deadlock against itself.
--
--   `chain_index`       the position the writer actually chained at, assigned
--                       under that lock. Readers order by it instead of
--                       inferring order from `created_at, id` — two rows
--                       written in the same microsecond tie-break on a random
--                       UUID, which could order a replay differently from the
--                       way the writer chained it. A gap in this sequence is
--                       also direct evidence of a deleted row, which the hash
--                       links alone only imply.
--
--   a UNIQUE index      on `(tenant_id, prev_hash)`. A fork *is* two rows
--                       claiming the same predecessor, so this makes a fork
--                       unrepresentable. This is the part that does not
--                       depend on the lock being taken, on timing, or on any
--                       application code behaving: if every other layer were
--                       removed, the second writer would get a constraint
--                       violation instead of quietly forking.
--
-- What happens to rows already written
-- ------------------------------------
-- Nothing rewrites them. Re-chaining history would mean UPDATEing an
-- append-only table so that a known-broken history reads as clean, which is
-- the integrity problem the chain exists to detect — and it would have to
-- disable the immutability trigger from migration 004 to do it.
--
-- The discontinuity is recorded instead. `chain_epoch` is 1 for every row
-- that already exists and 2 for every row the serialized writer produces, so
-- a reader can tell a fork that pre-dates this change from one that does not.
-- The unique index covers epoch 2 only, because epoch 1 already contains the
-- forks above and an index over them could not be built. Epoch 2 still chains
-- off epoch 1's head: this is a change of writer, not a new chain.
--
-- The column default stays 1 and the *writer* sets 2. Epoch 2 means "produced
-- by the serialized appender", which is a fact about the code that wrote the
-- row and not about the schema it landed in. Making it a schema default would
-- also stamp 2 onto rows written by a pre-074 replica during a rolling
-- deploy — rows the old writer chains off an audit_log scan rather than the
-- head table — and those are exactly the rows that could collide with the new
-- unique index and start failing mutations mid-deploy.

BEGIN;

-- ── The serialization point ─────────────────────────────────────────────────
--
-- `next_index` is the position the *next* append will take, so a tenant with
-- no audit rows starts at 0 and the value doubles as the count of chained
-- rows. `head_hash` NULL means the tenant has no chained row yet — genesis.
CREATE TABLE IF NOT EXISTS audit_chain_head (
    tenant_id   UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    head_hash   VARCHAR(64),
    next_index  BIGINT      NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_chain_head IS
    'One row per tenant. Appenders SELECT ... FOR UPDATE it, so concurrent '
    'audit writes for a tenant serialize instead of both reading the same '
    'head and forking the chain. Holds the head hash so an append does not '
    'have to scan audit_log to find it.';
COMMENT ON COLUMN audit_chain_head.head_hash IS
    'entry_hash of the most recently chained audit_log row for this tenant. '
    'NULL means no chained row yet.';
COMMENT ON COLUMN audit_chain_head.next_index IS
    'Position the next append will occupy, and therefore the number of rows '
    'chained so far. Monotonic; a gap in audit_log.chain_index against it is '
    'evidence of a deleted row.';

-- ── Position and epoch on the row itself ────────────────────────────────────
ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS chain_index BIGINT,
    ADD COLUMN IF NOT EXISTS chain_epoch SMALLINT NOT NULL DEFAULT 1;

COMMENT ON COLUMN audit_log.chain_index IS
    'Per-tenant chain position, assigned under the audit_chain_head row lock. '
    'Replay orders by this rather than inferring order from (created_at, id), '
    'which ties on a random UUID when two rows share a microsecond. NULL on '
    'rows written before migration 074.';
COMMENT ON COLUMN audit_log.chain_epoch IS
    '1 = written by the pre-074 unserialized writer, which could fork under '
    'concurrency. 2 = written by the serialized writer. No epoch 1 row was '
    'rewritten; the epoch records the discontinuity instead of hiding it.';

-- ── Continuity: seed the head from the history that already exists ─────────
--
-- Without this the first append for an existing tenant would read no head
-- row, conclude the tenant has no history, and write a second genesis row —
-- restarting the chain, which is exactly what a forged truncation looks like.
--
-- Which row is "the head" is ambiguous on a tenant whose chain already
-- forked: several rows are tips. This picks the same one the pre-074 writer
-- would have picked, `ORDER BY created_at DESC, id DESC`, so epoch 2
-- continues the branch the old code was already extending rather than
-- silently choosing a different one.
--
-- `next_index` starts at the number of chained rows the tenant holds. Epoch 1
-- rows have no `chain_index`, so gap detection only means anything from
-- epoch 2 onward; starting at the count keeps the position honest about how
-- many rows precede it rather than implying the chain began here.
INSERT INTO audit_chain_head (tenant_id, head_hash, next_index)
SELECT
    t.tenant_id,
    (
        SELECT a.entry_hash
        FROM audit_log a
        WHERE a.tenant_id = t.tenant_id AND a.entry_hash IS NOT NULL
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT 1
    ),
    t.chained
FROM (
    SELECT tenant_id, count(*) FILTER (WHERE entry_hash IS NOT NULL) AS chained
    FROM audit_log
    GROUP BY tenant_id
) t
ON CONFLICT (tenant_id) DO NOTHING;

-- ── The invariant ───────────────────────────────────────────────────────────
--
-- Two rows with the same (tenant_id, prev_hash) *is* a fork. COALESCE rather
-- than NULLS NOT DISTINCT so the genesis row is covered too and the index
-- does not depend on a PostgreSQL 15+ behaviour.
--
-- Scoped to epoch 2 because epoch 1 already holds forks; an unscoped index
-- could not be created on an affected deployment, and a migration that fails
-- on exactly the installations that have the defect is not a fix.
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_log_chain_successor
    ON audit_log (tenant_id, COALESCE(prev_hash, ''))
    WHERE chain_epoch >= 2 AND entry_hash IS NOT NULL;

-- Replay reads a tenant's rows in chain order; this is that read.
CREATE INDEX IF NOT EXISTS idx_audit_log_chain_index
    ON audit_log (tenant_id, chain_index)
    WHERE chain_index IS NOT NULL;

-- ── RLS + grants, matching every other tenant-scoped table ──────────────────
--
-- The `OR current_tenant_id() IS NULL` arm is what lets an unscoped
-- connection (migrations, the chain verifier) read across tenants. Without it
-- an append would silently see no head row and restart the chain, which is
-- the fork this migration exists to prevent, arriving by another door.
ALTER TABLE audit_chain_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_head FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_chain_head_tenant ON audit_chain_head;
CREATE POLICY audit_chain_head_tenant ON audit_chain_head
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES for new tables, but only for tables created
-- by the role that ran it. Granting explicitly means a chain replayed by a
-- different owner still leaves the runtime role able to append.
--
-- No DELETE. Deleting a tenant's head row would let the next append restart
-- the chain from genesis, which is precisely a forged truncation.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE ON audit_chain_head TO aisoc_app;
    END IF;
END
$$;

COMMIT;
