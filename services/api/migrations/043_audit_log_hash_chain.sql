-- 043_audit_log_hash_chain.sql
--
-- Add tamper-evident hash-chaining to the audit_log table.
--
-- Why: ``audit_log`` already enforces append-only writes through a
-- trigger (see 004_audit_log.sql) and tenant isolation through RLS.
-- What it does NOT defend against is a privileged operator (or stolen
-- DB credentials) issuing a DROP/RECREATE or TRUNCATE on the table and
-- forging a replacement history that still satisfies the trigger.
--
-- A hash-chain closes that gap. Each row carries:
--   * ``prev_hash``  — the ``entry_hash`` of the previous audit row
--                      for the same tenant, or NULL for the first.
--   * ``entry_hash`` — sha256 over the canonical serialization of the
--                      row's fields, mixed with ``prev_hash``.
--
-- Verification (offline or via the export endpoint) replays the chain
-- per tenant and proves no row was deleted, reordered, or rewritten.
-- The trigger-enforced immutability still applies; the chain catches
-- the cases the trigger cannot.
--
-- Both columns are nullable + idempotent so existing deployments can
-- adopt the chain without a backfill flag day — new rows chain off the
-- last existing row (or NULL if the table is empty for that tenant).

BEGIN;

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS prev_hash  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(64);

-- Index supports the "latest entry per tenant" lookup that the chain
-- writer performs on every insert.
CREATE INDEX IF NOT EXISTS idx_audit_tenant_entry_hash
    ON audit_log(tenant_id, created_at DESC)
    WHERE entry_hash IS NOT NULL;

COMMIT;
