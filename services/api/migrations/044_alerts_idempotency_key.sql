-- 044_alerts_idempotency_key.sql
--
-- Add an idempotency key to the ``alerts`` table so the ``POST /alerts/submit``
-- direct-write path (the founder-flow ``aisoc submit`` CLI, and any connector
-- that retries on transient errors) can safely retry without creating
-- duplicate alert rows.
--
-- Rationale
-- ─────────
-- The submit endpoint synthesises one alert per request and writes it
-- straight into the alerts table. Without an idempotency key, a client
-- retrying after a network blip (or an at-least-once delivery from a
-- connector) lands two alerts that look identical to the analyst but
-- are separate rows — they double-count the queue, double-page on-call,
-- and corrupt MTTD numbers.
--
-- The key is supplied client-side under the ``Idempotency-Key`` header.
-- The server scopes uniqueness per tenant (different tenants can use the
-- same key without colliding). The unique partial index lets us keep the
-- column nullable for legacy rows / unrelated insertion paths while
-- still enforcing uniqueness on the subset of rows that opted in.
--
-- Idempotency is keyed (tenant_id, idempotency_key) — never just on the
-- key — so a hostile client can't replay another tenant's key and get
-- silently de-duplicated against an alert they don't own.
--
-- This migration is fully idempotent. ``ADD COLUMN IF NOT EXISTS`` and
-- ``CREATE UNIQUE INDEX IF NOT EXISTS`` make it safe to re-run on
-- partially-migrated environments.

BEGIN;

-- The column itself. Stored as TEXT so the client can use any opaque
-- string (UUIDs are the recommended shape, but we don't enforce that
-- — operators sometimes prefer hashes of source IDs for stable
-- deduplication across reconnections).
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

-- Partial unique index: only rows with a non-NULL idempotency_key
-- participate in the constraint. This keeps the column optional for
-- the connector pipeline (which has its own dedup via Kafka offsets)
-- while still enforcing strict per-tenant uniqueness for clients that
-- opt in.
CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_tenant_idempotency
    ON alerts (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

COMMIT;
