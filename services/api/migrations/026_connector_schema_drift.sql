-- 026_connector_schema_drift.sql
-- Connector Health & Schema-Drift Sentinel
--
-- Adds three columns to the `connectors` table so the polling scheduler can
-- record schema fingerprints from each connector's most recent payload and
-- raise an alert (drift) when the field set changes between polls.
--
--   schema_fingerprint    : SHA-256 hex of the sorted unique top-level
--                           field names observed in the most recent batch.
--                           NULL until the connector has produced its
--                           first non-empty batch.
--
--   last_schema_drift_at  : Timestamp of the most recent confirmed drift
--                           (fingerprint changed vs prior baseline).
--
--   last_drift_details    : JSONB describing what changed — added fields,
--                           removed fields, sample event count, etc.
--                           Surfaced in the UI so an operator can decide
--                           whether the upstream API legitimately changed
--                           or whether a parser is breaking.
--
--   events_dropped        : Counter incremented when pre-ingest filter
--                           rules (Security Data Pipeline feature) drop
--                           an event before it reaches the ingest service.
--
-- This migration is additive and idempotent; running it twice is safe.

BEGIN;

ALTER TABLE connectors
    ADD COLUMN IF NOT EXISTS schema_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS last_schema_drift_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_drift_details JSONB,
    ADD COLUMN IF NOT EXISTS events_dropped INTEGER NOT NULL DEFAULT 0;

-- Index on health_status so the new health-summary endpoint can group
-- counts in a single scan instead of a tenant-wide table scan.
CREATE INDEX IF NOT EXISTS idx_connectors_health_status
    ON connectors(tenant_id, health_status);

-- Index on last_schema_drift_at to surface "drifted in the last 24 h"
-- rows quickly on the dashboard.
CREATE INDEX IF NOT EXISTS idx_connectors_last_drift
    ON connectors(tenant_id, last_schema_drift_at)
    WHERE last_schema_drift_at IS NOT NULL;

COMMIT;
