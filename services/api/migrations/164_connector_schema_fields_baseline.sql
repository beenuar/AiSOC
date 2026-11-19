-- 164: drift-sentinel v2 — persist the stable-core baseline field set.
--
-- The sentinel used to store only the SHA-256 of the batch's full field-name
-- union. Two problems followed: (1) dynamically named fields (m365_audit's
-- param_<name> lifts from Parameters) and conditional optional fields
-- (src_ip, object_id, ...) vary legitimately between batches on busy
-- tenants, so ordinary polls fingerprinted as drift (all-added, zero-removed
-- noise on the dashboard); (2) with only a hash persisted, the 'removed'
-- diff could never be computed against the real baseline, so every drift
-- report listed the entire current key set as 'added'.
--
-- schema_fields stores the stable core key set (dynamic + optional excluded)
-- from the last accepted batch. Drift is now flagged only when a baseline
-- core field disappears — the rename/removal failure mode the sentinel
-- exists to catch.
ALTER TABLE connectors
    ADD COLUMN IF NOT EXISTS schema_fields JSONB;

COMMENT ON COLUMN connectors.schema_fields IS
    'Drift-sentinel baseline: stable core normalize() field names from the last accepted batch (dynamic param_* and optional fields excluded). NULL until first poll seeds it.';
