-- Issue #568: preserve source-rule provenance on the alert row.
--
-- Fusion previously encoded the firing detection rule only inside the
-- human-readable `source` ("detection:<id>") and `title` strings, so the
-- auto-triage worker and investigation graph had to parse them back out.
-- These columns carry the rule identifier + name (and, for vendor-asserted
-- Splunk notables, the saved-search name) as first-class fields.
--
-- Idempotent + transactional so the create_all lineage and repeated compose
-- installs stay green.
BEGIN;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_name TEXT;

COMMIT;
