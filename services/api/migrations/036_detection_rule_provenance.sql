-- Migration 036: Bulk-import provenance for detection_rules (WS-B1)
--
-- The Sigma bulk-import pipeline (services/api/app/services/detections/sigma_import.py)
-- pulls hundreds of community rules per run. To make those imports honest
-- and re-runnable we need a structured ``provenance`` block on every rule
-- row — the same shape we already use on disk for offline imports
-- (tools/detection_import/common.py):
--
--   {
--     "source":         "SigmaHQ/sigma",
--     "source_id":      "<upstream uuid>",
--     "source_commit":  "<short sha>",
--     "license":        "DRL-1.1",
--     "license_url":    "https://...",
--     "imported_at":    "2026-05-09",
--     "imported_by":    "sigma_importer",
--     "upstream_path":  "rules/cloud/aws/aws_root_login.yml"
--   }
--
-- Why a dedicated column (and not just stuff it into ``tags``)?
--   1. Idempotency. Re-running the importer must update an existing row
--      rather than create duplicates; the lookup key is
--      ``(provenance->>'source', provenance->>'source_id')``. We need
--      a real index for that query at corpus sizes ≥ 300 rules.
--   2. Attribution. License + upstream path are not "tags"; they are
--      legal/audit metadata that must survive rule edits.
--   3. Separation of concerns. ``tags`` already carries MITRE technique
--      IDs and category buckets used by the runtime engine; mixing
--      provenance into the same blob makes both harder to evolve.
--
-- We use ADD COLUMN IF NOT EXISTS so the migration tolerates two distinct
-- code paths through which the table reaches us:
--   * Dev installs that bootstrap the schema via SQLAlchemy's
--     ``Base.metadata.create_all`` (services/api/app/models/detection_rule.py)
--     — the column is created on first boot and this migration is a no-op.
--   * Legacy installs that originated from migration 001_init.sql
--     (which predates the rule_language/rule_body refactor and never
--     defined ``provenance``) — this migration adds the column without
--     touching the legacy rule_type/rule_content columns.

BEGIN;

-- 1. Add the column. JSONB instead of JSON: we will index it.
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS provenance JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2. Idempotency lookup index.
--    Re-imports query by (source, source_id) to decide INSERT vs UPDATE.
--    We index the JSON path expressions directly so the planner can use
--    a single index scan rather than a sequential scan with a JSON cast.
--    NOT UNIQUE — a rule's source_id is unique per source, but the
--    business uniqueness is enforced by the importer (which we trust
--    far more than upstream contributors). A unique constraint here
--    would make a bad upstream rename break the entire import run; the
--    importer prefers to surface a warning and continue.
CREATE INDEX IF NOT EXISTS detection_rules_provenance_source_idx
    ON detection_rules ((provenance ->> 'source'), (provenance ->> 'source_id'));

-- 3. License rollup index. Operators who need to honour an upstream
--    license clause (DRL-1.1's attribution requirement, GPL's copyleft,
--    etc.) want a fast "list every imported rule under <license>" query.
--    Cheap to maintain — the license cardinality is single-digit.
CREATE INDEX IF NOT EXISTS detection_rules_provenance_license_idx
    ON detection_rules ((provenance ->> 'license'))
    WHERE provenance ? 'license';

COMMENT ON COLUMN detection_rules.provenance IS
    'WS-B1: structured provenance block for imported rules. Empty {} for native AiSOC rules. Used by services/api/app/services/detections/sigma_import.py for idempotent re-imports.';

COMMIT;
