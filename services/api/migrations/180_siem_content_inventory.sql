-- the per-tenant SIEM content inventory.
--
-- The rule-health and proposal machinery exists for AiSOC-native rules and
-- lacks a SIEM-facing counterpart; the first missing piece is knowing WHAT
-- detection content the customer's SIEM runs. One row per (tenant,
-- connector, vendor rule), with a content hash so drift between sweeps is
-- a fact rather than a diff nobody ran. `last_seen` advancing with an
-- unchanged hash is "still there"; a changed hash bumps `version` and
-- keeps `previous_hash`, which is what the health view cites when a rule's
-- behaviour changes after an edit.

-- lane allocation: migration 180

CREATE TABLE IF NOT EXISTS siem_content_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id    UUID        NOT NULL,
    connector_type  TEXT        NOT NULL,
    vendor_rule_id  TEXT        NOT NULL,
    name            TEXT        NOT NULL DEFAULT '',
    kind            TEXT        NOT NULL DEFAULT '',
    enabled         BOOLEAN,
    severity        TEXT        NOT NULL DEFAULT '',
    -- The rule's own ATT&CK technique ids, where the vendor exposes them.
    attack          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    content_sha256  TEXT        NOT NULL,
    previous_hash   TEXT,
    version         INTEGER     NOT NULL DEFAULT 1,
    -- The vendor fields as listed, for the console drilldown. Query text
    -- included: the hash is computed over it.
    raw             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT siem_content_rules_identity UNIQUE (tenant_id, connector_id, vendor_rule_id)
);

COMMENT ON TABLE siem_content_rules IS
    'What detection content the tenant''s SIEM runs: one row per '
    'vendor rule, content-hashed so drift is a fact. Read-only inventory; '
    'writes to the SIEM go through the governed sync_detection_rule verb.';

CREATE INDEX IF NOT EXISTS idx_siem_content_tenant ON siem_content_rules (tenant_id, connector_type);

ALTER TABLE siem_content_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_content_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS siem_content_rules_tenant ON siem_content_rules;
CREATE POLICY siem_content_rules_tenant ON siem_content_rules
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON siem_content_rules TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS siem_content_rules;
