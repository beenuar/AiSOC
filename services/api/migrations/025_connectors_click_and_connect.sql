-- 025_connectors_click_and_connect.sql
-- Align the connectors DDL with the evolved ORM model (Connector in
-- services/api/app/models/connector.py) used by the click-and-connect feature.

BEGIN;

-- Rename columns that changed semantics
ALTER TABLE connectors RENAME COLUMN config          TO connector_config;
ALTER TABLE connectors RENAME COLUMN credentials_enc TO auth_config;
ALTER TABLE connectors RENAME COLUMN status          TO health_status;
ALTER TABLE connectors RENAME COLUMN last_sync_at    TO last_sync;

-- Resize the health_status column to match the ORM (VARCHAR 20)
ALTER TABLE connectors ALTER COLUMN health_status TYPE VARCHAR(20);
ALTER TABLE connectors ALTER COLUMN health_status SET DEFAULT 'unknown';

-- Add new columns introduced by the ORM
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS category         VARCHAR(50) NOT NULL DEFAULT '';
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS last_health_check TIMESTAMPTZ;
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS error_count      INTEGER     DEFAULT 0;
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS tags             JSONB       DEFAULT '[]';

-- Drop columns the ORM no longer uses
ALTER TABLE connectors DROP COLUMN IF EXISTS vendor;
ALTER TABLE connectors DROP COLUMN IF EXISTS description;
ALTER TABLE connectors DROP COLUMN IF EXISTS last_error;

-- Index on connector_type for catalog lookups
CREATE INDEX IF NOT EXISTS idx_connectors_type ON connectors(connector_type);

COMMIT;
