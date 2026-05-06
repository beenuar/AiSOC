-- Migration 016: Internal threat-intel generation
-- Stores IOCs, threat actor profiles, and campaign data produced or enriched
-- by the AiSOC fusion engine.

BEGIN;

-- 1. IOC (Indicators of Compromise) catalogue -----------------------------------
CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ioc_type        TEXT NOT NULL CHECK (ioc_type IN (
                        'ip', 'domain', 'url', 'file_hash_md5',
                        'file_hash_sha1', 'file_hash_sha256',
                        'email', 'asn', 'cidr', 'cve'
                    )),
    value           TEXT NOT NULL,
    -- confidence and scoring
    confidence      INT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    severity        TEXT NOT NULL DEFAULT 'medium'
                        CHECK (severity IN ('critical','high','medium','low','info')),
    tlp             TEXT NOT NULL DEFAULT 'amber'
                        CHECK (tlp IN ('red','amber','green','white')),
    -- attribution and classification
    threat_actor    TEXT,
    campaign        TEXT,
    malware_family  TEXT,
    tags            TEXT[],
    -- sourcing
    source          TEXT NOT NULL DEFAULT 'internal',
    source_ref      TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    -- status
    is_active       BOOLEAN NOT NULL DEFAULT true,
    false_positive  BOOLEAN NOT NULL DEFAULT false,
    -- related alerts (array of alert UUIDs as text for portability)
    linked_alerts   UUID[],
    -- freeform context
    context         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_ioc_tenant        ON threat_intel_iocs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_ioc_type_value    ON threat_intel_iocs (tenant_id, ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_active        ON threat_intel_iocs (tenant_id) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_ioc_actor         ON threat_intel_iocs (tenant_id, threat_actor) WHERE threat_actor IS NOT NULL;

-- 2. Threat actor profiles -------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_actors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    aliases         TEXT[],
    motivation      TEXT,   -- 'financial', 'espionage', 'hacktivism', etc.
    sophistication  TEXT CHECK (sophistication IN ('minimal','novice','intermediate','advanced','expert')),
    country_of_origin TEXT,
    target_sectors  TEXT[],
    ttps            TEXT[],     -- MITRE ATT&CK technique IDs
    description     TEXT,
    first_observed  TIMESTAMPTZ,
    last_activity   TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    context         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_actor_tenant  ON threat_actors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_actor_active  ON threat_actors (tenant_id) WHERE is_active;

-- 3. Intel feed subscriptions ----------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    feed_type       TEXT NOT NULL CHECK (feed_type IN ('taxii', 'misp', 'stix', 'csv', 'json', 'internal')),
    url             TEXT,
    api_key_ref     TEXT,       -- references credential vault key name
    poll_interval   INT NOT NULL DEFAULT 3600,  -- seconds
    last_polled_at  TIMESTAMPTZ,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    config          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_feed_tenant ON threat_intel_feeds (tenant_id);

-- 4. Updated-at triggers ---------------------------------------------------------
CREATE OR REPLACE FUNCTION update_ti_ts()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_ioc_ts ON threat_intel_iocs;
CREATE TRIGGER trg_ioc_ts
    BEFORE UPDATE ON threat_intel_iocs
    FOR EACH ROW EXECUTE FUNCTION update_ti_ts();

DROP TRIGGER IF EXISTS trg_actor_ts ON threat_actors;
CREATE TRIGGER trg_actor_ts
    BEFORE UPDATE ON threat_actors
    FOR EACH ROW EXECUTE FUNCTION update_ti_ts();

COMMIT;
