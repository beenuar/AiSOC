-- Migration 014: Insider-threat module
-- Tracks anomalous user-behaviour indicators and risk scores over time.

BEGIN;

-- 1. User behaviour baseline --------------------------------------------------
-- One row per user, updated by the fusion engine on each evaluation cycle.
CREATE TABLE IF NOT EXISTS user_risk_profiles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id             UUID REFERENCES users(id) ON DELETE CASCADE,
    external_user_ref   TEXT,          -- email / UPN for users not in the local table
    risk_score          FLOAT NOT NULL DEFAULT 0.0 CHECK (risk_score BETWEEN 0.0 AND 100.0),
    risk_tier           TEXT NOT NULL DEFAULT 'low'
        CHECK (risk_tier IN ('critical', 'high', 'medium', 'low')),
    -- aggregated behavioural signals
    failed_auth_24h     INT NOT NULL DEFAULT 0,
    off_hours_events_7d INT NOT NULL DEFAULT 0,
    data_staging_score  FLOAT NOT NULL DEFAULT 0.0,   -- 0–1
    peer_anomaly_score  FLOAT NOT NULL DEFAULT 0.0,   -- 0–1 vs. peer-group baseline
    privilege_delta     INT NOT NULL DEFAULT 0,        -- role/privilege changes in last 30d
    -- disposition
    is_watchlisted      BOOLEAN NOT NULL DEFAULT false,
    watchlist_reason    TEXT,
    watchlisted_at      TIMESTAMPTZ,
    watchlisted_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    -- timestamps
    last_evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, external_user_ref),
    UNIQUE (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_urp_tenant      ON user_risk_profiles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_urp_score       ON user_risk_profiles (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_urp_watchlist   ON user_risk_profiles (tenant_id) WHERE is_watchlisted;
CREATE INDEX IF NOT EXISTS idx_urp_user        ON user_risk_profiles (user_id) WHERE user_id IS NOT NULL;

-- 2. Insider-threat indicator events -----------------------------------------
CREATE TABLE IF NOT EXISTS insider_indicators (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id          UUID NOT NULL REFERENCES user_risk_profiles(id) ON DELETE CASCADE,
    indicator_type      TEXT NOT NULL,   -- 'off_hours_login', 'large_download', 'new_device', etc.
    severity            TEXT NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description         TEXT NOT NULL,
    source_alert_id     UUID,            -- linked alert if applicable
    evidence            JSONB NOT NULL DEFAULT '{}',
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ii_tenant   ON insider_indicators (tenant_id);
CREATE INDEX IF NOT EXISTS idx_ii_profile  ON insider_indicators (profile_id);
CREATE INDEX IF NOT EXISTS idx_ii_type     ON insider_indicators (tenant_id, indicator_type);
CREATE INDEX IF NOT EXISTS idx_ii_occurred ON insider_indicators (tenant_id, occurred_at DESC);

-- 3. Peer-group definitions ---------------------------------------------------
CREATE TABLE IF NOT EXISTS insider_peer_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    criteria    JSONB NOT NULL DEFAULT '{}',  -- e.g. {"department":"Engineering","job_title_prefix":"SRE"}
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS insider_peer_group_members (
    group_id    UUID NOT NULL REFERENCES insider_peer_groups(id) ON DELETE CASCADE,
    profile_id  UUID NOT NULL REFERENCES user_risk_profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, profile_id)
);

-- 4. Trigger to keep updated_at current --------------------------------------
CREATE OR REPLACE FUNCTION update_urp_ts()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_urp_ts ON user_risk_profiles;
CREATE TRIGGER trg_urp_ts
    BEFORE UPDATE ON user_risk_profiles
    FOR EACH ROW EXECUTE FUNCTION update_urp_ts();

COMMIT;
