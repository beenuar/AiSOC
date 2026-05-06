-- Migration 018: Identity-centric correlation graph
-- Stores identity nodes (users, service accounts, devices) and edges
-- (relationships, auth events, privilege grants) for graph-based correlation.

BEGIN;

-- 1. Identity nodes --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_type       TEXT NOT NULL CHECK (node_type IN (
                        'human_user', 'service_account', 'device',
                        'application', 'group', 'role'
                    )),
    external_id     TEXT NOT NULL,      -- email, UPN, ARN, object ID, etc.
    display_name    TEXT,
    source_system   TEXT NOT NULL,      -- 'okta', 'azure_ad', 'aws_iam', etc.
    -- risk context
    risk_score      FLOAT NOT NULL DEFAULT 0.0 CHECK (risk_score BETWEEN 0.0 AND 100.0),
    -- privilege tier: 0=standard, 1=elevated, 2=admin, 3=super-admin
    privilege_tier  INT NOT NULL DEFAULT 0 CHECK (privilege_tier BETWEEN 0 AND 3),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_activity   TIMESTAMPTZ,
    attributes      JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source_system, external_id)
);

CREATE INDEX IF NOT EXISTS idx_inode_tenant   ON identity_nodes (tenant_id);
CREATE INDEX IF NOT EXISTS idx_inode_type     ON identity_nodes (tenant_id, node_type);
CREATE INDEX IF NOT EXISTS idx_inode_risk     ON identity_nodes (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_inode_priv     ON identity_nodes (tenant_id, privilege_tier DESC);
CREATE INDEX IF NOT EXISTS idx_inode_extid    ON identity_nodes (tenant_id, external_id);

-- 2. Identity edges (relationships) ---------------------------------------------
CREATE TABLE IF NOT EXISTS identity_edges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id       UUID NOT NULL REFERENCES identity_nodes(id) ON DELETE CASCADE,
    target_id       UUID NOT NULL REFERENCES identity_nodes(id) ON DELETE CASCADE,
    edge_type       TEXT NOT NULL CHECK (edge_type IN (
                        'member_of', 'manages', 'owns', 'delegates_to',
                        'authenticated_to', 'assumed_role', 'accessed',
                        'created', 'lateral_movement_candidate'
                    )),
    weight          FLOAT NOT NULL DEFAULT 1.0,
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ,
    evidence        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source_id, target_id, edge_type)
);

CREATE INDEX IF NOT EXISTS idx_iedge_tenant  ON identity_edges (tenant_id);
CREATE INDEX IF NOT EXISTS idx_iedge_source  ON identity_edges (source_id);
CREATE INDEX IF NOT EXISTS idx_iedge_target  ON identity_edges (target_id);
CREATE INDEX IF NOT EXISTS idx_iedge_type    ON identity_edges (tenant_id, edge_type);

-- 3. Alert-to-identity correlation ----------------------------------------------
CREATE TABLE IF NOT EXISTS alert_identity_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id        UUID NOT NULL,
    node_id         UUID NOT NULL REFERENCES identity_nodes(id) ON DELETE CASCADE,
    link_reason     TEXT NOT NULL,  -- 'subject', 'actor', 'target', 'lateral_path'
    confidence      FLOAT NOT NULL DEFAULT 1.0 CHECK (confidence BETWEEN 0.0 AND 1.0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alert_id_link_tenant ON alert_identity_links (tenant_id);
CREATE INDEX IF NOT EXISTS idx_alert_id_link_alert  ON alert_identity_links (alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_id_link_node   ON alert_identity_links (node_id);

-- 4. Updated-at trigger ----------------------------------------------------------
CREATE OR REPLACE FUNCTION update_inode_ts()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_inode_ts ON identity_nodes;
CREATE TRIGGER trg_inode_ts
    BEFORE UPDATE ON identity_nodes
    FOR EACH ROW EXECUTE FUNCTION update_inode_ts();

COMMIT;
