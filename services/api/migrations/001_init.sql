-- AiSOC initial schema
-- Runs on first postgres container start via /docker-entrypoint-initdb.d

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ──────────────────────────────────────────────────────────────────────────────
-- Tenants & Users
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100) UNIQUE NOT NULL,
    plan        VARCHAR(50)  DEFAULT 'starter',
    is_active   BOOLEAN      DEFAULT TRUE,
    settings    JSONB        DEFAULT '{}',
    limits      JSONB        DEFAULT '{}',
    created_at  TIMESTAMPTZ  DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           VARCHAR(255) UNIQUE NOT NULL,
    username        VARCHAR(100) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role            VARCHAR(50)  DEFAULT 'soc_analyst',
    is_active       BOOLEAN      DEFAULT TRUE,
    is_verified     BOOLEAN      DEFAULT FALSE,
    last_login      TIMESTAMPTZ,
    preferences     JSONB        DEFAULT '{}',
    created_at      TIMESTAMPTZ  DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);

CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    name         VARCHAR(255) NOT NULL,
    key_prefix   VARCHAR(20)  NOT NULL,
    hashed_key   VARCHAR(255) NOT NULL,
    scopes       JSONB        DEFAULT '[]',
    is_active    BOOLEAN      DEFAULT TRUE,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hashed ON api_keys(hashed_key);

-- ──────────────────────────────────────────────────────────────────────────────
-- Connectors
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS connectors (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             VARCHAR(255) NOT NULL,
    connector_type   VARCHAR(100) NOT NULL,
    vendor           VARCHAR(100),
    description      TEXT,
    config           JSONB        DEFAULT '{}',
    credentials_enc  JSONB        DEFAULT '{}',
    is_enabled       BOOLEAN      DEFAULT TRUE,
    status           VARCHAR(30)  DEFAULT 'pending',
    last_sync_at     TIMESTAMPTZ,
    last_error       TEXT,
    events_ingested  BIGINT       DEFAULT 0,
    created_at       TIMESTAMPTZ  DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);

-- ──────────────────────────────────────────────────────────────────────────────
-- Alerts
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS alerts (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title               VARCHAR(500) NOT NULL,
    description         TEXT,
    severity            VARCHAR(20)  NOT NULL DEFAULT 'medium',
    status              VARCHAR(30)  NOT NULL DEFAULT 'new',
    priority            INTEGER      DEFAULT 50,
    category            VARCHAR(100),
    mitre_tactics       JSONB        DEFAULT '[]',
    mitre_techniques    JSONB        DEFAULT '[]',
    connector_id        UUID,
    connector_type      VARCHAR(100),
    source_event_ids    JSONB        DEFAULT '[]',
    ocsf_class_uid      INTEGER,
    ai_score            FLOAT,
    ai_summary          TEXT,
    ai_recommendations  JSONB        DEFAULT '[]',
    false_positive_score FLOAT,
    anomaly_score       FLOAT,
    iocs                JSONB        DEFAULT '[]',
    entities            JSONB        DEFAULT '[]',
    raw_event           JSONB        DEFAULT '{}',
    dedup_hash          VARCHAR(64),
    case_id             UUID,
    first_seen          TIMESTAMPTZ  DEFAULT NOW(),
    last_seen           TIMESTAMPTZ  DEFAULT NOW(),
    event_time          TIMESTAMPTZ  DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant   ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_case     ON alerts(case_id);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup    ON alerts(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_alerts_event_t  ON alerts(event_time DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- Cases
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cases (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_number      VARCHAR(30)  UNIQUE NOT NULL,
    title            VARCHAR(500) NOT NULL,
    description      TEXT,
    status           VARCHAR(30)  DEFAULT 'open',
    priority         VARCHAR(20)  DEFAULT 'medium',
    severity         VARCHAR(20)  DEFAULT 'medium',
    case_type        VARCHAR(50)  DEFAULT 'security_incident',
    mitre_tactics    JSONB        DEFAULT '[]',
    mitre_techniques JSONB        DEFAULT '[]',
    assigned_to_id   UUID,
    assigned_at      TIMESTAMPTZ,
    created_by_id    UUID,
    sla_deadline     TIMESTAMPTZ,
    sla_breached     BOOLEAN      DEFAULT FALSE,
    alert_ids        JSONB        DEFAULT '[]',
    ioc_ids          JSONB        DEFAULT '[]',
    artifact_ids     JSONB        DEFAULT '[]',
    tags             JSONB        DEFAULT '[]',
    ticket_refs      JSONB        DEFAULT '[]',
    summary          TEXT,
    closed_at        TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cases_tenant   ON cases(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases(priority);

CREATE TABLE IF NOT EXISTS case_timeline_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL,
    event_type  VARCHAR(50) NOT NULL,
    actor_id    UUID,
    actor_type  VARCHAR(30) DEFAULT 'user',
    summary     TEXT NOT NULL,
    detail      JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_case_timeline_case ON case_timeline_events(case_id);

-- ──────────────────────────────────────────────────────────────────────────────
-- Detection Rules
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS detection_rules (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    rule_type       VARCHAR(20)  NOT NULL DEFAULT 'sigma',
    rule_content    TEXT         NOT NULL,
    severity        VARCHAR(20)  DEFAULT 'medium',
    tags            JSONB        DEFAULT '[]',
    mitre_tactics   JSONB        DEFAULT '[]',
    mitre_techniques JSONB       DEFAULT '[]',
    enabled         BOOLEAN      DEFAULT TRUE,
    version         INTEGER      DEFAULT 1,
    last_run_at     TIMESTAMPTZ,
    last_hit_at     TIMESTAMPTZ,
    hit_count       BIGINT       DEFAULT 0,
    author          VARCHAR(255),
    source          VARCHAR(100) DEFAULT 'custom',
    created_at      TIMESTAMPTZ  DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rules_tenant  ON detection_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON detection_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_rules_type    ON detection_rules(rule_type);

-- ──────────────────────────────────────────────────────────────────────────────
-- Seed: default tenant & admin user
-- ──────────────────────────────────────────────────────────────────────────────

INSERT INTO tenants (id, name, slug, plan)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'enterprise')
ON CONFLICT (slug) DO NOTHING;

-- password = "admin" (bcrypt)
INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'admin@aisoc.local',
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3EEbF7FtRS',
    'admin',
    TRUE,
    TRUE
) ON CONFLICT (email) DO NOTHING;
