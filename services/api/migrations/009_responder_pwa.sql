-- AiSOC Responder PWA migration (Phase 4B)
-- Adds the operational tables the mobile responder PWA needs:
--
--   passkey_credentials   — WebAuthn passkeys per user (passwordless auth)
--   passkey_challenges    — short-lived register/auth challenges
--   oncall_status         — current on-call snapshot per user (available|busy|offline)
--   agent_approvals       — agent-blocking approval requests with one-tap
--                           approve/deny actions from the PWA
--
-- Plus a `snoozed_until` column on `alerts` so the queue view can hide
-- alerts the responder asked to defer for an hour without losing them.
--
-- All tables enforce tenant isolation via Row-Level Security so the
-- responder PWA respects the same boundaries as alerts/cases.

-- ============================================================
-- 0. Alerts: snooze support for the mobile triage queue
-- ============================================================
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS snoozed_by_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_snoozed
    ON alerts(tenant_id, snoozed_until)
    WHERE snoozed_until IS NOT NULL;

-- ============================================================
-- 1. passkey_credentials  (WebAuthn / FIDO2)
-- ============================================================
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Raw WebAuthn credential ID (base64url-encoded for portability).
    credential_id   TEXT         NOT NULL UNIQUE,
    -- COSE public key, base64url-encoded.
    public_key      TEXT         NOT NULL,
    -- Anti-clone counter from the authenticator.
    sign_count      BIGINT       NOT NULL DEFAULT 0,
    -- Authenticator transports (usb, ble, nfc, internal, hybrid).
    transports      JSONB        NOT NULL DEFAULT '[]'::jsonb,
    -- Friendly name like "iPhone 15 Pro" or "YubiKey 5C NFC".
    device_name     VARCHAR(120) NOT NULL,
    -- Optional AAGUID for telemetry / device-class display.
    aaguid          UUID,
    -- True if the authenticator says it's a discoverable credential.
    is_discoverable BOOLEAN      NOT NULL DEFAULT TRUE,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user
    ON passkey_credentials(user_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_passkeys_tenant
    ON passkey_credentials(tenant_id);

ALTER TABLE passkey_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS passkeys_tenant ON passkey_credentials;
CREATE POLICY passkeys_tenant ON passkey_credentials
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ============================================================
-- 2. passkey_challenges  (short-lived registration & auth challenges)
-- ============================================================
CREATE TABLE IF NOT EXISTS passkey_challenges (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Challenge type: 'register' or 'authenticate'.
    purpose     VARCHAR(20)  NOT NULL,
    -- The pre-shared random challenge bytes, base64url-encoded.
    challenge   TEXT         NOT NULL UNIQUE,
    -- For registration we know the user; for authentication we may not
    -- (discoverable creds), in which case both fields are NULL.
    user_id     UUID         REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID         REFERENCES tenants(id) ON DELETE CASCADE,
    -- For passwordless conditional UI flows we record the email hint.
    email_hint  VARCHAR(255),
    -- The hostname/origin that asked for the challenge (RP ID).
    rp_id       VARCHAR(255) NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expiry
    ON passkey_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_user
    ON passkey_challenges(user_id);

-- Challenges deliberately do NOT enforce RLS: the registration/auth start
-- endpoints insert rows on behalf of unauthenticated users (auth flow) or
-- in the tenant context of the requesting user (registration flow). The
-- challenge value itself is the secret.

-- ============================================================
-- 3. oncall_status  (current on-call snapshot per user)
-- ============================================================
CREATE TABLE IF NOT EXISTS oncall_status (
    user_id     UUID         PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- 'available' | 'busy' | 'offline'.
    status      VARCHAR(20)  NOT NULL DEFAULT 'offline',
    -- ISO-8601 schedule reference (PagerDuty/OpsGenie/manual/etc).
    schedule_ref VARCHAR(200),
    -- Optional rotation handle ("primary-soc", "ir-secondary", …).
    rotation    VARCHAR(80),
    note        TEXT,
    until       TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oncall_tenant_status
    ON oncall_status(tenant_id, status);

ALTER TABLE oncall_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE oncall_status FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oncall_tenant ON oncall_status;
CREATE POLICY oncall_tenant ON oncall_status
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ============================================================
-- 4. agent_approvals  (one-tap approval requests blocking agent runs)
-- ============================================================
CREATE TABLE IF NOT EXISTS agent_approvals (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Optional pointers back to the originating run/case/alert.
    run_id          UUID         REFERENCES investigation_runs(id) ON DELETE SET NULL,
    case_id         VARCHAR(200),
    alert_id        UUID,
    -- Who created the approval (always the agents service).
    requested_by    VARCHAR(120) NOT NULL DEFAULT 'agent',
    -- Who must approve. Either a specific user or a rotation/topic.
    required_user_id UUID        REFERENCES users(id) ON DELETE SET NULL,
    required_topic  VARCHAR(80),
    -- Human-readable summary surfaced in the PWA card.
    title           VARCHAR(200) NOT NULL,
    summary         TEXT         NOT NULL,
    risk_level      VARCHAR(20)  NOT NULL DEFAULT 'medium',
    -- Structured action the agent intends to take if approved
    -- ({ kind: "isolate_host", host: "WIN-…" }, etc).
    action          JSONB        NOT NULL,
    -- Approval lifecycle.
    status          VARCHAR(20)  NOT NULL DEFAULT 'pending',
    -- pending | approved | denied | expired | cancelled
    decided_by_id   UUID         REFERENCES users(id) ON DELETE SET NULL,
    decided_at      TIMESTAMPTZ,
    decision_comment TEXT,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_approvals_tenant_status
    ON agent_approvals(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_approvals_user
    ON agent_approvals(required_user_id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_agent_approvals_run
    ON agent_approvals(run_id);

ALTER TABLE agent_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_approvals_tenant ON agent_approvals;
CREATE POLICY agent_approvals_tenant ON agent_approvals
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ============================================================
-- 5. House-keeping: keep updated_at fresh on agent_approvals
-- ============================================================
CREATE OR REPLACE FUNCTION agent_approvals_touch_updated()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_agent_approvals_touch ON agent_approvals;
CREATE TRIGGER trg_agent_approvals_touch
    BEFORE UPDATE ON agent_approvals
    FOR EACH ROW EXECUTE FUNCTION agent_approvals_touch_updated();
