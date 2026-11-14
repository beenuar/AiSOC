-- Workload identity, API-key rotation, JIT elevation, ABAC conditions.
--
-- Gap-closure wave 13.
--
-- **One shared service token.** `AISOC_SERVICE_TOKEN` is a single
-- string every internal caller presents. It cannot be attributed —
-- the audit trail says "a service" did it — it cannot be rotated
-- without restarting everything at once, and it cannot be scoped, so
-- the agents worker presents the same credential as the ingest
-- pipeline. One leaked log line is total internal access.
--
-- **API keys cannot be rotated in place.** The only path is create a
-- new one, update every caller, delete the old one — so rotation
-- means downtime and most people do not do it.
--
-- **No elevation.** A role is held permanently or not at all, so an
-- analyst who needs to isolate a host once either holds that
-- permission every day or waits for someone who does.
--
-- **Permissions are unconditional.** `cases:write` is true everywhere,
-- always, from any address. There is no way to say "from the
-- corporate network" or "during this incident".

-- ── Workload identity ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS workload_identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Which service this credential belongs to. The whole point: the
    -- audit trail can name `agents` rather than "a service".
    service         TEXT NOT NULL,
    description     TEXT,

    -- Scopes this workload may use, which the shared token could not
    -- express. The ingest pipeline does not need to dispatch actions.
    scopes          TEXT[] NOT NULL DEFAULT ARRAY[]::text[],

    -- Hashed, never stored in the clear. A secret readable from the
    -- table it authenticates against is not a secret.
    secret_hash     TEXT NOT NULL,
    secret_prefix   TEXT NOT NULL,

    -- Rotation without downtime needs two live secrets at once. The
    -- previous one keeps working until `previous_expires_at`, so
    -- callers roll over on their own schedule instead of all at the
    -- same instant.
    previous_hash       TEXT,
    previous_expires_at TIMESTAMPTZ,

    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (service, secret_prefix)
);

CREATE INDEX IF NOT EXISTS ix_workload_prefix ON workload_identities (secret_prefix) WHERE revoked_at IS NULL;

COMMENT ON TABLE workload_identities IS
    'Per-service credentials replacing the single shared AISOC_SERVICE_TOKEN, which '
    'could not be attributed, scoped, or rotated without restarting everything at once.';

-- ── API-key rotation in place ──────────────────────────────────────────────

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS previous_hash TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS previous_expires_at TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;

COMMENT ON COLUMN api_keys.previous_hash IS
    'The superseded secret, honoured until previous_expires_at. Rotation used to mean '
    'create, update every caller, delete — which is downtime, so most people never did it.';

-- ── Just-in-time elevation ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS privilege_grants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- What was granted, and only for a while. Permissions rather than
    -- a role: elevating to `admin` to isolate one host grants the
    -- wildcard, which is the opposite of least privilege.
    permissions     TEXT[] NOT NULL,

    -- Why, in the requester's words, and who approved. An elevation
    -- nobody has to justify is a role held permanently with extra
    -- steps.
    justification   TEXT NOT NULL,
    approved_by_id  UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Bounded, and short. NOT NULL so a grant cannot be permanent by
    -- omission, which is how every JIT system decays into standing
    -- access.
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,

    -- What the elevation was for, so a review can ask whether it was
    -- used for that.
    case_id         UUID,
    alert_id        UUID
);

CREATE INDEX IF NOT EXISTS ix_privilege_grants_live
    ON privilege_grants (tenant_id, user_id, expires_at)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE privilege_grants IS
    'Time-boxed permission grants. Permissions rather than roles: elevating to admin to '
    'isolate one host confers the wildcard, which is the opposite of least privilege.';

-- ── ABAC conditions ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS permission_conditions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The permission this constrains. Conditions narrow; they never
    -- grant. A condition that could grant would be a second
    -- authorization system disagreeing with the first.
    permission      TEXT NOT NULL,
    role            TEXT,

    -- Declarative so a condition can be added from the console without
    -- a deploy, and so the evaluator is one audited function rather
    -- than scattered checks.
    condition       JSONB NOT NULL DEFAULT '{}'::jsonb,
    description     TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_permission_conditions
    ON permission_conditions (tenant_id, permission) WHERE enabled;

COMMENT ON TABLE permission_conditions IS
    'Attribute conditions that narrow a permission. They never grant: a condition that '
    'could grant would be a second authorization system disagreeing with the first.';

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['privilege_grants', 'permission_conditions']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
            'WITH CHECK (tenant_id = current_tenant_id())',
            t
        );
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO aisoc_app', t);
        END IF;
    END LOOP;

    -- Workload identities are deployment-wide, not tenant-scoped: a
    -- service authenticates before any tenant is known.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON workload_identities TO aisoc_app;
    END IF;
END
$$;
