-- A second factor for the desktop console.
--
-- Fix pass 4.2.
--
-- `POST /api/v1/auth/login` verified a password and returned a token pair,
-- and nothing a user or an administrator could do made that insufficient.
-- Passkeys existed on `/responder/*` only, so the surface an analyst works
-- from all day was single-factor by construction.

-- ── The enrolment ───────────────────────────────────────────────────────────
--
-- One row per enrolled user. A row exists from `enroll/begin`; it is only a
-- *credential* once `confirmed_at` is set, which happens when the user
-- returns a code the secret generates. Unconfirmed rows are deliberately
-- inert: beginning an enrolment and abandoning it must not lock anybody out
-- of their own account.
CREATE TABLE IF NOT EXISTS aisoc_user_mfa (
    user_id         UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Vault-encrypted (`vault:v1:` / `vault:v2:`), never the base32 the user
    -- scanned. A database dump that yields TOTP secrets yields the second
    -- factor for every account in it, which is most of the reason for having
    -- one.
    secret_encrypted TEXT NOT NULL,

    confirmed_at    TIMESTAMPTZ,

    -- The highest 30-second step this secret has already authenticated.
    -- Without it a code stays arithmetically valid for the rest of its
    -- window after use, so anyone who reads it over an analyst's shoulder
    -- has most of a minute to replay it.
    last_used_step  BIGINT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS aisoc_user_mfa_tenant_idx ON aisoc_user_mfa (tenant_id);

-- ── Recovery codes ──────────────────────────────────────────────────────────
--
-- Hashed with SHA-256 rather than bcrypt, deliberately. A recovery code is
-- 100+ bits of generated entropy, so there is no dictionary to slow down,
-- and a verification walks every unused code the user holds — ten bcrypt
-- comparisons per attempt would be a second of CPU on the login path and a
-- denial-of-service primitive.
CREATE TABLE IF NOT EXISTS aisoc_user_mfa_recovery_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS aisoc_user_mfa_recovery_user_idx
    ON aisoc_user_mfa_recovery_codes (user_id) WHERE used_at IS NULL;

-- ── Per-tenant enforcement ──────────────────────────────────────────────────
--
-- A row exists only once an administrator has asked for one, and **no
-- migration writes one**. Absence means "not required".
--
-- Stated because the obvious alternative — backfill a row per tenant with
-- `require_totp = FALSE` — changes the meaning of every predicate that
-- counts rows in this table, and that exact shape has already produced a
-- zero-permission administrator on a fresh install in this repository.
CREATE TABLE IF NOT EXISTS aisoc_tenant_mfa_policy (
    tenant_id     UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    require_totp  BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Row-level security ──────────────────────────────────────────────────────
--
-- The unbound arm (`current_tenant_id() IS NULL`) is required on the reads
-- and is the same reasoning `080_sso_connections.sql` spells out: the login
-- route runs *before* there is an authenticated principal, so the session it
-- arrives on binds no tenant. Without it, every MFA challenge on every
-- deployment running as the DML-only `aisoc_app` role would see zero rows and
-- conclude the user had no second factor — which fails open, the one
-- direction this table must never fail.
--
-- Writes stay bound, with no null escape, so an unscoped session cannot
-- insert a row naming any tenant it likes. The two write paths that run
-- before authentication — recording a spent recovery code, and advancing
-- `last_used_step` during a challenge — bind the context from the user row
-- they have already resolved, the same way `complete_sso_login` does.
-- Written out three times rather than looped over in a `DO $$` block.
-- The loop was the first draft and it is the wrong shape here: a policy
-- built by `EXECUTE format(...)` is invisible to `check_rls_policy_shape.py`
-- and `check_tenant_query_predicates.py`, both of which replay this file as
-- text, so the second reported these tables as having no RLS at all. A
-- security control a gate cannot see is a control nobody is holding to
-- account.

ALTER TABLE aisoc_user_mfa ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_user_mfa FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON aisoc_user_mfa;
CREATE POLICY tenant_isolation ON aisoc_user_mfa
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE aisoc_user_mfa_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_user_mfa_recovery_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON aisoc_user_mfa_recovery_codes;
CREATE POLICY tenant_isolation ON aisoc_user_mfa_recovery_codes
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE aisoc_tenant_mfa_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_tenant_mfa_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON aisoc_tenant_mfa_policy;
CREATE POLICY tenant_isolation ON aisoc_tenant_mfa_policy
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_user_mfa TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_user_mfa_recovery_codes TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_tenant_mfa_policy TO aisoc_app;
    END IF;
END
$$;
