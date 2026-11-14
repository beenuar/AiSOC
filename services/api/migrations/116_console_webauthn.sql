-- Per-role MFA enforcement, and WebAuthn as a console second factor.
--
-- Depth 8.1 (parity 4.2's remainder).
--
-- `096_console_mfa.sql` shipped TOTP with recovery codes and a per-*tenant*
-- switch. Two halves of the item were left open: enforcement per **role**,
-- and WebAuthn.
--
-- WebAuthn needs no new table. `009_responder_pwa.sql` already has
-- `passkey_credentials` and `passkey_challenges`, and both the registration
-- and the authentication path in `app/api/v1/endpoints/passkeys.py` pass
-- `require_user_verification=True` — so every credential in that table is a
-- possession factor that has also verified the user, which is what a second
-- factor has to be. A second table would have meant a user enrolling the
-- same authenticator twice to use it in two places, and two sign-count
-- high-water marks for one device, which is a clone-detection control split
-- in half.

-- ── Per-role enforcement ────────────────────────────────────────────────────
--
-- One row per (tenant, role) an administrator has asked to enforce. The
-- effective requirement is the tenant-wide switch in
-- `aisoc_tenant_mfa_policy` **OR** a row here matching the user's role, so a
-- deployment can require a second factor of its administrators without
-- requiring one of every viewer.
--
-- **No migration writes a row, and absence means "not required".** The
-- alternative — a row per (tenant, role) with `require_mfa = FALSE` — changes
-- the meaning of every predicate that counts rows in this table, and that
-- exact shape has already produced a zero-permission administrator on a fresh
-- install in this repository. `096` says the same thing about its own table
-- and the reasoning has not changed.
--
-- `role` is a plain TEXT with no foreign key, deliberately. The role
-- vocabulary lives in `ROLE_PERMISSIONS` in application code and in the RBAC
-- catalogue seed, which disagree by construction (the catalogue seeds a
-- subset). A foreign key to either would make a policy un-writable for a role
-- that exists in the other, and the failure would be a 500 at policy-save
-- time rather than anything an administrator could act on. The application
-- validates the name against `ROLE_PERMISSIONS` before the insert.
CREATE TABLE IF NOT EXISTS aisoc_tenant_mfa_role_policy (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role         TEXT NOT NULL,
    require_mfa  BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, role)
);

-- ── Row-level security ──────────────────────────────────────────────────────
--
-- The same shape as `096_console_mfa.sql`, and for the same reason, which is
-- worth restating because it is the one arm that looks like a hole:
--
-- The unbound read arm (`current_tenant_id() IS NULL`) is **required**. The
-- login route runs before there is an authenticated principal, so the session
-- it arrives on binds no tenant. Without it, every enforcement check on every
-- deployment running as the DML-only `aisoc_app` role would see zero rows and
-- conclude no role required a factor — which fails open, the one direction
-- this table must never fail.
--
-- Writes stay bound with no null escape, so an unscoped session cannot insert
-- a row naming any tenant it likes. Written out rather than looped over in a
-- `DO $$` block: a policy built by `EXECUTE format(...)` is invisible to
-- `check_rls_policy_shape.py` and `check_tenant_query_predicates.py`, both of
-- which replay this file as text.
ALTER TABLE aisoc_tenant_mfa_role_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_tenant_mfa_role_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON aisoc_tenant_mfa_role_policy;
CREATE POLICY tenant_isolation ON aisoc_tenant_mfa_role_policy
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

-- ── The console's own WebAuthn credentials ──────────────────────────────────
--
-- `passkey_credentials` predates per-surface thinking and carries no column
-- saying where a credential was enrolled. The console needs to *show* that
-- ("Security key added from the console on 3 March"), and an administrator
-- resetting a user's console factors must not silently revoke the passkey
-- that account uses to sign in to the responder app on their phone.
--
-- Nullable, and NULL means "enrolled before this column existed", which is
-- the responder PWA because that was the only enroller. It is not defaulted
-- to `'responder'`: a backfilled value asserts something about rows nobody
-- measured, and the honest reading of an unlabelled row is that its origin is
-- unknown.
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS enrolled_via TEXT;

CREATE INDEX IF NOT EXISTS passkey_credentials_user_active_idx
    ON passkey_credentials (user_id) WHERE revoked_at IS NULL;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_tenant_mfa_role_policy TO aisoc_app;
    END IF;
END
$$;
