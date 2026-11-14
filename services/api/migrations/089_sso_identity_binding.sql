-- Bind an identity-provider subject to the local account it signs in as.
--
-- GHSA-qjjc-q2h2-56cg. `provision_user` selected the local account with
-- `WHERE tenant_id = :t AND lower(email) = lower(:e)`, and nothing in the OIDC
-- path required `email_verified` -- the word appeared nowhere in `oidc.py` or
-- `sso_provisioning.py`. So an attacker able to authenticate to the tenant's
-- configured identity provider with an account carrying a victim's unverified
-- email received an access token minted for the victim's local id, and with
-- database-backed RBAC the API then resolved the *victim's* `user_roles`.
--
-- Why the binding is per connection, not per tenant
-- -------------------------------------------------
-- `provision_user`'s docstring explains why matching was on email at all, and
-- the reason is good: an organisation that moves from one identity provider to
-- another keeps its email addresses and would otherwise get a second account
-- for every person. Binding on `(connection_id, subject)` keeps that true. An
-- IdP migration is a new connection, so its bindings start empty and everyone
-- re-claims their own account by verified email on first sign-in. Within one
-- connection a second subject presenting a bound account's address is either a
-- provider recycling addresses or an attacker, and neither should win quietly.
--
-- `subject` is text and not a uuid: OIDC says `sub` is a case-sensitive string
-- up to 255 ASCII characters, and SAML NameIDs are routinely longer and are
-- not uuids either.

CREATE TABLE IF NOT EXISTS aisoc_sso_identities (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The SSO connection this subject was asserted by. Not a foreign key to
    -- `aisoc_sso_connections` on purpose: deleting a connection must not
    -- silently drop the bindings that record who claimed which account, and an
    -- operator who re-creates a connection gets a new id and therefore a clean
    -- re-claim, which is the migration path above.
    connection_id  UUID        NOT NULL,

    subject        TEXT        NOT NULL,

    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- What the provider asserted at bind time, kept for an auditor asking how
    -- this account came to be claimed.
    bound_email    TEXT        NOT NULL,
    provider       TEXT        NOT NULL,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One subject per connection, and one account per subject.
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_sso_identities_subject
    ON aisoc_sso_identities (connection_id, subject);

-- And the other direction: one account may be claimed by at most one subject
-- on a given connection. Without this, two subjects could each bind to the
-- same user and both would resolve -- which is the vulnerability wearing a
-- different hat.
CREATE UNIQUE INDEX IF NOT EXISTS aisoc_sso_identities_account
    ON aisoc_sso_identities (connection_id, user_id);

CREATE INDEX IF NOT EXISTS aisoc_sso_identities_tenant
    ON aisoc_sso_identities (tenant_id);

COMMENT ON TABLE aisoc_sso_identities IS
    'Binds an IdP subject to the local account it signs in as, per SSO connection. '
    'Closes GHSA-qjjc-q2h2-56cg: before this, an unverified email claim could select '
    'any existing account in the tenant.';

DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_sso_identities ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_sso_identities FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_sso_identities';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_sso_identities '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_sso_identities TO aisoc_app';
    END IF;
END
$$;
