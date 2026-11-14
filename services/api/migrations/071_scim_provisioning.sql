-- 071: SCIM 2.0 provisioning (RFC 7643 / RFC 7644).
--
-- Gap-closure Phase 13.1.
--
-- What this table set is, and why it is shaped defensively
-- --------------------------------------------------------
-- SCIM is a write surface into the identity system, operated by a third
-- party, reached with a long-lived bearer token that lives in somebody
-- else's configuration screen. Every other write path in this tree is
-- driven by a human holding a session; this one is driven by a machine
-- holding a secret, unattended, on a schedule. So the boundary is the
-- token, and the columns below exist to make that boundary auditable and
-- revocable rather than merely present.
--
-- Why the tenant is on the token
-- -------------------------------
-- `aisoc_scim_tokens.tenant_id` is NOT NULL, and it is the only place the
-- tenant of a SCIM request comes from. A SCIM client never names a tenant:
-- there is no field for it in RFC 7643, and adding one would make the
-- boundary a request parameter. One token addresses exactly one tenant.
--
-- `org_id` is nullable on purpose. A single-tenant deployment has no
-- operator organisation and must still be able to run SCIM; an MSSP sets it
-- so the white-label and usage-metering surfaces (13.2, 13.3) can join a
-- provisioning event to the organisation that caused it.
--
-- Why the secret is a hash and a prefix
-- --------------------------------------
-- The same convention `api_keys` already uses: a SHA-256 digest for lookup
-- and a short prefix for display. A token is 192 bits from `secrets`, so a
-- plain digest is right here and a password KDF would not be: there is no
-- low-entropy guess to slow down, and a KDF on the request path would put a
-- deliberate delay in front of every SCIM call an IdP makes.
--
-- Why rotation is two rows rather than an UPDATE
-- ----------------------------------------------
-- Rotating in place means the old secret stops working the instant the new
-- one is minted, and the administrator pasting it into the IdP is offline
-- for however long that takes. `rotated_from_id` plus an `expires_at` on the
-- superseded row gives an overlap window: both secrets work, the old one
-- expires by itself, and the audit log shows which token served which call.
-- An UPDATE would also destroy the evidence of what the previous secret was
-- used for, which is the thing an incident review asks about first.
--
-- Why deactivation is a timestamp on the user, not a row here
-- -----------------------------------------------------------
-- See `users.sessions_revoked_at` at the foot of this file. Deprovisioning
-- has to end access, and flipping `users.is_active` already does that for
-- sessions because the request path re-reads it. What it does not do is
-- survive re-activation: an access token minted before the deactivation is
-- still inside its expiry window and starts working again. The timestamp
-- closes that, and it lives on `users` because it is a property of the
-- principal rather than of the provisioning channel.

CREATE TABLE IF NOT EXISTS aisoc_scim_tokens (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The operator organisation this token belongs to, when there is one.
    -- Nullable: a single-tenant deployment runs SCIM with no organisation.
    org_id          UUID        REFERENCES organizations(id) ON DELETE CASCADE,

    -- Administrator-facing label, so a tenant with two IdPs can tell which
    -- token is which without comparing prefixes.
    name            TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),

    -- First 12 characters of the raw secret, for display only.
    token_prefix    TEXT        NOT NULL,
    -- SHA-256 hex digest of the raw secret. Indexed because it is the
    -- lookup key on every SCIM request.
    token_hash      TEXT        NOT NULL UNIQUE,

    created_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    -- Set on the superseded token when a rotation opens an overlap window,
    -- and settable at mint time for a token that should not outlive a pilot.
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    rotated_from_id UUID        REFERENCES aisoc_scim_tokens(id) ON DELETE SET NULL
);

COMMENT ON TABLE aisoc_scim_tokens IS
    'Per-organisation SCIM bearer tokens. The tenant of a SCIM request comes '
    'from this row and from nowhere else: RFC 7643 has no tenant field and '
    'adding one would make the boundary a request parameter.';
COMMENT ON COLUMN aisoc_scim_tokens.token_hash IS
    'SHA-256 of the raw secret. The raw value is returned once at mint time '
    'and is not recoverable from this table.';
COMMENT ON COLUMN aisoc_scim_tokens.rotated_from_id IS
    'The token this one replaced. Both work until the old row expires, so an '
    'administrator can paste the new secret into the IdP without an outage.';

CREATE INDEX IF NOT EXISTS idx_scim_tokens_tenant ON aisoc_scim_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_org ON aisoc_scim_tokens (org_id);


-- SCIM metadata for a provisioned principal.
--
-- A side table rather than columns on `users`, because `users` is read on
-- every authenticated request in the platform and SCIM has no business
-- widening that row. The join only happens on the SCIM surface itself.
CREATE TABLE IF NOT EXISTS aisoc_scim_users (
    user_id     UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The IdP's own identifier. Okta and Entra both send it and both expect
    -- it echoed back; it is how a rename is distinguished from a new user.
    external_id TEXT,

    given_name  TEXT,
    family_name TEXT,
    -- Which token provisioned this principal, for the audit trail.
    token_id    UUID        REFERENCES aisoc_scim_tokens(id) ON DELETE SET NULL,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- An external id identifies one principal within one tenant. Two tenants
    -- provisioned from two IdPs may legitimately collide on it.
    UNIQUE (tenant_id, external_id)
);

COMMENT ON TABLE aisoc_scim_users IS
    'SCIM metadata for a provisioned principal, kept beside users rather than '
    'in it so the row read on every authenticated request stays narrow.';

CREATE INDEX IF NOT EXISTS idx_scim_users_tenant ON aisoc_scim_users (tenant_id);


-- A group pushed by the identity provider.
--
-- Why `mapped_role` is nullable, and why that is the safe default
-- ---------------------------------------------------------------
-- An IdP pushes whatever groups the administrator selected, named however
-- that directory names things. Creating a platform role per pushed group
-- would manufacture roles that grant nothing and read, in the console, as
-- though they grant something. Instead a group either resolves to one of
-- the roles this platform actually enforces, or it resolves to NULL and is
-- membership-only: recorded, audited, and granting no privilege at all.
-- Unrecognised therefore means powerless rather than unconstrained.
CREATE TABLE IF NOT EXISTS aisoc_scim_groups (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name TEXT        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 300),
    external_id  TEXT,

    -- One of the roles services/api/app/core/security.py ROLE_PERMISSIONS
    -- enforces, or NULL for a group that confers nothing. Not a foreign key:
    -- the role vocabulary is code, not a table, and check_scim_contract.py
    -- is what keeps this column and that map in agreement.
    mapped_role  TEXT,

    token_id     UUID        REFERENCES aisoc_scim_tokens(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, display_name),
    UNIQUE (tenant_id, external_id)
);

COMMENT ON COLUMN aisoc_scim_groups.mapped_role IS
    'The enforced platform role this group confers, or NULL for a group that '
    'confers nothing. NULL is the default for an unrecognised group name, so '
    'an unmapped directory group grants no privilege rather than an unknown one.';

CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON aisoc_scim_groups (tenant_id);


CREATE TABLE IF NOT EXISTS aisoc_scim_group_members (
    group_id  UUID        NOT NULL REFERENCES aisoc_scim_groups(id) ON DELETE CASCADE,
    user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Denormalised so this table carries the same row-level-security shape
    -- as every other tenant-scoped table, rather than depending on a join to
    -- be filtered.
    tenant_id UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_tenant ON aisoc_scim_group_members (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON aisoc_scim_group_members (user_id);


-- Session revocation, so deprovisioning ends access instead of marking it.
--
-- `get_current_user` re-reads `users.is_active` on every request, so
-- deactivating already stops a session in its tracks. It does not survive
-- re-activation: an access token minted before the deactivation is still
-- inside its expiry window and resumes working the moment the row flips
-- back. Tokens now carry `iat`, and a token issued at or before this
-- timestamp is refused however active the principal currently is.
ALTER TABLE users ADD COLUMN IF NOT EXISTS sessions_revoked_at TIMESTAMPTZ;

COMMENT ON COLUMN users.sessions_revoked_at IS
    'Access and refresh tokens issued at or before this instant are refused. '
    'Set by SCIM deprovisioning and by an administrator ending sessions, so '
    'revocation survives a later re-activation of the same principal.';


-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) reach these
-- tables; dropping it makes those silently see nothing. FORCE so the table
-- owner, which is the role that runs migrations, does not walk past it.
ALTER TABLE aisoc_scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_scim_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_scim_tokens_tenant ON aisoc_scim_tokens;
CREATE POLICY aisoc_scim_tokens_tenant ON aisoc_scim_tokens
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_scim_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_scim_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_scim_users_tenant ON aisoc_scim_users;
CREATE POLICY aisoc_scim_users_tenant ON aisoc_scim_users
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_scim_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_scim_groups_tenant ON aisoc_scim_groups;
CREATE POLICY aisoc_scim_groups_tenant ON aisoc_scim_groups
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_scim_group_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_scim_group_members_tenant ON aisoc_scim_group_members;
CREATE POLICY aisoc_scim_group_members_tenant ON aisoc_scim_group_members
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_scim_tokens TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_scim_users TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_scim_groups TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_scim_group_members TO aisoc_app;
    END IF;
END
$$;
