-- Workstream 2: hosted OAuth one-click.
--
-- Two tables backing /api/v1/oauth/start and /api/v1/oauth/callback:
--
--   oauth_app_credentials
--     Per-tenant, per-connector-class OAuth client_id / client_secret. We
--     do not bake a single shared client into the platform; each tenant
--     registers their own OAuth app (or operator-side admin pre-fills it
--     for a managed deployment). client_secret_vault is opaque ciphertext
--     produced by services/api/app/security/credential_vault.py and is
--     never returned over the wire in plaintext.
--
--   oauth_states
--     Short-lived nonces used as the OAuth ``state`` parameter to defend
--     against CSRF and to thread the originating tenant + connector +
--     redirect intent through the round-trip to the upstream provider.
--     Rows TTL out at 10 minutes; a row is also deleted on first
--     successful callback (single-use).

BEGIN;

CREATE TABLE IF NOT EXISTS oauth_app_credentials (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_type VARCHAR(50) NOT NULL,
    -- Public half of the OAuth app registration. Safe to return to the
    -- UI so operators can audit what credential is wired in.
    client_id TEXT NOT NULL,
    -- Encrypted client secret. Format: vault:v1:<base64> — see
    -- services/api/app/security/credential_vault.py.
    client_secret_vault TEXT NOT NULL,
    -- Optional override of the default authorize/token URLs for
    -- on-prem providers (Atlassian Data Center, GitHub Enterprise
    -- Server, internal Okta orgs). NULL means use the default from
    -- the connector's OAuthHints.
    authorize_url TEXT,
    token_url TEXT,
    -- Optional scope downscoping. NULL means use the default scopes
    -- from the connector's OAuthHints.
    scopes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, connector_type)
);

CREATE INDEX IF NOT EXISTS oauth_app_credentials_tenant_idx
    ON oauth_app_credentials (tenant_id);

CREATE TABLE IF NOT EXISTS oauth_states (
    -- The actual ``state`` value we hand to the upstream provider.
    -- Random 32-byte URL-safe token; we look it up on callback.
    state TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    connector_type VARCHAR(50) NOT NULL,
    -- Optional connector_id when re-authing an existing instance.
    -- NULL means the callback should create a new connector row.
    connector_id UUID REFERENCES connectors(id) ON DELETE CASCADE,
    -- PKCE code_verifier for providers that mandate it (e.g. Atlassian).
    code_verifier TEXT,
    -- Free-form hint that becomes part of the connector_config so the
    -- callback knows what extras to persist (e.g. {"organization": "acme"}
    -- for GitHub, {"admin_email": "..."} for Google Workspace).
    extras JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Where to redirect the operator after the callback completes.
    -- Defaults to /onboarding so the verify-data-flowing screen lights up.
    return_to TEXT NOT NULL DEFAULT '/onboarding',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);

CREATE INDEX IF NOT EXISTS oauth_states_expires_idx
    ON oauth_states (expires_at);

-- Connectors created via hosted OAuth need somewhere to stash the
-- refresh_token so the auto-refresh worker (Workstream 5) can rotate
-- access_tokens without operator involvement. The cleanest place is
-- the existing auth_config JSON, but we want a stable, indexable
-- pointer for "was this connector provisioned through hosted OAuth?"
-- so the UI can render the right (read-only) credential view.
ALTER TABLE connectors
    ADD COLUMN IF NOT EXISTS oauth_provisioned BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;
