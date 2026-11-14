-- Migration 038: Per-tenant BYOK LLM credentials (WS-H2).
--
-- Why this table exists
-- ---------------------
-- Up to v1.0 the platform resolved LLM configuration from process-level
-- environment variables (``OPENAI_API_KEY`` / ``OPENAI_BASE_URL`` /
-- ``OPENAI_MODEL``). That is fine for a single-tenant dev box but it
-- doesn't survive contact with real buyers, who want one of three
-- things:
--
--   1. "We have an enterprise OpenAI / Anthropic agreement — please
--      bill our API key, not the platform's." (Bring-Your-Own-Key.)
--   2. "Route this tenant's traffic through our local Ollama / vLLM /
--      LiteLLM proxy on a private host." (Air-gapped overlay.)
--   3. "Please don't call any LLM at all for this tenant; turn off the
--      Explain feature." (Disable BYOK + leave the env-var fallback
--      empty → ``_llm_allowed()`` returns false.)
--
-- All three collapse to: store one *active* LLM credential per tenant,
-- vault-encrypt the API key, and have the request path resolve
-- (tenant → row) before falling back to the process env vars.
--
-- Schema decisions
-- ----------------
-- * One row per tenant (``tenant_id`` is the PRIMARY KEY). We could
--   have keyed ``(tenant_id, provider)`` to allow multiple stored
--   credentials per tenant with one marked active, but every tenant
--   we have talked to wants exactly one. We can split rows in v1.1
--   without a destructive migration (drop PK, add a ``is_active``
--   partial unique index).
-- * ``provider`` is a ``VARCHAR`` with a CHECK constraint matching the
--   classification logic in ``services/api/app/api/v1/endpoints/llm_status.py``.
--   This keeps the storage layer honest about what the application
--   layer can actually resolve. Adding a new provider is a one-line
--   migration.
-- * ``api_key_vault`` is opaque ciphertext (``vault:v1:<base64>``)
--   produced by ``services/api/app/security/credential_vault.py``.
--   It is *never* round-tripped to the UI in plaintext; the read
--   endpoint exposes ``has_api_key: bool`` only.
-- * ``base_url`` and ``model`` are nullable overrides. NULL means
--   "use the provider's default" (e.g. ``https://api.openai.com/v1``
--   for OpenAI, ``http://ollama:11434/v1`` for local-ollama). We
--   intentionally do not enforce URL shape here — operators running
--   funky reverse proxies inside an air-gapped network need the
--   flexibility. The application layer validates on PUT.
-- * ``settings`` is a JSONB escape hatch for provider-specific knobs
--   (max_tokens override, organization id, deployment name for
--   Azure OpenAI). v1.0 ships with the column empty; v1.1 features
--   can populate it without a migration.
--
-- Audit + rotation
-- ----------------
-- Every PUT/DELETE on this table emits an audit row via
-- :func:`services.api.app.services.audit.emit_audit` with action
-- ``settings.llm.upsert`` / ``settings.llm.delete``. Rotation is "PUT
-- a new key, the old ciphertext is overwritten." We do not maintain
-- a history table — the audit log is the durable record of who
-- rotated and when.
--
-- RLS
-- ---
-- Row-level security mirrors the pattern in 037_saved_views.sql:
-- a tenant can only see its own row. The ``current_tenant_id()``
-- helper is set in 002_rls.sql.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_llm_credentials (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- One of: openai | anthropic | azure-openai | local-ollama |
    -- local-vllm | local-litellm | custom. Mirrors the enum in
    -- services/api/app/api/v1/endpoints/llm_status.py::_classify_provider.
    provider VARCHAR(40) NOT NULL,
    -- Optional override of the provider's default API base URL.
    -- Required for ``custom`` and the three ``local-*`` providers
    -- (the application layer enforces this on PUT). NULL for the
    -- hosted SaaS providers means "use the canonical endpoint".
    base_url TEXT,
    -- Optional model override. NULL means "use the platform default
    -- (gpt-4o-mini for openai, claude-3-5-sonnet for anthropic, etc.)".
    model VARCHAR(120),
    -- Vault-encrypted API key. Format: ``vault:v1:<base64>``.
    -- Nullable because local-* providers (Ollama / vLLM with no auth)
    -- legitimately have no key. ``custom`` may or may not require one
    -- depending on the proxy.
    api_key_vault TEXT,
    -- Provider-specific settings escape hatch. Empty in v1.0.
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Soft-disable without deleting. Lets an operator say "pause LLM
    -- for this tenant while we rotate" without losing the saved
    -- configuration.
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- Audit metadata. ``last_rotated_at`` is bumped whenever
    -- ``api_key_vault`` changes (the API endpoint does this); the UI
    -- renders "rotated 3 days ago" so operators have a key-hygiene
    -- signal at a glance.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_rotated_at TIMESTAMPTZ,
    CONSTRAINT tenant_llm_credentials_provider_check CHECK (
        provider IN (
            'openai',
            'anthropic',
            'azure-openai',
            'local-ollama',
            'local-vllm',
            'local-litellm',
            'custom'
        )
    )
);

-- ============================================================
-- RLS: tenant isolation. Mirrors saved_views.
-- ============================================================
ALTER TABLE tenant_llm_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_llm_credentials FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_llm_credentials_isolation ON tenant_llm_credentials;
CREATE POLICY tenant_llm_credentials_isolation ON tenant_llm_credentials
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
