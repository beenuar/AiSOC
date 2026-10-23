-- Migration 120: OrcaRouter Cyber Inference as a named LLM provider.
--
-- Two provider ids, one credential shape: `orcarouter` is the paste-an-API-key
-- entry and `orcarouter-oauth` is the Connect-with-OrcaRouter (OAuth 2.0 +
-- PKCE, out-of-band) entry. Both resolve to https://api.orcarouter.ai/v1 and
-- both store a normal OrcaRouter API key; keeping the ids separate means the
-- settings panel can name which credential path is configured and a revoked
-- key is re-authenticated through the path that minted it.
--
-- The provider CHECK is the storage-layer mirror of the Pydantic Literal in
-- services/api/app/api/v1/endpoints/llm_credentials.py and of
-- app.api.v1.endpoints.llm_status._classify_provider. Adding a value here
-- without the other two leaves a provider that can be stored and then
-- classified as "custom".
--
-- The connect-state table holds one row per in-flight PKCE attempt: the code
-- verifier never leaves the server, the state is single-use, and the row is
-- deleted before the code is exchanged so a replayed state cannot redeem a
-- second key.

BEGIN;

ALTER TABLE tenant_llm_credentials
    DROP CONSTRAINT IF EXISTS tenant_llm_credentials_provider_check;

ALTER TABLE tenant_llm_credentials
    ADD CONSTRAINT tenant_llm_credentials_provider_check CHECK (
        provider IN (
            'openai',
            'anthropic',
            'azure-openai',
            'local-ollama',
            'local-vllm',
            'local-litellm',
            'custom',
            'orcarouter',
            'orcarouter-oauth'
        )
    );

CREATE TABLE IF NOT EXISTS orcarouter_connect_states (
    state TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    -- RFC 7636 code_verifier. Server-side only; never round-tripped to a
    -- browser and never logged.
    code_verifier TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Auth codes carry a 10 minute TTL at the provider; the attempt expires
    -- with it rather than outliving the code it is waiting for.
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orcarouter_connect_states_tenant
    ON orcarouter_connect_states (tenant_id);

ALTER TABLE orcarouter_connect_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE orcarouter_connect_states FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS orcarouter_connect_states_isolation ON orcarouter_connect_states;
CREATE POLICY orcarouter_connect_states_isolation ON orcarouter_connect_states
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
