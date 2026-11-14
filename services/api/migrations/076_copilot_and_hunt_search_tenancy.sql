-- Copilot conversations and saved hunt searches become tenant-scoped rows.
--
-- Both lived in a module-level dict: `_CONVERSATIONS` in
-- `services/agents/app/api/copilot.py` and `_SAVED_SEARCHES` in
-- `services/agents/app/api/hunt_search.py`. Neither carried a tenant, and
-- the list handlers bound no principal at all, so `GET /copilot/conversations`
-- returned every tenant's conversations to whoever asked and
-- `GET /copilot/conversations/{id}` returned any conversation by id.
--
-- A copilot conversation is not chat history. It contains the analyst's
-- question, which names hosts and users, and the model's answer, which
-- quotes the alert evidence it was grounded on. A saved hunt search is the
-- query body an analyst wrote against their own telemetry.
--
-- These are not caching bugs with a privacy side effect. A module global has
-- no tenant, so the moment a handler writes to one the read can no longer be
-- scoped — the information needed to scope it was never stored.
--
-- Both tables carry `tenant_id NOT NULL` so a row cannot exist outside a
-- tenant, which is the property the dict could not have.

BEGIN;

CREATE TABLE IF NOT EXISTS aisoc_copilot_conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The author. Nullable because the agents service reaches some callers
    -- through a service principal that has a tenant but no user, and a
    -- conversation owned by the tenant is still correctly scoped.
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    title           TEXT NOT NULL DEFAULT '',
    messages        JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The list query is "this tenant's conversations, newest first", so the
-- index carries the sort column rather than leaving it to a sort node.
CREATE INDEX IF NOT EXISTS idx_copilot_conversations_tenant_updated
    ON aisoc_copilot_conversations (tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS aisoc_saved_hunt_searches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    name            TEXT NOT NULL,
    query           TEXT NOT NULL,
    backend         TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_saved_hunt_searches_tenant_updated
    ON aisoc_saved_hunt_searches (tenant_id, updated_at DESC);

-- RLS as defence in depth. The query layer filters by `tenant_id` as well,
-- because the services connect as `aisoc_app` and a policy is only as good
-- as the `set_config` that precedes it — a connection that forgets the
-- context would otherwise read nothing, which is safe, or everything, which
-- is not, depending on the policy's null handling.
ALTER TABLE aisoc_copilot_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_copilot_conversations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_copilot_conversations_tenant ON aisoc_copilot_conversations;
CREATE POLICY aisoc_copilot_conversations_tenant ON aisoc_copilot_conversations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_saved_hunt_searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_saved_hunt_searches FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_saved_hunt_searches_tenant ON aisoc_saved_hunt_searches;
CREATE POLICY aisoc_saved_hunt_searches_tenant ON aisoc_saved_hunt_searches
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- `ALTER DEFAULT PRIVILEGES` from 061 only covers tables created by the role
-- that ran it, so a new table needs its grant stated. Without this the
-- DML-only `aisoc_app` role gets a permission error that
-- `CREATE TABLE IF NOT EXISTS` callers have historically swallowed into a
-- debug log.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON aisoc_copilot_conversations, aisoc_saved_hunt_searches
            TO aisoc_app;
    END IF;
END
$$;

COMMIT;
