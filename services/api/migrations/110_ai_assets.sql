-- 110: the AI estate a tenant actually runs, as opposed to the one it registered.
--
-- Depth plan 6.1.
--
-- `aisoc_mcp_servers` (069) is a *declaration*: the MCP servers an operator
-- chose to trust. This table is an *observation*: every AI app, coding agent,
-- MCP server, IDE extension, provider key and OAuth grant AiSOC has seen,
-- whether or not anybody declared it. The two have to be separate, because
-- the interesting row is the one in this table and not in that one — the
-- coding agent nobody registered, running on a laptop, holding a key.
--
-- Why one table with a `kind` rather than six tables
-- --------------------------------------------------
-- Every question an analyst asks of this data is asked across the kinds, not
-- within one: what does this person run, what runs on this device, what has
-- appeared since Friday. Six tables would make each of those a six-way union
-- and would let the columns drift apart. The kinds differ in what identifies
-- them, which is `external_id`, and in what they carry, which is `attributes`.
--
-- Why `first_seen_at` and `last_seen_at` are columns and not derived
-- ------------------------------------------------------------------
-- Derived from the lake they would be a scan over every AI event ever
-- archived, per row, per page load. They are also the two fields the page is
-- sorted and filtered by. The recorder maintains them with `LEAST`/`GREATEST`
-- on conflict so a late-arriving event cannot move `first_seen_at` forward.
--
-- Why the person, the device and the permissions are nullable
-- -----------------------------------------------------------
-- Because the source often does not know. A gateway log names the agent and
-- the model and nothing about the laptop; an osquery row names the device and
-- the process and nothing about the provider account. Writing an empty string
-- or a placeholder would make "we did not learn this" indistinguishable from
-- "there is nobody", and the console renders the two differently: an unlinked
-- asset is a finding, not a blank cell.
--
-- `effective_permissions` holds what Phase 2.5's resolver returned for the
-- linked principal at the time of the last sighting, as a snapshot rather
-- than a join. A join would re-resolve on every read and would silently
-- change history; a snapshot answers "what could this agent reach when we
-- last saw it", which is the question an incident asks.
--
-- Why `risk_score` is stored rather than computed in the query
-- ------------------------------------------------------------
-- It is computed by one function (`app/services/ai_inventory.py::score_risk`)
-- on write, so the console, the API and any future detection all read the
-- same number. Two surfaces computing a risk two ways is how `mttr_hours` and
-- `cases_closed_7d` came to disagree about the same rows.

CREATE TABLE IF NOT EXISTS aisoc_ai_assets (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The six kinds the plan names. Constrained in the database because a
    -- seventh value arriving from a new discovery source should fail loudly
    -- at the write rather than appear as an unfilterable row in the console.
    kind                  TEXT        NOT NULL CHECK (kind IN (
                                          'ai_app',
                                          'coding_agent',
                                          'mcp_server',
                                          'ide_extension',
                                          'provider_key',
                                          'oauth_grant'
                                      )),

    -- Stable within (tenant, kind): the agent id from runtime telemetry, the
    -- process name plus device from endpoint discovery, the key id from a
    -- provider's audit log, the client id of an OAuth grant.
    external_id           TEXT        NOT NULL,
    display_name          TEXT,
    vendor                TEXT,

    -- Which discovery path produced this row. Carried because the three see
    -- different things and an analyst needs to know which one is talking:
    -- `ai_runtime` knows the model and the tools and not the device,
    -- `endpoint` knows the device and the binary and not the model,
    -- `provider_audit` knows the account and the key and neither.
    discovery_source      TEXT        NOT NULL CHECK (discovery_source IN (
                                          'ai_runtime',
                                          'endpoint',
                                          'provider_audit',
                                          'oauth_audit',
                                          'declared'
                                      )),

    -- Links. NULL means "not learned", never "none" — see the header.
    principal             TEXT,
    device                TEXT,
    effective_permissions JSONB,

    -- Everything kind-specific: model, provider, tool names, extension
    -- version, scopes granted. Indexed as a whole rather than per key,
    -- because the shape differs per kind by design.
    attributes            JSONB       NOT NULL DEFAULT '{}'::jsonb,

    risk_score            INTEGER     NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    -- Why the row scored what it scored, so the console can show it and a
    -- reviewer can disagree with a reason rather than with a number.
    risk_reasons          JSONB       NOT NULL DEFAULT '[]'::jsonb,

    -- An operator's judgement, independent of the score. `sanctioned` is the
    -- allowlist the shadow-AI detection reads; it defaults to NULL, meaning
    -- nobody has decided, which is different from "reviewed and refused".
    sanctioned            BOOLEAN,

    first_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    observation_count     BIGINT      NOT NULL DEFAULT 1,

    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The upsert key. A device is part of identity for the kinds where the
    -- same binary on two laptops is two assets (a coding agent, an IDE
    -- extension) and NULL for the kinds where it is one (a provider key).
    --
    -- NULLS NOT DISTINCT is load-bearing and is the whole reason this is a
    -- named constraint. Under the default, NULL never equals NULL, so every
    -- sighting of a provider key — which has no device — would insert a new
    -- row rather than update the one before it, and the inventory would grow
    -- one row per event while `first_seen_at` reset on each. The same
    -- mistake was made in 074 and is spelled the same way here. PostgreSQL
    -- 15 or later; the tree pins 16.
    CONSTRAINT aisoc_ai_assets_identity
        UNIQUE NULLS NOT DISTINCT (tenant_id, kind, external_id, device)
);

COMMENT ON TABLE aisoc_ai_assets IS
    'Observed AI estate: apps, coding agents, MCP servers, IDE extensions, '
    'provider keys and OAuth grants, with the person and device behind each. '
    'Written by the fusion recorder from AI runtime, endpoint and provider '
    'audit telemetry. Distinct from aisoc_mcp_servers, which is what an '
    'operator declared rather than what is running.';
COMMENT ON COLUMN aisoc_ai_assets.principal IS
    'The person the asset acted for, when a source said so. NULL means not '
    'learned, never "nobody" — the console renders an unlinked asset as a '
    'finding rather than a blank cell.';
COMMENT ON COLUMN aisoc_ai_assets.effective_permissions IS
    'Snapshot of what the Phase 2.5 resolver returned for the linked '
    'principal at the last sighting. A snapshot and not a join, so history '
    'does not change under a later permission edit.';
COMMENT ON COLUMN aisoc_ai_assets.sanctioned IS
    'Operator judgement. NULL means undecided, which is not the same as '
    'reviewed-and-refused; the shadow-AI detection reads TRUE as an allowlist.';

CREATE INDEX IF NOT EXISTS idx_ai_assets_tenant_last_seen
    ON aisoc_ai_assets (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_assets_tenant_kind
    ON aisoc_ai_assets (tenant_id, kind);
CREATE INDEX IF NOT EXISTS idx_ai_assets_tenant_principal
    ON aisoc_ai_assets (tenant_id, principal);

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) reach this
-- table; dropping it makes those silently see nothing. FORCE so the table
-- owner, which is the role that runs migrations, does not walk past it.
ALTER TABLE aisoc_ai_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_ai_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_ai_assets_tenant ON aisoc_ai_assets;
CREATE POLICY aisoc_ai_assets_tenant ON aisoc_ai_assets
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_ai_assets TO aisoc_app;
    END IF;
END
$$;
