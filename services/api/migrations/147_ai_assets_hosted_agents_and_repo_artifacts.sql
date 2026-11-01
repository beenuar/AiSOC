-- 147: two more AI asset kinds — hosted agents and repository AI artefacts.
--
-- Depth plan wave 2, Phase 7.2.
--
-- Migration 110 constrained `kind` to six values deliberately, so that a
-- seventh arriving from a new discovery source would fail loudly at the
-- write rather than appear in the console as a row nothing can filter on.
-- This is that failure being answered properly: the constraint widens, by a
-- migration somebody reviewed, rather than being dropped.
--
-- `hosted_agent`
--     An agent configured in a provider's own control plane rather than on
--     anyone's laptop. It has an owner, a model, a tool list, a set of MCP
--     servers and a set of skills, and it runs whether or not any endpoint
--     the tenant manages is switched on. That is a different exposure from
--     a coding agent: there is no device to contain, and the existing
--     `unlinked_device` signal must not fire for it — see the matching
--     change in `score_risk`, which is the one place the number is
--     computed.
--
-- `repo_ai_artifact`
--     An agent-instruction file, a skill directory or an MCP configuration
--     file found in a repository. These are the files that tell an agent
--     what it may do, and they are checked into source control where
--     anybody with write access — or anybody who can land a pull request —
--     can edit them. The tools and servers they name are recorded in
--     `attributes` so the estate can answer "which repositories point an
--     agent at this MCP server".
--
-- Why these are assets and not findings
-- --------------------------------------
-- Because the question is the same question the rest of this table answers:
-- what AI is running here, who is accountable for it, and has anybody
-- reviewed it. A `sanctioned` decision on a skill directory is exactly as
-- meaningful as one on an IDE extension, and routing them anywhere else
-- would mean a second review surface and a second score.
--
-- `code_platform` as a discovery source
-- --------------------------------------
-- The five existing sources each describe what their telemetry can and
-- cannot see, and the console renders that limitation. A repository scan
-- knows the repository and the file and never the device or the runtime, so
-- it needs its own source rather than borrowing `declared` — which would
-- say an operator registered it, the opposite of the truth.

ALTER TABLE aisoc_ai_assets DROP CONSTRAINT IF EXISTS aisoc_ai_assets_kind_check;
ALTER TABLE aisoc_ai_assets ADD CONSTRAINT aisoc_ai_assets_kind_check CHECK (kind IN (
    'ai_app',
    'coding_agent',
    'mcp_server',
    'ide_extension',
    'provider_key',
    'oauth_grant',
    'hosted_agent',
    'repo_ai_artifact'
));

ALTER TABLE aisoc_ai_assets DROP CONSTRAINT IF EXISTS aisoc_ai_assets_discovery_source_check;
ALTER TABLE aisoc_ai_assets ADD CONSTRAINT aisoc_ai_assets_discovery_source_check CHECK (discovery_source IN (
    'ai_runtime',
    'endpoint',
    'provider_audit',
    'oauth_audit',
    'declared',
    'provider_admin',
    'code_platform'
));

COMMENT ON COLUMN aisoc_ai_assets.kind IS
    'Eight kinds. `hosted_agent` runs in a provider control plane and has no '
    'device to contain; `repo_ai_artifact` is an agent-instruction file, '
    'skill directory or MCP config in a repository, whose referenced tools '
    'and servers are recorded in attributes.';

-- The estate page filters by repository, which is a key inside `attributes`
-- rather than a column: the shape differs per kind by design (110's header
-- explains why). Indexed as an expression so "what AI does this repository
-- carry" does not become a sequential scan on a tenant with many thousands
-- of assets.
CREATE INDEX IF NOT EXISTS idx_ai_assets_tenant_repository
    ON aisoc_ai_assets (tenant_id, (attributes ->> 'repository'))
    WHERE attributes ? 'repository';
