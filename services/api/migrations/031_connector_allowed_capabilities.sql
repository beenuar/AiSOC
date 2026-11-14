-- Migration 031: Per-instance capability downscoping (AI Stack plan, Workstream 4).
--
-- Each connector class declares the set of actions it *could* perform via the
-- new ``capabilities()`` classmethod (e.g. ``PULL_ALERTS``, ``ISOLATE_HOST``).
-- That declaration is global to the connector type. Operators frequently want
-- to install a powerful connector (e.g. CrowdStrike with ``ISOLATE_HOST``)
-- but only authorize a *subset* of those capabilities for the agent — for
-- example, "read alerts but never let the agent isolate a host".
--
-- ``allowed_capabilities`` is that per-instance allow-list. NULL means "no
-- downscoping — agent may use everything the class declares". A non-NULL
-- JSON array is treated as the canonical allow-list, and any capability not
-- in the array is filtered out by ``BaseConnector.effective_capabilities()``.
--
-- The agent layer reads ``effective_capabilities()`` (not ``capabilities()``)
-- when surfacing tools to the LLM via ``GET /api/v1/agents/tools``.

ALTER TABLE connectors
    ADD COLUMN IF NOT EXISTS allowed_capabilities JSONB;

-- Backfill nothing: existing connectors keep NULL, which means
-- "agent may use everything the class declares" — same behavior as before
-- this column existed.

COMMENT ON COLUMN connectors.allowed_capabilities IS
    'Per-instance capability downscoping. NULL = use class default. JSON array of capability strings (e.g. ["pull_alerts","query_logs"]) restricts the agent to that subset.';
