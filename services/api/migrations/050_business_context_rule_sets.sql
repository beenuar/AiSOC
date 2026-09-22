-- Business-context rules: durable, tenant-scoped, readable by the triage worker.
--
-- The console has let a tenant author business-context rules — "this host is a
-- domain controller, escalate anything touching it", "this service account runs
-- the nightly backup, suppress its noise" — since T3.5. They were stored in a
-- module-level dict inside whichever API process served the write:
--
--     _rule_store: dict[UUID, _RuleStoreEntry] = {}
--
-- so they were lost on restart, invisible to every other replica, and — worse —
-- the auto-triage worker never read them at all. `BusinessContextApplier` loads
-- YAML from a file path in `AISOC_BUSINESS_CONTEXT_RULES_FILE`, which nothing
-- sets. A tenant could configure business context, see it saved, preview it
-- against their last 50 alerts, and have it apply to no triage decision ever.
--
-- The endpoint's own comment pointed at this table as the follow-up. This is it.

CREATE TABLE IF NOT EXISTS aisoc_business_context_rule_sets (
    tenant_id   UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- The authored YAML, kept verbatim rather than normalised: it is the
    -- artifact the analyst edits, and round-tripping it through a parser would
    -- lose their comments and ordering.
    yaml_text   TEXT        NOT NULL DEFAULT '',
    -- Default-on, matching the endpoint's existing behaviour for a tenant with
    -- no stored row.
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The triage worker polls this on a short interval, once per tenant, on the
-- hot path for every fused alert. Index the freshness column so it can ask
-- "anything changed?" without reading the YAML payloads.
CREATE INDEX IF NOT EXISTS idx_business_context_updated_at
    ON aisoc_business_context_rule_sets (updated_at DESC);

COMMENT ON TABLE aisoc_business_context_rule_sets IS
    'Per-tenant business-context rules authored in the console and applied by the auto-triage worker.';
