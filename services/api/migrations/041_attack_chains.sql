-- Migration 041: Attack-chain timeline cache (Track 3, T3.3 — v8.0 plan).
--
-- Stores the materialised output of ``services/api/app/services/attack_chain.py``
-- so the case-detail page can render the right-column timeline + entity
-- graph without re-running the BFS on every navigation. The algorithm
-- is cheap on a healthy database (depth-3 BFS over JSONB indexes ≈
-- a few ms per seed) but the *entity graph* payload it returns is
-- relatively heavy and we want it cacheable so the UI can hydrate
-- the timeline on first paint and stream the entity graph behind it.
--
-- One row per (seed_alert, window) — ``chain_signature`` lets the
-- service detect when a recompute produced an identical chain and
-- skip the rewrite (cheap when nothing has changed). The chain itself
-- is stored as opaque JSONB; the service owns the schema. The
-- ``confidence`` column is denormalised so the inbox / case list
-- can sort by it without unpacking the JSONB.
--
-- Schema:
--   id                 - opaque uuid, surfaced in API responses for
--                        invalidation by an admin tool.
--   tenant_id          - owner tenant, RLS-enforced.
--   seed_alert_id      - the alert the chain was rooted at.
--   case_id            - convenience join (the case currently
--                        anchored to the seed); nullable so a chain
--                        can be cached before a case is opened.
--   window             - human-readable window label ('24h', '7d',
--                        '30d', '72h'). The service refuses anything
--                        outside its allowlist.
--   chain              - JSONB array of ChainLink dicts (alert_id,
--                        score, distance, dt_seconds, shared_entities,
--                        ...).
--   entity_graph       - JSONB { nodes: [...], edges: [...] }, owned
--                        by the service. Used by the right-column
--                        side-by-side graph view.
--   chain_signature    - SHA-256 (truncated 32-char hex) of the
--                        seed + chain alert ids. Idempotency key
--                        for the recompute path.
--   confidence         - 0..1 score of the top-of-chain link.
--                        Denormalised for cheap sort.
--   created_at         - mint timestamp.
--   updated_at         - bumped on every recompute.
--
-- Indexes:
--   - (tenant_id, seed_alert_id) — primary read path: "fetch the
--     chain for the seed I'm looking at".
--   - (tenant_id, case_id) — secondary read path for the case-detail
--     surface ("any chains anchored to this case?").
--   - unique (tenant_id, seed_alert_id, window, chain_signature) —
--     dedup at write time so the recompute upsert is a true no-op
--     when the chain hasn't changed.

BEGIN;

CREATE TABLE IF NOT EXISTS aisoc_attack_chains (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    seed_alert_id       UUID NOT NULL,
    case_id             UUID,
    -- "window" is a reserved keyword in Postgres; it must be quoted
    -- everywhere it is used as an identifier (column def, constraints,
    -- and in the application's INSERT/ON CONFLICT statements).
    "window"            VARCHAR(8) NOT NULL,
    chain               JSONB NOT NULL DEFAULT '[]'::jsonb,
    entity_graph        JSONB NOT NULL DEFAULT '{}'::jsonb,
    chain_signature     VARCHAR(64) NOT NULL,
    confidence          NUMERIC(5, 4) NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT aisoc_attack_chains_window_check
        CHECK ("window" IN ('1h', '6h', '24h', '72h', '7d', '30d')),
    CONSTRAINT aisoc_attack_chains_unique_signature
        UNIQUE (tenant_id, seed_alert_id, "window", chain_signature)
);

CREATE INDEX IF NOT EXISTS aisoc_attack_chains_seed_idx
    ON aisoc_attack_chains (tenant_id, seed_alert_id);

CREATE INDEX IF NOT EXISTS aisoc_attack_chains_case_idx
    ON aisoc_attack_chains (tenant_id, case_id)
    WHERE case_id IS NOT NULL;

-- ============================================================
-- RLS: tenant isolation. Attack chains are tenant-shared (any
-- analyst in the tenant can see any chain) so we enforce only
-- the tenant boundary at the DB layer.
-- ============================================================
ALTER TABLE aisoc_attack_chains ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_attack_chains FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS aisoc_attack_chains_tenant_isolation ON aisoc_attack_chains;
CREATE POLICY aisoc_attack_chains_tenant_isolation ON aisoc_attack_chains
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
