-- Depth plan 4.2 / parity 6.10 — a real TAXII 2.1 server backed by the
-- tenant IOC store.
--
-- Why a table rather than a derived collection
-- --------------------------------------------
-- TAXII clients bookmark a collection by its id and poll it with
-- `added_after`, so the id has to be stable across restarts and across a
-- change in what the collection contains. Deriving one collection per
-- tenant from `threat_intel_iocs` would give a stable id but no way for a
-- tenant to publish a subset, which is the normal reason to run TAXII at
-- all: a partner gets the indicators you are willing to share, not your
-- whole store.
--
-- So a collection is a tenant-owned row with a filter over the IOC store.
-- The objects themselves are never duplicated here — the collection is a
-- view, and an IOC edited in one place does not have to be edited in two.
--
-- `can_write` exists because the specification has the column and a client
-- reads it to decide whether to offer an upload. It is false on every row
-- this migration can create and the server refuses writes outright: an
-- inbound TAXII write is an unauthenticated party inserting indicators
-- that drive this tenant's detections, and that is a reach-out capability
-- that ships off.

CREATE TABLE IF NOT EXISTS taxii_collections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The TAXII `alias`, which is what appears in a URL when a client uses
    -- one. Unique per tenant so a bookmarked alias cannot start resolving
    -- to a different collection.
    alias           TEXT,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    can_read        BOOLEAN NOT NULL DEFAULT true,
    can_write       BOOLEAN NOT NULL DEFAULT false,
    -- Which IOCs this collection publishes. Keys are the ones the server
    -- knows how to translate into a predicate: ioc_type (list), tlp
    -- (list), min_confidence (int), tags (list, any-match), source (list).
    -- An unknown key is refused at write time rather than silently
    -- ignored, because a filter that does not apply publishes more than
    -- the tenant asked to publish.
    ioc_filter      JSONB NOT NULL DEFAULT '{}',
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, alias)
);

CREATE INDEX IF NOT EXISTS taxii_collections_tenant_idx
    ON taxii_collections (tenant_id)
    WHERE is_enabled;

COMMENT ON TABLE taxii_collections IS
    'TAXII 2.1 collections. A collection is a filtered view over threat_intel_iocs, never a '
    'copy: an indicator edited in one place must not have to be edited in two.';

COMMENT ON COLUMN taxii_collections.can_write IS
    'Always false today. The server refuses inbound writes: an authenticated partner inserting '
    'indicators that drive this tenant''s detections is a reach-out capability, and those ship off.';

-- `added_after` is the whole of TAXII pagination, and it reads against the
-- IOC store rather than this table. The IOC table already indexes
-- (tenant_id) and (tenant_id, ioc_type, value); neither orders by the
-- column a TAXII client pages on, so a collection poll would sort the
-- tenant's whole store on every request.
CREATE INDEX IF NOT EXISTS idx_ioc_taxii_paging
    ON threat_intel_iocs (tenant_id, updated_at, id)
    WHERE is_active AND NOT false_positive;

-- Written out per table rather than looped, so the policy stays visible to
-- grep and to scripts/check_tenant_query_predicates.py.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE taxii_collections ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE taxii_collections FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON taxii_collections';
    EXECUTE
        'CREATE POLICY tenant_isolation ON taxii_collections '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON taxii_collections TO aisoc_app';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_taxii_collection_ts ON taxii_collections;
CREATE TRIGGER trg_taxii_collection_ts
    BEFORE UPDATE ON taxii_collections
    FOR EACH ROW EXECUTE FUNCTION update_ti_ts();
