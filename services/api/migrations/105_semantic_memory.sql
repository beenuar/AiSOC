-- 105_semantic_memory.sql — memory items with provenance, and the conflicts
-- an analyst has to settle before the agent reads either side.
--
-- Depth plan 9.2 (parity 6.5). The knowledge base was full-text only:
-- `to_tsvector('english', content) @@ plainto_tsquery(...)`. That answers a
-- question phrased in the words the runbook happens to use and answers
-- nothing otherwise, which for an analyst mid-incident is most of the time —
-- "someone is brute-forcing a VPN account" does not lexically overlap
-- "credential stuffing against the remote-access gateway".
--
-- Why a table *and* a vector store
-- --------------------------------
-- Qdrant holds the vectors and nothing else that matters. Everything an
-- analyst or an auditor needs to decide whether to trust a recalled item
-- lives here, in Postgres, under RLS, because:
--
--   * a vector payload is not a place to enforce a foreign key, a CHECK or a
--     row-level policy, and every one of those is load-bearing for this data;
--   * the vectors are derivable — re-embedding rebuilds them from this table
--     — and Qdrant's collections are immutable in their dimension, so an
--     embedding-model change is a re-embed. A store you may have to rebuild
--     is not the store of record;
--   * the conflict workflow below is a state machine, and a state machine
--     living in a payload nobody can transactionally update is not one.
--
-- Provenance, which is the whole point of 6.5
-- -------------------------------------------
-- Every item carries an author, a source, a scope, an expiry and a state.
-- Those five exist because an agent that cites a memory item is making an
-- argument from authority, and the reader has to be able to ask whose
-- authority, from where, over what, until when, and whether anybody has
-- disputed it. A recalled item with none of that is an unattributed
-- assertion in the prompt that decides what happens to somebody's estate.
--
-- `state` is the enforcement point:
--
--   in_use      recall returns it
--   conflict    recall does NOT return it, and neither side of the conflict,
--               until an analyst settles which one is right
--   not_in_use  retired; kept for the audit trail, never recalled
--
-- Withholding *both* sides of a conflict is deliberate and is the opposite of
-- the obvious design. Returning the newer one silently resolves a
-- disagreement by timestamp, and the case where that is wrong -- an analyst
-- correcting a bad entry, then the bad entry being re-ingested by a job -- is
-- exactly the case the feature exists for.
--
-- `expires_at` is nullable because some memory is genuinely permanent ("this
-- subnet is the payment estate"), but an expired item is `not_in_use` by
-- query rather than by a sweep job, so a worker being down cannot resurrect
-- one.
--
-- `content_hash` is what makes re-ingestion idempotent and what detects a
-- conflict: same `subject`, different hash, both `in_use` is a contradiction
-- by definition.
--
-- `embedding_model` and `embedded_at` travel with the row so a re-embed can
-- find the stale ones, and so a reader can tell an item that has never been
-- embedded from one embedded by a model that is no longer configured. Those
-- two render differently and a NULL rendered as "fine" is the failure this
-- repository keeps finding.
--
-- Reversible: DROP TABLE IF EXISTS aisoc_memory_items.

CREATE TABLE IF NOT EXISTS aisoc_memory_items (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- What kind of thing this is. Closed set: a free-text kind is one nobody
    -- can filter a recall by, and "runbook" spelled three ways is how a
    -- retrieval quietly stops covering a third of the corpus.
    kind            TEXT        NOT NULL
                    CHECK (kind IN ('case', 'runbook', 'memory')),

    -- What the item is *about*. Two items with the same subject are making
    -- claims about the same thing, which is what makes a contradiction
    -- detectable at all. For a closed case this is its id; for institutional
    -- memory, the memory key; for a runbook, its title.
    subject         TEXT        NOT NULL,

    -- Where the original lives, when there is one. Free text because it is a
    -- case id, a document id or a memory key depending on `kind`.
    source_ref      TEXT        NOT NULL DEFAULT '',

    title           TEXT        NOT NULL DEFAULT '',
    content         TEXT        NOT NULL,
    -- TEXT, not CHAR(64). `char_length` on a `bpchar` strips trailing
    -- blanks, so the padding a CHAR(64) adds does not satisfy the length
    -- check below -- the two would have been fighting each other, and the
    -- type would have bought nothing the check does not already give.
    content_hash    TEXT        NOT NULL
                    CHECK (char_length(content_hash) = 64),

    -- ── Provenance ────────────────────────────────────────────────────────
    -- Who said it. An email, an API key prefix, or a worker's name.
    author          TEXT        NOT NULL DEFAULT '',
    -- Where it came from: 'analyst', 'agent', 'case_closure', 'import', …
    -- Not a CHECK: the set grows with every writer, and refusing an unknown
    -- source at the database would mean a new writer silently dropping rows.
    source          TEXT        NOT NULL DEFAULT 'analyst',
    -- 'tenant' (private) or 'global' (shipped content, visible to everyone).
    -- A row is still tenant_id-stamped either way; 'global' is a statement
    -- about who authored it, never a licence to cross tenants on read.
    scope           TEXT        NOT NULL DEFAULT 'tenant'
                    CHECK (scope IN ('tenant', 'global')),
    expires_at      TIMESTAMPTZ,

    state           TEXT        NOT NULL DEFAULT 'in_use'
                    CHECK (state IN ('in_use', 'conflict', 'not_in_use')),
    -- The other item this one contradicts. Set on both rows when a conflict
    -- is raised, cleared on both when it is settled.
    conflicts_with  UUID        REFERENCES aisoc_memory_items(id) ON DELETE SET NULL,
    -- Why it is not in use, or how the conflict was settled. Shown to the
    -- analyst and carried into the audit row.
    state_reason    TEXT        NOT NULL DEFAULT '',

    -- ── Embedding bookkeeping ─────────────────────────────────────────────
    embedding_model TEXT,
    embedded_at     TIMESTAMPTZ,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One live item per subject per kind. The partial unique index means a
    -- retired or conflicted row does not block a replacement, which is what
    -- makes "correct a bad entry" a one-statement operation rather than a
    -- delete followed by an insert with a window in between.
    CONSTRAINT aisoc_memory_items_content_hash_len CHECK (char_length(content_hash) = 64)
);

CREATE UNIQUE INDEX IF NOT EXISTS aisoc_memory_items_live_subject_idx
    ON aisoc_memory_items (tenant_id, kind, subject)
    WHERE state = 'in_use';

CREATE INDEX IF NOT EXISTS aisoc_memory_items_tenant_state_idx
    ON aisoc_memory_items (tenant_id, state, updated_at DESC);

-- The re-embed worker's query: rows whose vector was made by a model that is
-- no longer the configured one, plus rows that have never been embedded.
CREATE INDEX IF NOT EXISTS aisoc_memory_items_embedding_idx
    ON aisoc_memory_items (tenant_id, embedding_model);

COMMENT ON TABLE aisoc_memory_items IS
    'Store of record for semantic memory. Qdrant holds the vectors and nothing else that '
    'matters: the vectors are derivable by re-embedding from here, and a vector payload '
    'cannot carry a foreign key, a CHECK or a row-level policy.';

COMMENT ON COLUMN aisoc_memory_items.state IS
    'in_use | conflict | not_in_use. Recall returns in_use only, and withholds BOTH sides '
    'of a conflict rather than preferring the newer one -- resolving a disagreement by '
    'timestamp is wrong in exactly the case this feature exists for.';

-- Written out rather than looped with format(): a loop makes the policy
-- invisible to grep and to scripts/check_tenant_query_predicates.py, which
-- reads migrations to learn which tables carry one.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_memory_items ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_memory_items FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_memory_items';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_memory_items '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_memory_items TO aisoc_app';
    END IF;
END
$$;
