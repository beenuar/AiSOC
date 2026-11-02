-- 128: resolved identity links (depth plan wave 2, Phase 3.1).
--
-- Why Postgres and not only the graph
-- -----------------------------------
-- ADR-0010 measured Neo4j at 696.8 MiB resident for CORE's entity context,
-- which is 42.2% of what the CORE profile has left while it is triaging an
-- alert, and put the entity and session store in Postgres for CORE with the
-- graph kept for `full`. Identity resolution is entity context, so it lands
-- the same way: this table in CORE, `SAME_PERSON` edges in the graph when it
-- is enabled, written from one code path so the two cannot disagree.
--
-- A CORE install that could not resolve identities would be unable to build
-- a story across sources at all, which is the profile most evaluators run.
--
-- Why confidence is a column and not a filter applied at write time
-- -----------------------------------------------------------------
-- A weak link is useful to an analyst reading a story and dangerous to
-- anything that merges. Those are different consumers and they need
-- different answers from one store, so every link is written with its
-- confidence and the reader decides. Dropping sub-threshold links at write
-- time would make "we considered this and rejected it" unrecoverable, and
-- that sentence is most of the value when somebody asks why two accounts
-- were not joined.
--
-- The merge threshold itself lives in
-- `services/api/app/services/identity_resolution.py` and is deliberately not
-- duplicated here: a threshold in two places is a threshold that drifts, and
-- a CHECK constraint enforcing one would make tuning it a migration.

CREATE TABLE IF NOT EXISTS identity_links (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL,

    -- Source-scoped identifiers, `<source>:<id>`, ordered so a pair is
    -- stored once however it was discovered. Ordering is applied by the
    -- writer, and the unique index below is what makes it matter.
    left_key        text NOT NULL,
    right_key       text NOT NULL,

    -- 0.0-1.0. The rule's confidence, not the pair's: what varies between
    -- pairs is which rule fired, and a confidence that depends on the data
    -- is one nobody can reason about.
    confidence      double precision NOT NULL,
    rule            text NOT NULL,
    -- Why this link was proposed, in sentences. A link an analyst cannot
    -- interrogate is one they either trust blindly or ignore entirely.
    evidence        jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- A person's decision about the link, where one was made. Separate from
    -- `confidence` because a human confirming a weak link is a different
    -- fact from the rule becoming more certain, and overwriting the
    -- confidence would lose which it was.
    decided         text,
    decided_by      uuid,
    decided_at      timestamptz,

    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT identity_links_confidence_check CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CONSTRAINT identity_links_decided_check CHECK (
        decided IS NULL OR decided IN ('confirmed', 'rejected')
    ),
    -- A link from an identity to itself is not a link, and would make every
    -- cluster contain one spurious self-edge.
    CONSTRAINT identity_links_distinct_check CHECK (left_key <> right_key),
    -- The writer orders the pair; this makes a violation loud rather than a
    -- silent duplicate under the other ordering.
    CONSTRAINT identity_links_ordered_check CHECK (left_key < right_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_links_pair_idx
    ON identity_links (tenant_id, left_key, right_key);

-- "What else is this person" — the lookup every consumer makes, from either
-- end of the pair.
CREATE INDEX IF NOT EXISTS identity_links_left_idx
    ON identity_links (tenant_id, left_key, confidence DESC);
CREATE INDEX IF NOT EXISTS identity_links_right_idx
    ON identity_links (tenant_id, right_key, confidence DESC);

COMMENT ON TABLE identity_links IS
    'Resolved links between one person''s identities across IdP, EDR, proxy, cloud, code platform '
    'and Workspace. Every link carries its rule, confidence and evidence; a low-confidence link is '
    'stored and shown and never used to merge.';

COMMENT ON COLUMN identity_links.decided IS
    'A person''s confirmation or rejection. Kept separate from confidence because a human '
    'confirming a weak link is a different fact from the rule becoming more certain.';


DO $$
BEGIN
    EXECUTE 'ALTER TABLE identity_links ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE identity_links FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON identity_links';
    EXECUTE
        'CREATE POLICY tenant_isolation ON identity_links '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON identity_links TO aisoc_app';
    END IF;
END
$$;
