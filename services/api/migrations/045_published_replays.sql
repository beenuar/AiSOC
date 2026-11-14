-- 045_published_replays.sql
-- v8 W3 — public, immutable, redacted investigation-replay snapshots served at
-- tryaisoc.com/r/<slug>.
--
-- Intentionally NOT under Row-Level Security: this table holds post-redaction,
-- non-identifying data and is meant to be read without a tenant context (the
-- public share link). Writes are scoped to the publishing tenant in the
-- application layer; tenant_id is kept for the publisher's audit / unpublish.

CREATE TABLE IF NOT EXISTS published_replays (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug         VARCHAR(32) NOT NULL UNIQUE,
    run_id       UUID NOT NULL,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id      VARCHAR(200) NOT NULL,
    title        TEXT NOT NULL,
    snapshot     JSONB NOT NULL,
    published_by UUID,
    view_count   INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_published_replays_slug ON published_replays (slug);
CREATE INDEX IF NOT EXISTS idx_published_replays_tenant ON published_replays (tenant_id);
CREATE INDEX IF NOT EXISTS idx_published_replays_run ON published_replays (run_id);

-- Immutability: block UPDATEs to every column except the best-effort
-- view_count bump, so a published snapshot can never be silently altered.
CREATE OR REPLACE FUNCTION published_replays_block_update() RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.slug, NEW.run_id, NEW.tenant_id, NEW.case_id, NEW.title, NEW.snapshot, NEW.published_by, NEW.created_at)
       IS DISTINCT FROM
       (OLD.slug, OLD.run_id, OLD.tenant_id, OLD.case_id, OLD.title, OLD.snapshot, OLD.published_by, OLD.created_at)
    THEN
        RAISE EXCEPTION 'published_replays rows are immutable (only view_count may change)';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_published_replays_immutable ON published_replays;
CREATE TRIGGER trg_published_replays_immutable
    BEFORE UPDATE ON published_replays
    FOR EACH ROW EXECUTE FUNCTION published_replays_block_update();
