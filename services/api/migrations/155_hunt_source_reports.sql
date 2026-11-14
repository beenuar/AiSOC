-- Wave 2, Phase 5.1 — the report a hunt came from.
--
-- A hunt drafted from a vendor write-up is a hunt whose reasoning lives
-- outside the product. Six weeks later an analyst looking at a finding needs
-- to know which report produced the indicator, what that report said, and
-- whether it has changed since — none of which is recoverable from the hunt
-- plan alone, because the plan carries values and not provenance.
--
-- What is stored, and what deliberately is not
-- --------------------------------------------
-- The URL, the time it was fetched, its size, and a SHA-256 of the bytes.
-- **Not the body.** Three reasons, in order of weight:
--
--   * it is third-party prose, and a security platform silently retaining
--     copies of vendor publications is a licensing question nobody asked;
--   * it is untrusted text whose only safe handling is a fenced prompt
--     channel, and a copy at rest is a second place it can be read from by
--     something that forgets to fence it;
--   * the digest answers the question that actually matters — "is this the
--     same document I reviewed?" — without keeping the document.
--
-- `indicator_count` and `technique_count` are what the reviewer approved,
-- recorded so a finding can say "4 of the 37 indicators in this report", and
-- `truncated` records that the fetch hit its size bound, because a hunt
-- built from the first 2 MB of a longer report is a different hunt from one
-- built from all of it and the difference is invisible afterwards.

CREATE TABLE IF NOT EXISTS hunt_source_reports (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    url              TEXT        NOT NULL,
    fetched_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fetched_by       UUID,

    byte_size        BIGINT      NOT NULL CHECK (byte_size >= 0),
    content_sha256   TEXT        NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),

    -- TRUE when the fetch hit its size bound. A hunt built from a truncated
    -- report is a different hunt, and the difference is invisible later.
    truncated        BOOLEAN     NOT NULL DEFAULT FALSE,

    indicator_count  INTEGER     NOT NULL DEFAULT 0 CHECK (indicator_count >= 0),
    technique_count  INTEGER     NOT NULL DEFAULT 0 CHECK (technique_count >= 0),

    -- Set when a person approved the extracted list. NULL means drafted and
    -- never reviewed, which must not read as approved: nothing is hunted
    -- from a report until this is non-NULL.
    approved_at      TIMESTAMPTZ,
    approved_by      UUID,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE hunt_source_reports IS
    'Provenance for hunts drafted from third-party reports. The body is '
    'deliberately not stored; the digest answers "is this the same document '
    'I reviewed?" without retaining somebody else''s publication.';
COMMENT ON COLUMN hunt_source_reports.truncated IS
    'TRUE when the fetch hit its size bound. A hunt built from part of a '
    'report is a different hunt from one built from all of it.';
COMMENT ON COLUMN hunt_source_reports.approved_at IS
    'NULL means drafted and never reviewed. Nothing is hunted until this is '
    'set, so NULL must never be rendered as approved.';

-- "Have we already pulled this report?" — the read that stops a second
-- fetch of the same URL producing a duplicate review queue entry.
CREATE INDEX IF NOT EXISTS idx_hunt_source_reports_url
    ON hunt_source_reports (tenant_id, url, fetched_at DESC);

-- RLS, mirroring `alerts_tenant` from `002_rls.sql`: written through the
-- request-scoped API session, read by the hunting worker, which binds no
-- tenant GUC. Migration 151 records what the stricter policy costs.
ALTER TABLE hunt_source_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE hunt_source_reports FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS hunt_source_reports_tenant ON hunt_source_reports;
CREATE POLICY hunt_source_reports_tenant ON hunt_source_reports
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON hunt_source_reports TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS hunt_source_reports;
--
-- Hunts drafted from reports keep working and lose their provenance, which
-- is the pre-5.1 behaviour: an indicator with no recorded origin.
