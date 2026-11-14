-- Migration 016: Knowledge-base + RAG over org docs/runbooks
-- Stores indexed document chunks for retrieval-augmented generation.

CREATE TABLE IF NOT EXISTS aisoc_kb_documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID,
    title           TEXT NOT NULL,
    source_url      TEXT,
    doc_kind        TEXT NOT NULL DEFAULT 'runbook'
                        CHECK (doc_kind IN ('runbook','policy','playbook','sop','wiki','other')),
    content         TEXT NOT NULL,
    -- chunk metadata (if chunked at ingest)
    chunk_index     INT DEFAULT 0,
    chunk_total     INT DEFAULT 1,
    -- simple keyword tags for pre-filter
    tags            TEXT[] DEFAULT ARRAY[]::TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_aisoc_kb_tenant  ON aisoc_kb_documents (tenant_id);
CREATE INDEX IF NOT EXISTS idx_aisoc_kb_kind    ON aisoc_kb_documents (doc_kind);
-- Full-text search index
CREATE INDEX IF NOT EXISTS idx_aisoc_kb_fts     ON aisoc_kb_documents USING gin(to_tsvector('english', content));
